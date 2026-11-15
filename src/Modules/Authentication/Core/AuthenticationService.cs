using System.Data.Common;
using System.Text;
using System.Text.Json;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Authentication.Core;

internal sealed class AuthenticationService(IAuditAppender audit, TimeProvider time, ISessions sessions, ICredentialStep credentialStep)
    : IAuthentication
{
    private static readonly AuditTypeCode Started = AuthenticationEvents.SignInTransactionStarted.Code;
    private static readonly AuditTypeCode Extended = AuthenticationEvents.SignInTransactionExtended.Code;
    private static readonly AuditTypeCode Identified = AuthenticationEvents.SignInTransactionIdentified.Code;
    private static readonly AuditTypeCode Completed = AuthenticationEvents.SignInTransactionCompleted.Code;
    private static readonly AuditTypeCode Refused = AuthenticationEvents.SignInTransactionRefused.Code;

    private const string InsertTransaction =
        """
        INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, identifier, created_at, expires_at)
        VALUES (@tenant_id, @id, @application_id, @binding_hash, @parameters::jsonb, @identifier, @created_at, @expires_at)
        """;

    // Story 4.2: found only by the binding's hash, under the request's Tenant (RLS too), and locked until the
    // caller's transaction ends.
    private const string SelectByBinding =
        """
        SELECT id, application_id, parameters::text, completed_steps, step_version, identifier,
               authenticated_session_id, expires_at, completed_at
        FROM signin_transaction
        WHERE tenant_id = @tenant_id AND binding_hash = @binding_hash
        FOR UPDATE
        """;

    private const string SlideTransaction =
        """
        UPDATE signin_transaction
        SET expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL
        """;

    // A restarted transaction's binding is replaced by a random hash no cookie has, so its old cookie is refused.
    private const string RetireBinding =
        """
        UPDATE signin_transaction
        SET binding_hash = @binding_hash
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL
        """;

    // Only a transaction at Login records an identifier, and only once.
    private const string RecordIdentifier =
        """
        UPDATE signin_transaction
        SET identifier = @identifier, completed_steps = array_append(completed_steps, @step),
            step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND cardinality(completed_steps) = 0
        RETURNING step_version
        """;

    private const string RecordAuthenticated =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @step), authenticated_session_id = @session_id,
            step_version = step_version + 1
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL
          AND @identifier_step = ANY (completed_steps) AND NOT (@step = ANY (completed_steps))
        RETURNING step_version
        """;

    private const string CompleteTransaction =
        """
        UPDATE signin_transaction
        SET completed_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND application_id = @application_id
          AND completed_at IS NULL AND @step = ANY (completed_steps) AND authenticated_session_id IS NOT NULL
        """;

    /// <summary>The largest serialized parameter set a sign-in stores: 16 KiB.</summary>
    private const int MaxParametersBytes = 16 * 1024;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ISessions _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly ICredentialStep _credentialStep = credentialStep ?? throw new ArgumentNullException(nameof(credentialStep));

    public Task<StartedSignIn> BeginAsync(
        CommandContext context,
        SignInRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(request);

        return InsertAsync(context, request.ApplicationId, request.Parameters, identifier: null, cancellationToken);
    }

    public async Task<SignInTransaction?> FindAsync(CommandContext context, Secret<string> binding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(binding);

        var tenantId = TenantOf(context);
        if (binding.Use(static v => OpaqueValues.IsWellFormed(v) ? OpaqueValues.Hash(v) : null) is not { } hash)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = SelectByBinding;
        Add(command, "tenant_id", tenantId);
        Add(command, "binding_hash", hash);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new SignInTransaction(
            reader.GetGuid(0),
            reader.GetGuid(1),
            JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(2)) ?? [],
            reader.GetFieldValue<string[]>(3),
            reader.GetInt32(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetGuid(6),
            reader.GetFieldValue<DateTimeOffset>(7),
            reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8));
    }

    public async Task<StartedSignIn> RestartAsync(CommandContext context, SignInTransaction expired, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(expired);

        var tenantId = TenantOf(context);
        await using (var command = context.CreateCommand())
        {
            command.CommandText = RetireBinding;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", expired.Id);
            Add(command, "binding_hash", OpaqueValues.New().Hash);

            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("No uncompleted sign-in transaction has that ID in this Tenant.");
            }
        }

        return await InsertAsync(context, expired.ApplicationId, expired.Parameters, expired.Identifier, cancellationToken);
    }

    public async Task<DateTimeOffset> ExtendAsync(CommandContext context, Guid transactionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = TenantOf(context);
        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;

        await using (var command = context.CreateCommand())
        {
            command.CommandText = SlideTransaction;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", transactionId);
            Add(command, "expires_at", expiresAt);

            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("No uncompleted sign-in transaction has that ID in this Tenant.");
            }
        }

        await AppendAnonymousAsync(context, Extended, cancellationToken);
        return expiresAt;
    }

    public async Task<IdentifiedSignIn> IdentifyAsync(
        CommandContext context,
        SignInTransaction transaction,
        string email,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);

        var tenantId = TenantOf(context);
        if (!AuthenticationContract.TryNormalizeEmail(email, out var identifier))
        {
            throw new ArgumentException("An identifier is a valid email address of at most 254 characters.", nameof(email));
        }

        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        int stepVersion;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = RecordIdentifier;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", transaction.Id);
            Add(command, "identifier", identifier);
            Add(command, "step", SignInSteps.Identifier);
            Add(command, "expires_at", expiresAt);

            stepVersion = await command.ExecuteScalarAsync(cancellationToken) is int version
                ? version
                : throw new InvalidOperationException("The sign-in transaction isn't at Login.");
        }

        await AppendAnonymousAsync(context, Extended, cancellationToken);
        await AppendAnonymousAsync(context, Identified, cancellationToken);

        var identified = transaction with
        {
            Identifier = identifier,
            CompletedSteps = [.. transaction.CompletedSteps, SignInSteps.Identifier],
            StepVersion = stepVersion,
            ExpiresAt = expiresAt,
        };

        // The next step: none in a release build until Story 4.9; only a test's credential step authenticates.
        if (await _credentialStep.AfterIdentifierAsync(context, identified, cancellationToken) is not { } authentication)
        {
            return new IdentifiedSignIn(stepVersion, expiresAt, null);
        }

        var session = await _sessions.StartOrRotateAsync(
            context, new NewSession(authentication.UserId, authentication.Amr, authentication.AuthTime), presentedSession, cancellationToken);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = RecordAuthenticated;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", transaction.Id);
            Add(command, "step", SignInSteps.Authenticated);
            Add(command, "identifier_step", SignInSteps.Identifier);
            Add(command, "session_id", session.SessionId);

            stepVersion = await command.ExecuteScalarAsync(cancellationToken) is int version
                ? version
                : throw new InvalidOperationException("The sign-in transaction can't record its authentication.");
        }

        return new IdentifiedSignIn(stepVersion, expiresAt, session);
    }

    public async Task CompleteAsync(CommandContext context, Guid transactionId, Guid applicationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = TenantOf(context);
        await using (var command = context.CreateCommand())
        {
            command.CommandText = CompleteTransaction;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", transactionId);
            Add(command, "application_id", applicationId);
            Add(command, "step", SignInSteps.Authenticated);
            Add(command, "now", _time.GetUtcNow());

            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("No uncompleted, authenticated sign-in transaction of that Application has that ID.");
            }
        }

        await AppendAnonymousAsync(context, Completed, cancellationToken);
    }

    public Task RefuseAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        TenantOf(context);
        return AppendAnonymousAsync(context, Refused, cancellationToken);
    }

    private async Task<StartedSignIn> InsertAsync(
        CommandContext context,
        Guid applicationId,
        IReadOnlyDictionary<string, string>? parameters,
        string? identifier,
        CancellationToken cancellationToken)
    {
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A sign-in begins only in a Tenant context.");

        if (applicationId == Guid.Empty)
        {
            throw new ArgumentException("A sign-in needs an Application.", nameof(applicationId));
        }

        var serialized = SerializedParameters(parameters);

        var now = _time.GetUtcNow();
        var id = Guid.CreateVersion7(now);
        var (binding, hash) = OpaqueValues.New();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertTransaction;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", id);
            Add(command, "application_id", applicationId);
            Add(command, "binding_hash", hash);
            Add(command, "parameters", serialized);
            Add(command, "identifier", identifier);
            Add(command, "created_at", now);
            Add(command, "expires_at", now + SecurityLimits.SignInTransactionLifetime);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // Nobody is signed in yet, and the envelope has no Application target kind.
        await _audit.AppendAsync(context, new AuditEvent(Started, Actor.Anonymous), detail: null, cancellationToken);

        return new StartedSignIn(id, binding);
    }

    private Task AppendAnonymousAsync(CommandContext context, AuditTypeCode code, CancellationToken cancellationToken) =>
        _audit.AppendAsync(context, new AuditEvent(code, Actor.Anonymous), detail: null, cancellationToken);

    private static Guid TenantOf(CommandContext context) =>
        context.TenantId ?? throw new InvalidOperationException("A sign-in transaction is reached only in a Tenant context.");

    /// <summary>
    /// The anonymous caller's parameters as JSON, refused before any write when jsonb can't
    /// hold them (a NUL character) or they are null or too large.
    /// </summary>
    private static string SerializedParameters(IReadOnlyDictionary<string, string>? parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentException("A sign-in needs its parameters.", nameof(parameters));
        }

        foreach (var (key, value) in parameters)
        {
            if (value is null || key.Contains('\0') || value.Contains('\0'))
            {
                throw new ArgumentException("A sign-in parameter is null or holds a NUL character.", nameof(parameters));
            }
        }

        var json = JsonSerializer.Serialize(parameters);
        if (Encoding.UTF8.GetByteCount(json) > MaxParametersBytes)
        {
            throw new ArgumentException("The sign-in parameters are too large.", nameof(parameters));
        }

        return json;
    }

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}

/// <summary>The release build's credential step (Story 4.2): none is available until Story 4.9.</summary>
internal sealed class NoCredentialStep : ICredentialStep
{
    public ValueTask<CredentialAuthentication?> AfterIdentifierAsync(
        CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken) =>
        ValueTask.FromResult<CredentialAuthentication?>(null);
}
