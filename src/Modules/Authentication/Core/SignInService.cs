using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Identity.Contracts;
using Gatekeep.Modules.Notifications.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// Password sign-in (Story 4.9, FR-23, NFR-2, NFR-20), each call one command in the caller's Tenant context. Every submit
/// runs exactly one Argon2id verification in a slot of the hashing budget sign-up shares: against the User's active
/// credential, or against <see cref="DummyHashAsync"/> when there is no account or active password, so an unknown account
/// costs what a known one does. The transaction moves only by guarded statements.
/// </summary>
internal sealed class SignInService(
    IAuditAppender audit,
    TimeProvider time,
    ISessions sessions,
    IIdentity identity,
    IDirectory directory,
    ITenants tenants,
    IJobEnqueuer enqueuer,
    IPasswordHashGate gate) : ISignIn
{
    /// <summary>A password sign-in's one authentication method (RFC 8176).</summary>
    private static readonly IReadOnlyList<string> PasswordAmr = ["pwd"];

    private static readonly AuditTypeCode Extended = AuthenticationEvents.SignInTransactionExtended.Code;

    private static readonly Lock DummyLock = new();

    /// <summary>
    /// The process-wide dummy hash (Story 4.9): one PHC string of random bytes under the current parameters, so verifying
    /// against it costs what verifying a current credential does. No password matches it. It is started when the host
    /// builds its sign-in (<see cref="WarmDummyHash"/>), off any request's slot, and made again on next use should that build have failed.
    /// </summary>
    private static Task<string>? _dummy;

    // Only a transaction at the Password step records its authentication, and only once. Its life slides, so the resume that
    // follows isn't refused for an expiry the User didn't cause.
    private const string RecordAuthenticated =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @step), authenticated_session_id = @session_id,
            step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@identifier]::text[]
        RETURNING step_version
        """;

    // An unverified User's correct password: Email verification required, through Story 4.7's Continue and Resend.
    private const string RecordRegistered =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @registered), signup_user_id = @user_id,
            signup_credential_id = @credential_id, step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@identifier]::text[]
        RETURNING step_version
        """;

    // Edit: back to Login, the identifier kept for the email field.
    private const string RecordBack =
        """
        UPDATE signin_transaction
        SET completed_steps = array_remove(completed_steps, @identifier), step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@identifier]::text[]
        RETURNING step_version
        """;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ISessions _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly IIdentity _identity = identity ?? throw new ArgumentNullException(nameof(identity));
    private readonly IDirectory _directory = directory ?? throw new ArgumentNullException(nameof(directory));
    private readonly ITenants _tenants = tenants ?? throw new ArgumentNullException(nameof(tenants));
    private readonly IJobEnqueuer _enqueuer = enqueuer ?? throw new ArgumentNullException(nameof(enqueuer));
    private readonly IPasswordHashGate _gate = gate ?? throw new ArgumentNullException(nameof(gate));

    public async Task<SignInResult> SignInAsync(
        CommandContext context,
        SignInTransaction transaction,
        Secret<string> password,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(password);
        var tenantId = TenantOf(context);
        RequireAtPassword(transaction);

        var unavailable = new SignInResult(SignInStatus.Unavailable, transaction.StepVersion, transaction.ExpiresAt);
        if (await _directory.FindDatabaseConnectionAsync(context, cancellationToken) is not { Enabled: true } connection)
        {
            return unavailable;
        }

        var account = transaction.Identifier is { } email ? await _identity.FindSignInAccountAsync(context, email, cancellationToken) : null;
        var stored = account is { CredentialId: not null, PasswordHash: { } hash } ? hash : null;

        // Read for every account alike. Verification off counts only while the Tenant is Dev, which the read already applies.
        var verificationOff = (await _tenants.GetSignupSettingsAsync(context, tenantId, cancellationToken))?.EmailVerificationOff == true;
        var verified = account?.EmailVerifiedAt is not null || verificationOff;

        // Awaited before the slot, so the slot holds exactly one hash whatever the account.
        var against = stored ?? await DummyHashAsync();

        // Exactly one verification, whatever the account: the dummy stands in for a missing account or password.
        bool matched;
        string? upgraded = null;
        using (var slot = await _gate.EnterAsync(tenantId, cancellationToken))
        {
            if (slot is null)
            {
                return unavailable;
            }

            matched = await PasswordHasher.VerifyAsync(password, against) && stored is not null;
            if (matched && verified && PasswordHasher.NeedsRehash(stored!))
            {
                upgraded = await PasswordHasher.HashAsync(password);
            }
        }

        if (!matched)
        {
            return new SignInResult(SignInStatus.Incorrect, transaction.StepVersion, transaction.ExpiresAt, FailedUserId: account?.UserId);
        }

        var userId = account!.UserId;
        var credentialId = account.CredentialId!.Value;
        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;

        // States beyond the password appear only after the correct one (EXPERIENCE): an unverified email asks for its link.
        if (!verified)
        {
            var registeredVersion = await StepAsync(
                context,
                RecordRegistered,
                "The sign-in transaction isn't at the Password step.",
                cancellationToken,
                ("tenant_id", tenantId),
                ("id", transaction.Id),
                ("registered", SignInSteps.Registered),
                ("identifier", SignInSteps.Identifier),
                ("user_id", userId),
                ("credential_id", credentialId),
                ("expires_at", expiresAt));
            var link = await _identity.IssueVerificationLinkAsync(context, userId, credentialId, transaction.ApplicationId, cancellationToken);
            await EnqueueVerificationAsync(context, userId, link, cancellationToken);
            await _audit.AppendAsync(context, new AuditEvent(Extended, Actor.Anonymous), detail: null, cancellationToken);
            return new SignInResult(SignInStatus.VerificationRequired, registeredVersion, expiresAt);
        }

        // NFR-2: an old-parameter hash is replaced by the same password under the current ones, only while it is still the
        // hash verified, so a password changed meanwhile is never overwritten; otherwise the upgrade is skipped. The history
        // is unchanged.
        if (upgraded is not null)
        {
            _ = await _identity.UpdatePasswordHashAsync(context, credentialId, stored!, upgraded, cancellationToken);
        }

        var session = await _sessions.StartOrRotateAsync(
            context,
            new NewSession(userId, PasswordAmr, _time.GetUtcNow(), account.ConnectionId ?? connection.Id),
            presentedSession,
            cancellationToken);
        var stepVersion = await StepAsync(
            context,
            RecordAuthenticated,
            "The sign-in transaction can't record its authentication.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("step", SignInSteps.Authenticated),
            ("identifier", SignInSteps.Identifier),
            ("session_id", session.SessionId),
            ("expires_at", expiresAt));
        await _audit.AppendAsync(
            context,
            new AuditEvent(AuthenticationEvents.SignInSucceeded.Code, Actor.User(userId), AuditTargetKind.User, userId),
            detail: null,
            cancellationToken);
        return new SignInResult(SignInStatus.Authenticated, stepVersion, expiresAt, session);
    }

    public Task RecordFailureAsync(CommandContext context, Guid? userId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        TenantOf(context);
        var failed = userId is { } id
            ? new AuditEvent(AuthenticationEvents.SignInFailed.Code, Actor.Anonymous, AuditTargetKind.User, id)
            : new AuditEvent(AuthenticationEvents.SignInFailed.Code, Actor.Anonymous);
        return _audit.AppendAsync(context, failed, detail: null, cancellationToken);
    }

    public async Task<MovedSignIn> BackAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);
        RequireAtPassword(transaction);

        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        var stepVersion = await StepAsync(
            context,
            RecordBack,
            "The sign-in transaction isn't at the Password step.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("identifier", SignInSteps.Identifier),
            ("expires_at", expiresAt));
        await _audit.AppendAsync(context, new AuditEvent(Extended, Actor.Anonymous), detail: null, cancellationToken);
        return new MovedSignIn(stepVersion, expiresAt);
    }

    /// <summary>Starts building the dummy hash off any request, when the host builds its sign-in (Story 4.9).</summary>
    public static void WarmDummyHash() => _ = DummyHashAsync();

    /// <summary>The process-wide dummy hash, started once and started again if its last build failed.</summary>
    private static Task<string> DummyHashAsync()
    {
        lock (DummyLock)
        {
            if (_dummy is null || _dummy.IsFaulted || _dummy.IsCanceled)
            {
                _dummy = Task.Run(static () => PasswordHasher.HashAsync(new Secret<string>(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)))));
            }

            return _dummy;
        }
    }

    /// <summary>The verification email, enqueued in the caller's command, with the link as the job's Transit-encrypted credential.</summary>
    private Task<Guid> EnqueueVerificationAsync(CommandContext context, Guid userId, Secret<string> link, CancellationToken cancellationToken)
    {
        var credential = new Secret<byte[]>(link.Use(static value => Encoding.ASCII.GetBytes(value)));
        return _enqueuer.EnqueueAsync(
            context,
            NotificationsContract.SendEmailJob,
            NotificationsContract.EmailPayload(userId, NotificationsContract.VerificationTemplate, credential),
            runAfter: null,
            cancellationToken);
    }

    private static void RequireAtPassword(SignInTransaction transaction)
    {
        if (!transaction.CompletedSteps.SequenceEqual([SignInSteps.Identifier], StringComparer.Ordinal))
        {
            throw new InvalidOperationException("The sign-in transaction isn't at the Password step.");
        }
    }

    private static async Task<int> StepAsync(
        CommandContext context, string sql, string refusal, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            Add(command, name, value);
        }

        return await command.ExecuteScalarAsync(cancellationToken) is int version ? version : throw new InvalidOperationException(refusal);
    }

    private static Guid TenantOf(CommandContext context) =>
        context.TenantId ?? throw new InvalidOperationException("A sign-in is reached only in a Tenant context.");

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
