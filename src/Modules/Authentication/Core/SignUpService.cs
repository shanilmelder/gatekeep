using System.Data.Common;
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
/// Sign-up and email verification (Story 4.7, FR-17, FR-18, NFR-2), each call one command in the caller's Tenant context.
/// The transaction's steps move only by guarded statements, so a step that hasn't passed can't be skipped. A Session is
/// started only through Sessions, for a User whose credential the sign-up made is active: after its link verified the
/// email, or at once where a Dev Tenant turned verification off.
/// </summary>
internal sealed class SignUpService(
    IAuditAppender audit,
    TimeProvider time,
    ISessions sessions,
    IIdentity identity,
    IDirectory directory,
    ITenants tenants,
    IJobEnqueuer enqueuer,
    IPasswordHashGate gate) : ISignUp
{
    /// <summary>A password sign-up's one authentication method (RFC 8176).</summary>
    private static readonly IReadOnlyList<string> PasswordAmr = ["pwd"];

    private static readonly AuditTypeCode Extended = AuthenticationEvents.SignInTransactionExtended.Code;

    // Only a transaction at Login opens Signup, and the email typed there is kept when it is valid.
    private const string RecordOpened =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @step), identifier = COALESCE(@identifier, identifier),
            step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND cardinality(completed_steps) = 0
        RETURNING step_version
        """;

    private const string RecordBack =
        """
        UPDATE signin_transaction
        SET completed_steps = array_remove(completed_steps, @step), step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@step]::text[]
        RETURNING step_version
        """;

    private const string RecordRegistered =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @registered), identifier = @identifier,
            signup_user_id = @user_id, signup_credential_id = @credential_id,
            step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@signup]::text[]
        RETURNING step_version
        """;

    // Only the transaction whose sign-up made the credential records its authentication, and only once. Its life slides, so
    // the resume that follows isn't refused for an expiry the User didn't cause.
    private const string RecordAuthenticated =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @step), authenticated_session_id = @session_id,
            step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL
          AND @registered = ANY (completed_steps) AND NOT (@step = ANY (completed_steps))
          AND signup_user_id = @user_id AND signup_credential_id = @credential_id
        RETURNING step_version
        """;

    private const string Slide =
        """
        UPDATE signin_transaction
        SET expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND @registered = ANY (completed_steps)
        """;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ISessions _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly IIdentity _identity = identity ?? throw new ArgumentNullException(nameof(identity));
    private readonly IDirectory _directory = directory ?? throw new ArgumentNullException(nameof(directory));
    private readonly ITenants _tenants = tenants ?? throw new ArgumentNullException(nameof(tenants));
    private readonly IJobEnqueuer _enqueuer = enqueuer ?? throw new ArgumentNullException(nameof(enqueuer));
    private readonly IPasswordHashGate _gate = gate ?? throw new ArgumentNullException(nameof(gate));

    public async Task<SignupPolicy> ReadPolicyAsync(CommandContext context, Guid? applicationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        var policy = Policy(await _directory.FindDatabaseConnectionForApplicationAsync(context, applicationId, cancellationToken));
        var settings = await _tenants.GetSignupSettingsAsync(context, tenantId, cancellationToken);
        return policy with { TermsUrl = settings?.TermsUrl };
    }

    public async Task<MovedSignIn?> OpenAsync(CommandContext context, SignInTransaction transaction, string? email, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);

        // Story 4.12: only while the database Connection is enabled for the transaction's Application.
        if (!Policy(await _directory.FindDatabaseConnectionForApplicationAsync(context, transaction.ApplicationId, cancellationToken)).Enabled)
        {
            return null;
        }

        var identifier = AuthenticationContract.TryNormalizeEmail(email, out var normalized) ? normalized : null;
        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        var stepVersion = await StepAsync(
            context,
            RecordOpened,
            "The sign-in transaction isn't at Login.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("step", SignInSteps.Signup),
            ("identifier", identifier),
            ("expires_at", expiresAt));
        await AppendAnonymousAsync(context, Extended, cancellationToken);
        return new MovedSignIn(stepVersion, expiresAt);
    }

    public async Task<MovedSignIn> BackAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);

        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        var stepVersion = await StepAsync(
            context,
            RecordBack,
            "The sign-in transaction isn't at Signup.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("step", SignInSteps.Signup),
            ("expires_at", expiresAt));
        await AppendAnonymousAsync(context, Extended, cancellationToken);
        return new MovedSignIn(stepVersion, expiresAt);
    }

    public async Task<SignUpResult> SignUpAsync(
        CommandContext context,
        SignInTransaction transaction,
        string email,
        Secret<string> password,
        bool acceptTerms,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(password);
        var tenantId = TenantOf(context);
        if (!AuthenticationContract.TryNormalizeEmail(email, out var address))
        {
            throw new ArgumentException("A sign-up's email is a valid address of at most 254 characters.", nameof(email));
        }

        if (!IsAt(transaction, SignInSteps.Signup))
        {
            throw new InvalidOperationException("The sign-in transaction isn't at Signup.");
        }

        var connection = await _directory.FindDatabaseConnectionForApplicationAsync(context, transaction.ApplicationId, cancellationToken);
        if (connection is null || !Policy(connection).Enabled)
        {
            var back = await BackAsync(context, transaction, cancellationToken);
            return new SignUpResult(SignUpStatus.Disabled, [], back.StepVersion, back.ExpiresAt);
        }

        // Story 4.8: where the Tenant set terms, they must be accepted, before the rules and the hash, writing nothing. The
        // Tenant's terms URL at submit time is the terms' version recorded as accepted.
        var settings = await _tenants.GetSignupSettingsAsync(context, tenantId, cancellationToken);
        var termsUrl = settings?.TermsUrl;
        if (termsUrl is not null && !acceptTerms)
        {
            return new SignUpResult(SignUpStatus.TermsRequired, [], transaction.StepVersion, transaction.ExpiresAt);
        }

        // The policy first, so a refused password is never hashed. A sign-up has no earlier password to compare with.
        var failed = password.Use(value => PasswordRules.Check(value, connection.Policy, address));
        if (failed.Count != 0)
        {
            return new SignUpResult(SignUpStatus.RuleFailed, failed, transaction.StepVersion, transaction.ExpiresAt);
        }

        // One hash, whatever the address, so an existing account costs the same.
        string hash;
        using (var slot = await _gate.EnterAsync(tenantId, cancellationToken))
        {
            if (slot is null)
            {
                return new SignUpResult(SignUpStatus.Unavailable, [], transaction.StepVersion, transaction.ExpiresAt);
            }

            hash = await PasswordHasher.HashAsync(password);
        }

        var verificationOff = settings?.EmailVerificationOff == true;
        var registration = await _identity.RegisterAsync(
            context, address, connection.Id, hash, activate: verificationOff, acceptedTermsUrl: termsUrl, cancellationToken);
        var registered = registration.Registered;

        if (registered is not null && !verificationOff)
        {
            var link = await _identity.IssueVerificationLinkAsync(
                context, registered.UserId, registered.CredentialId, transaction.ApplicationId, cancellationToken);
            await EnqueueVerificationAsync(context, registered.UserId, link, cancellationToken);
        }
        else if (registration.ExistingUserId is { } existing)
        {
            // Story 4.8: an address someone already holds changes nothing, and its owner is told, through the same one
            // enqueue a new address costs. The per-recipient email limit still caps their inbox.
            await _enqueuer.EnqueueAsync(
                context,
                NotificationsContract.SendEmailJob,
                NotificationsContract.EmailPayload(existing, NotificationsContract.SecurityNotificationTemplate),
                runAfter: null,
                cancellationToken);
        }

        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        var stepVersion = await StepAsync(
            context,
            RecordRegistered,
            "The sign-in transaction isn't at Signup.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("registered", SignInSteps.Registered),
            ("signup", SignInSteps.Signup),
            ("identifier", address),
            ("user_id", registered?.UserId),
            ("credential_id", registered?.CredentialId),
            ("expires_at", expiresAt));
        await AppendAnonymousAsync(context, Extended, cancellationToken);

        if (registered is null || !verificationOff)
        {
            return new SignUpResult(SignUpStatus.Registered, [], stepVersion, expiresAt);
        }

        var (session, authenticatedVersion, authenticatedUntil) = await AuthenticateAsync(
            context, tenantId, transaction.Id, registered.UserId, registered.CredentialId, connection.Id, presentedSession, cancellationToken);
        return new SignUpResult(SignUpStatus.Authenticated, [], authenticatedVersion, authenticatedUntil, session);
    }

    public async Task<DateTimeOffset> ResendAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);
        RequireRegistered(transaction);

        // Story 4.12: with the database Connection off for the transaction's Application, nothing is sent or written.
        if (!await EnabledForAsync(context, transaction.ApplicationId, cancellationToken))
        {
            return transaction.ExpiresAt;
        }

        // Story 4.9: an unverified User's active credential, after a sign-in with the correct password, gets a link too.
        if (transaction is { SignupUserId: { } userId, SignupCredentialId: { } credentialId }
            && await _identity.FindCredentialAsync(context, credentialId, cancellationToken) is { UserVerified: false } credential
            && credential.UserId == userId)
        {
            var link = await _identity.IssueVerificationLinkAsync(context, userId, credentialId, transaction.ApplicationId, cancellationToken);
            await EnqueueVerificationAsync(context, userId, link, cancellationToken);
        }

        return await SlideAsync(context, tenantId, transaction.Id, cancellationToken);
    }

    public async Task<ContinuedSignUp> ContinueAsync(
        CommandContext context, SignInTransaction transaction, Secret<string>? presentedSession, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);
        RequireRegistered(transaction);

        // Only the credential this sign-up made, once active, signs it in: another sign-up's verification deleted it. A
        // database Connection disabled since signs nobody in. Story 4.9: an active credential isn't enough on its own, since a
        // sign-in may record an unverified User's: the email must be verified, or verification off on a Dev Tenant.
        if (transaction is { SignupUserId: { } userId, SignupCredentialId: { } credentialId }
            && await _identity.FindCredentialAsync(context, credentialId, cancellationToken) is { Active: true } credential
            && credential.UserId == userId
            && (credential.UserVerified
                || (await _tenants.GetSignupSettingsAsync(context, tenantId, cancellationToken))?.EmailVerificationOff == true)
            && await _directory.FindDatabaseConnectionForApplicationAsync(context, transaction.ApplicationId, cancellationToken) is { Enabled: true } connection)
        {
            var (session, stepVersion, expiresAt) = await AuthenticateAsync(
                context, tenantId, transaction.Id, userId, credentialId, connection.Id, presentedSession, cancellationToken);
            return new ContinuedSignUp(stepVersion, expiresAt, session);
        }

        return new ContinuedSignUp(transaction.StepVersion, transaction.ExpiresAt, null);
    }

    public async Task<LinkVerification> VerifyLinkAsync(
        CommandContext context,
        Secret<string> token,
        SignInTransaction? transaction,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        var tenantId = TenantOf(context);

        var verification = await _identity.VerifyEmailAsync(context, token, cancellationToken);
        if (verification.Status == EmailVerificationStatus.Unusable)
        {
            return new LinkVerification(false, null);
        }

        // The same browser: the live transaction whose sign-up made the very credential this link activated. The email is
        // verified either way; with the database Connection disabled since, no Session starts.
        var now = _time.GetUtcNow();
        if (verification is { Status: EmailVerificationStatus.Verified, UserId: { } userId, CredentialId: { } credentialId }
            && transaction is { CompletedAt: null } live
            && !live.IsExpiredAt(now)
            && IsRegistered(live)
            && live.SignupUserId == userId
            && live.SignupCredentialId == credentialId
            && await _directory.FindDatabaseConnectionForApplicationAsync(context, live.ApplicationId, cancellationToken) is { Enabled: true } connection)
        {
            var (session, stepVersion, _) = await AuthenticateAsync(
                context, tenantId, live.Id, userId, credentialId, connection.Id, presentedSession, cancellationToken);
            return new LinkVerification(true, session, stepVersion);
        }

        return new LinkVerification(true, null);
    }

    public async Task SendNewLinkAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        TenantOf(context);

        // Story 4.12: only while the database Connection is enabled for the Application the link's sign-up was for.
        if (await _identity.FindVerificationLinkAsync(context, token, cancellationToken) is { UserVerified: false } link
            && await EnabledForAsync(context, link.ApplicationId, cancellationToken)
            && await _identity.FindCredentialAsync(context, link.CredentialId, cancellationToken) is { UserVerified: false })
        {
            var fresh = await _identity.IssueVerificationLinkAsync(context, link.UserId, link.CredentialId, link.ApplicationId, cancellationToken);
            await EnqueueVerificationAsync(context, link.UserId, fresh, cancellationToken);
        }
    }

    /// <summary>Whether the database Connection is enabled for <paramref name="applicationId"/> (Story 4.12); a null one is the Tenant's own view.</summary>
    private async Task<bool> EnabledForAsync(CommandContext context, Guid? applicationId, CancellationToken cancellationToken) =>
        await _directory.FindDatabaseConnectionForApplicationAsync(context, applicationId, cancellationToken) is { Enabled: true };

    /// <summary>
    /// The Connection as Hosted Login shows it: sign-up open only while it is enabled with sign-up on, and (Story 4.9) the
    /// Password step offered while it is enabled.
    /// </summary>
    private static SignupPolicy Policy(DatabaseConnection? connection) =>
        connection is null
            ? new SignupPolicy(false, DirectoryContract.DefaultPasswordPolicy.MinLength, DirectoryContract.DefaultPasswordPolicy.Strength)
            : new SignupPolicy(connection.Enabled && connection.SignupEnabled, connection.Policy.MinLength, connection.Policy.Strength)
            {
                PasswordEnabled = connection.Enabled,
            };

    /// <summary>
    /// A Session for the User, through Sessions with <c>amr: ["pwd"]</c> and the database Connection, and the transaction's
    /// <see cref="SignInSteps.Authenticated"/>, in one command.
    /// </summary>
    private async Task<(StartedSession Session, int StepVersion, DateTimeOffset ExpiresAt)> AuthenticateAsync(
        CommandContext context,
        Guid tenantId,
        Guid transactionId,
        Guid userId,
        Guid credentialId,
        Guid connectionId,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        var session = await _sessions.StartOrRotateAsync(
            context, new NewSession(userId, PasswordAmr, _time.GetUtcNow(), connectionId), presentedSession, cancellationToken);
        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;

        var stepVersion = await StepAsync(
            context,
            RecordAuthenticated,
            "The sign-in transaction can't record its authentication.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transactionId),
            ("step", SignInSteps.Authenticated),
            ("registered", SignInSteps.Registered),
            ("session_id", session.SessionId),
            ("user_id", userId),
            ("credential_id", credentialId),
            ("expires_at", expiresAt));
        return (session, stepVersion, expiresAt);
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

    private async Task<DateTimeOffset> SlideAsync(CommandContext context, Guid tenantId, Guid transactionId, CancellationToken cancellationToken)
    {
        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Slide;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", transactionId);
            Add(command, "registered", SignInSteps.Registered);
            Add(command, "expires_at", expiresAt);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("No uncompleted, registered sign-in transaction has that ID in this Tenant.");
            }
        }

        await AppendAnonymousAsync(context, Extended, cancellationToken);
        return expiresAt;
    }

    /// <summary>Whether the transaction has passed exactly <paramref name="steps"/>, in order.</summary>
    private static bool IsAt(SignInTransaction transaction, params string[] steps) =>
        transaction.CompletedSteps.SequenceEqual(steps, StringComparer.Ordinal);

    /// <summary>
    /// Whether the transaction stands at Email verification required: after a sign-up (Story 4.7), or after an unverified
    /// User's correct password at the Password step (Story 4.9).
    /// </summary>
    private static bool IsRegistered(SignInTransaction transaction) =>
        IsAt(transaction, SignInSteps.Signup, SignInSteps.Registered) || IsAt(transaction, SignInSteps.Identifier, SignInSteps.Registered);

    private static void RequireRegistered(SignInTransaction transaction)
    {
        if (!IsRegistered(transaction))
        {
            throw new InvalidOperationException("The sign-in transaction isn't registered.");
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

    private Task AppendAnonymousAsync(CommandContext context, AuditTypeCode code, CancellationToken cancellationToken) =>
        _audit.AppendAsync(context, new AuditEvent(code, Actor.Anonymous), detail: null, cancellationToken);

    private static Guid TenantOf(CommandContext context) =>
        context.TenantId ?? throw new InvalidOperationException("A sign-up is reached only in a Tenant context.");

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
