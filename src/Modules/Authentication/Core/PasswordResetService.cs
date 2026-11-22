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

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// Password reset (Story 4.11, FR-19, FR-48, NFR-6, NFR-20), each call one command in the caller's Tenant context. The
/// transaction's steps move only by guarded statements. A request for an address with no active password mints and
/// encrypts a link it then discards, so it does the work a known one does. A completed reset ends access through the one
/// revocation path and never starts a Session.
/// </summary>
internal sealed class PasswordResetService(
    IAuditAppender audit,
    TimeProvider time,
    ISessions sessions,
    IIdentity identity,
    IDirectory directory,
    IJobEnqueuer enqueuer,
    IPasswordHashGate gate) : IPasswordReset
{
    private static readonly AuditTypeCode Extended = AuthenticationEvents.SignInTransactionExtended.Code;

    // Only a transaction at the Password step opens Forgot password.
    private const string RecordOpened =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @reset), step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@identifier]::text[]
        RETURNING step_version
        """;

    // Only a transaction at Forgot password records a request, with the address asked for as its identifier.
    private const string RecordSent =
        """
        UPDATE signin_transaction
        SET completed_steps = array_append(completed_steps, @reset_sent), identifier = @email,
            step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND completed_steps = ARRAY[@identifier, @reset]::text[]
        RETURNING step_version
        """;

    // Back to Login, the identifier kept for the email field.
    private const string RecordBack =
        """
        UPDATE signin_transaction
        SET completed_steps = '{}'::text[], step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL
          AND (completed_steps = ARRAY[@identifier, @reset]::text[] OR completed_steps = ARRAY[@identifier, @reset, @reset_sent]::text[])
        RETURNING step_version
        """;

    // A completed reset sends the browser's own live transaction, at the neutral confirmation, back to Login.
    private const string RecordBackAfterReset =
        """
        UPDATE signin_transaction
        SET completed_steps = '{}'::text[], step_version = step_version + 1, expires_at = @expires_at
        WHERE tenant_id = @tenant_id AND id = @id AND completed_at IS NULL AND expires_at > @now
          AND completed_steps = ARRAY[@identifier, @reset, @reset_sent]::text[]
        RETURNING step_version
        """;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly ISessions _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
    private readonly IIdentity _identity = identity ?? throw new ArgumentNullException(nameof(identity));
    private readonly IDirectory _directory = directory ?? throw new ArgumentNullException(nameof(directory));
    private readonly IJobEnqueuer _enqueuer = enqueuer ?? throw new ArgumentNullException(nameof(enqueuer));
    private readonly IPasswordHashGate _gate = gate ?? throw new ArgumentNullException(nameof(gate));

    public async Task<MovedSignIn> OpenAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);

        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        var stepVersion = await StepAsync(
            context,
            RecordOpened,
            "The sign-in transaction isn't at the Password step.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("reset", SignInSteps.Reset),
            ("identifier", SignInSteps.Identifier),
            ("expires_at", expiresAt));
        await AppendExtendedAsync(context, cancellationToken);
        return new MovedSignIn(stepVersion, expiresAt);
    }

    public async Task<MovedSignIn> RequestAsync(
        CommandContext context, SignInTransaction transaction, string email, bool issue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transaction);
        var tenantId = TenantOf(context);
        if (!AuthenticationContract.TryNormalizeEmail(email, out var address))
        {
            throw new ArgumentException("A reset request's email is a valid address of at most 254 characters.", nameof(email));
        }

        if (!transaction.CompletedSteps.SequenceEqual([SignInSteps.Identifier, SignInSteps.Reset], StringComparer.Ordinal))
        {
            throw new InvalidOperationException("The sign-in transaction isn't at Forgot password.");
        }

        if (issue)
        {
            // No lock: a request never waits on a sign-up or sign-in for the same address. Only an active password is reset;
            // a credential that changed since this read gets no link, and the request costs what an unknown address does.
            var account = await _identity.FindSignInAccountAsync(context, address, cancellationToken);
            var link = account is { CredentialId: { } credentialId }
                ? await _identity.IssueResetLinkAsync(context, account.UserId, credentialId, transaction.ApplicationId, cancellationToken)
                : null;
            if (link is not null)
            {
                await _enqueuer.EnqueueAsync(
                    context,
                    NotificationsContract.SendEmailJob,
                    ResetPayload(account!.UserId, link),
                    runAfter: null,
                    cancellationToken);
            }
            else
            {
                // The same minting and Transit encryption a known address costs, then discarded: nothing is stored or sent.
                await _enqueuer.RehearseAsync(
                    context,
                    NotificationsContract.SendEmailJob,
                    ResetPayload(Guid.CreateVersion7(), IdentityContract.MintDiscardedLink(tenantId)),
                    cancellationToken);
            }
        }

        var expiresAt = _time.GetUtcNow() + SecurityLimits.SignInTransactionLifetime;
        var stepVersion = await StepAsync(
            context,
            RecordSent,
            "The sign-in transaction isn't at Forgot password.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("reset_sent", SignInSteps.ResetSent),
            ("identifier", SignInSteps.Identifier),
            ("reset", SignInSteps.Reset),
            ("email", address),
            ("expires_at", expiresAt));
        await AppendExtendedAsync(context, cancellationToken);
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
            "The sign-in transaction isn't at Forgot password or its confirmation.",
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", transaction.Id),
            ("identifier", SignInSteps.Identifier),
            ("reset", SignInSteps.Reset),
            ("reset_sent", SignInSteps.ResetSent),
            ("expires_at", expiresAt));
        await AppendExtendedAsync(context, cancellationToken);
        return new MovedSignIn(stepVersion, expiresAt);
    }

    public async Task<ResetLinkState> OpenLinkAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        TenantOf(context);

        var (enabled, policy) = await ConnectionAsync(context, cancellationToken);
        var link = await _identity.FindResetLinkAsync(context, token, lockRows: false, cancellationToken);
        var usable = enabled && link is not null && link.IsUsableAt(_time.GetUtcNow());
        return new ResetLinkState(usable, policy.MinLength, policy.Strength, usable ? link!.Email : null);
    }

    public async Task<PasswordResetResult> CompleteAsync(
        CommandContext context,
        Secret<string> token,
        Secret<string> password,
        Secret<string> confirm,
        SignInTransaction? transaction,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(confirm);
        var tenantId = TenantOf(context);

        // 1. A stale link, or a database Connection no longer enabled: read with no lock, so nothing waits on the hashing.
        var (enabled, policy) = await ConnectionAsync(context, cancellationToken);
        if (!enabled
            || await _identity.FindResetLinkAsync(context, token, lockRows: false, cancellationToken) is not { } read
            || !read.IsUsableAt(_time.GetUtcNow()))
        {
            return new PasswordResetResult(PasswordResetStatus.Unusable, []);
        }

        // 2. The confirmation, as typed.
        if (!password.Use(typed => confirm.Use(confirmed => string.Equals(typed, confirmed, StringComparison.Ordinal))))
        {
            return new PasswordResetResult(PasswordResetStatus.Mismatch, []);
        }

        // 3 and 4. One slot of the budget sign-up and sign-in share holds every Argon2id step: the Connection's rules, with
        // the User's email and their newest earlier passwords, each history hash a full verification, then the new hash.
        string hash;
        using (var slot = await _gate.EnterAsync(tenantId, cancellationToken))
        {
            if (slot is null)
            {
                return new PasswordResetResult(PasswordResetStatus.Unavailable, []);
            }

            var history = await _identity.ReadPasswordHistoryAsync(context, read.UserId, policy.HistoryCount, cancellationToken);
            var failed = await AuthenticationContract.CheckPasswordAsync(password, policy, read.Email, history);
            if (failed.Count != 0)
            {
                return new PasswordResetResult(PasswordResetStatus.RuleFailed, failed);
            }

            hash = await PasswordHasher.HashAsync(password);
        }

        // 5. The link, locked with its User now and checked again, then one command: the password, the link and the email,
        // then every other reset link, every Session and Token Family of the User, and the notice. No Session starts.
        if (await _identity.FindResetLinkAsync(context, token, lockRows: true, cancellationToken) is not { } link
            || link.TokenId != read.TokenId
            || link.CredentialId != read.CredentialId
            || !await _identity.ResetPasswordAsync(context, link, hash, cancellationToken))
        {
            return new PasswordResetResult(PasswordResetStatus.Unusable, []);
        }

        await _identity.SupersedeResetLinksAsync(context, link.UserId, cancellationToken);
        await _sessions.RevokeAccessAsync(
            context,
            new RevocationScope.User(link.UserId),
            exceptSessionId: null,
            RevocationReason.CredentialChange,
            Actor.User(link.UserId),
            cancellationToken);
        await _enqueuer.EnqueueAsync(
            context,
            NotificationsContract.SendEmailJob,
            NotificationsContract.EmailPayload(link.UserId, NotificationsContract.SecurityNotificationTemplate),
            runAfter: null,
            cancellationToken);

        return new PasswordResetResult(
            PasswordResetStatus.Reset, [], await BackAfterResetAsync(context, tenantId, transaction, link.Email, cancellationToken));
    }

    public async Task SendNewLinkAsync(
        CommandContext context, Secret<string> token, Func<string, Task<bool>> recipientAllowed, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(recipientAllowed);
        TenantOf(context);

        // Only an unused link (expired or not) of a User still holding an active password, under an enabled Connection,
        // and only while its recipient is under the limit a request counts.
        if ((await ConnectionAsync(context, cancellationToken)).Enabled
            && await _identity.FindResetLinkAsync(context, token, lockRows: false, cancellationToken) is
                { UsedAt: null, ActiveCredentialId: { } credentialId, Email: { } email } link
            && await recipientAllowed(email.ToLowerInvariant())
            && await _identity.IssueResetLinkAsync(context, link.UserId, credentialId, link.ApplicationId, cancellationToken) is { } fresh)
        {
            await _enqueuer.EnqueueAsync(context, NotificationsContract.SendEmailJob, ResetPayload(link.UserId, fresh), runAfter: null, cancellationToken);
        }
    }

    /// <summary>
    /// Whether the browser's live transaction, at the neutral confirmation for the reset User's own address, went back to
    /// Login (Story 4.11): a guarded statement, so a transaction anywhere else, for another address, expired or completed,
    /// stays as it is.
    /// </summary>
    private async Task<bool> BackAfterResetAsync(
        CommandContext context, Guid tenantId, SignInTransaction? transaction, string? email, CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        if (transaction is not { CompletedAt: null } live || live.IsExpiredAt(now)
            || email is null || !string.Equals(live.Identifier, email, StringComparison.OrdinalIgnoreCase)
            || !live.CompletedSteps.SequenceEqual([SignInSteps.Identifier, SignInSteps.Reset, SignInSteps.ResetSent], StringComparer.Ordinal))
        {
            return false;
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = RecordBackAfterReset;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", live.Id);
            Add(command, "identifier", SignInSteps.Identifier);
            Add(command, "reset", SignInSteps.Reset);
            Add(command, "reset_sent", SignInSteps.ResetSent);
            Add(command, "now", now);
            Add(command, "expires_at", now + SecurityLimits.SignInTransactionLifetime);
            if (await command.ExecuteScalarAsync(cancellationToken) is not int)
            {
                return false;
            }
        }

        await AppendExtendedAsync(context, cancellationToken);
        return true;
    }

    /// <summary>
    /// Whether the database Connection is enabled, without which no link is used or sent, and its password policy, or the
    /// defaults when the Tenant has none.
    /// </summary>
    private async Task<(bool Enabled, PasswordPolicy Policy)> ConnectionAsync(CommandContext context, CancellationToken cancellationToken) =>
        await _directory.FindDatabaseConnectionAsync(context, cancellationToken) is { } connection
            ? (connection.Enabled, connection.Policy)
            : (false, DirectoryContract.DefaultPasswordPolicy);

    /// <summary>The reset email's payload, with the link as the job's credential, which the enqueuer encrypts under the Tenant's payload key.</summary>
    private static JobPayload ResetPayload(Guid userId, Secret<string> link) =>
        NotificationsContract.EmailPayload(
            userId, NotificationsContract.PasswordResetTemplate, new Secret<byte[]>(link.Use(static value => Encoding.ASCII.GetBytes(value))));

    private Task AppendExtendedAsync(CommandContext context, CancellationToken cancellationToken) =>
        _audit.AppendAsync(context, new AuditEvent(Extended, Actor.Anonymous), detail: null, cancellationToken);

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
        context.TenantId ?? throw new InvalidOperationException("A password reset is reached only in a Tenant context.");

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
