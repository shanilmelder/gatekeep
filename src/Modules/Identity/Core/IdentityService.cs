using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Identity.Contracts;

namespace Gatekeep.Modules.Identity.Core;

/// <summary>
/// Identity's Users, password credentials, verification links (Story 4.7) and reset links (Story 4.11), each call in the caller's Tenant context
/// and transaction. Every statement names the context's Tenant, and row-level security holds it there too.
/// </summary>
internal sealed class IdentityService(IAuditAppender audit, TimeProvider time) : IIdentity
{
    /// <summary>An email verification link's purpose (Story 4.7).</summary>
    private const string EmailVerificationPurpose = "email_verification";

    /// <summary>A password reset link's purpose (Story 4.11).</summary>
    private const string PasswordResetPurpose = "password_reset";

    private const string Pending = "pending";

    private const string Active = "active";

    // A User found by address is locked, so two sign-ups for it can't both add a credential unseen.
    private const string SelectUserByEmail =
        """
        SELECT u.id, u.email_verified_at IS NOT NULL,
               EXISTS (SELECT 1 FROM password_credential c WHERE c.tenant_id = u.tenant_id AND c.user_id = u.id AND c.status = 'active')
        FROM "user" u
        WHERE u.tenant_id = @tenant_id AND lower(u.email) = lower(@email)
        FOR UPDATE OF u
        """;

    // A concurrent sign-up for the same address waits here, then finds the row it inserted.
    private const string InsertUser =
        """
        INSERT INTO "user" (tenant_id, id, email, created_at, terms_accepted_url, terms_accepted_at)
        VALUES (@tenant_id, @id, @email, @now, @terms_url, @terms_at)
        ON CONFLICT (tenant_id, lower(email)) WHERE email IS NOT NULL DO NOTHING
        """;

    // Story 4.8: an unverified User signing up again records the terms this sign-up accepted, with its new credential.
    private const string RecordTerms =
        """
        UPDATE "user" SET terms_accepted_url = @terms_url, terms_accepted_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND email_verified_at IS NULL
        """;

    private const string InsertCredential =
        """
        INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status, created_at, updated_at)
        VALUES (@tenant_id, @id, @user_id, @connection_id, @password_hash, @status, @now, @now)
        """;

    // A credential's links go first: the reference is ON DELETE RESTRICT, as every one is.
    private const string DeleteOtherPendingLinks =
        """
        DELETE FROM one_time_token
        WHERE tenant_id = @tenant_id AND user_id = @user_id AND credential_id <> @keep
          AND credential_id IN (SELECT id FROM password_credential WHERE tenant_id = @tenant_id AND user_id = @user_id AND status = 'pending')
        """;

    private const string DeleteOtherLinks =
        "DELETE FROM one_time_token WHERE tenant_id = @tenant_id AND user_id = @user_id AND credential_id <> @keep";

    private const string DeleteOtherPendingCredentials =
        """
        DELETE FROM password_credential
        WHERE tenant_id = @tenant_id AND user_id = @user_id AND status = 'pending' AND id <> @keep
        """;

    // An unverified User holds an active credential only where a Dev Tenant turned verification off; the verified email's
    // own credential replaces it, so a User never has two.
    private const string DeleteOtherCredentials =
        "DELETE FROM password_credential WHERE tenant_id = @tenant_id AND user_id = @user_id AND id <> @keep";

    private const string InsertHistory =
        """
        INSERT INTO password_history (tenant_id, id, user_id, password_hash, created_at)
        VALUES (@tenant_id, @id, @user_id, @password_hash, @now)
        """;

    // Story 4.9: an active credential gets a link too while its User's email isn't verified, which happens only after a Dev
    // Tenant turned verification back on.
    private const string LockLinkableCredential =
        """
        SELECT 1 FROM password_credential c
        JOIN "user" u ON u.tenant_id = c.tenant_id AND u.id = c.user_id
        WHERE c.tenant_id = @tenant_id AND c.id = @id AND c.user_id = @user_id
          AND (c.status = 'pending' OR u.email_verified_at IS NULL)
        FOR UPDATE OF c
        """;

    // Story 4.9: no lock, so a sign-in never waits on a sign-up for the same address. Only an active credential signs in.
    private const string SelectSignInAccount =
        """
        SELECT u.id, c.id, c.password_hash, c.connection_id, u.email_verified_at
        FROM "user" u
        LEFT JOIN password_credential c ON c.tenant_id = u.tenant_id AND c.user_id = u.id AND c.status = 'active'
        WHERE u.tenant_id = @tenant_id AND lower(u.email) = lower(@email)
        """;

    private const string UpdateHash =
        """
        UPDATE password_credential SET password_hash = @password_hash, updated_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND status = 'active' AND password_hash = @previous_hash
        """;

    private const string SelectCredential =
        """
        SELECT c.user_id, c.status = 'active', u.email_verified_at IS NOT NULL
        FROM password_credential c
        JOIN "user" u ON u.tenant_id = c.tenant_id AND u.id = c.user_id
        WHERE c.tenant_id = @tenant_id AND c.id = @id
        """;

    private const string DeleteUnusedLinks =
        """
        DELETE FROM one_time_token
        WHERE tenant_id = @tenant_id AND credential_id = @credential_id AND purpose = @purpose AND used_at IS NULL
        """;

    private const string InsertLink =
        """
        INSERT INTO one_time_token (tenant_id, id, user_id, credential_id, purpose, token_hash, application_id, expires_at, created_at)
        VALUES (@tenant_id, @id, @user_id, @credential_id, @purpose, @token_hash, @application_id, @expires_at, @now)
        """;

    // Found by the hash alone, and locked with its User, so two uses of one link, or of two links of one User, run one at a time.
    private const string SelectLink =
        """
        SELECT t.id, t.user_id, t.credential_id, t.application_id, t.expires_at, t.used_at, u.email_verified_at IS NOT NULL
        FROM one_time_token t
        JOIN "user" u ON u.tenant_id = t.tenant_id AND u.id = t.user_id
        WHERE t.tenant_id = @tenant_id AND t.token_hash = @token_hash AND t.purpose = @purpose
        FOR UPDATE OF t, u
        """;

    private const string UseLink =
        """
        UPDATE one_time_token SET used_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND used_at IS NULL AND expires_at > @now
        """;

    private const string MarkVerified =
        """
        UPDATE "user" SET email_verified_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND email_verified_at IS NULL
        """;

    private const string ActivateCredential =
        """
        UPDATE password_credential SET status = 'active', updated_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND user_id = @user_id AND status = 'pending'
        RETURNING password_hash
        """;

    // Story 4.11: only a User's active credential gets a reset link; locked, so a reset and a password change run one at a time.
    private const string LockActiveCredential =
        """
        SELECT 1 FROM password_credential
        WHERE tenant_id = @tenant_id AND id = @id AND user_id = @user_id AND status = 'active'
        FOR UPDATE
        """;

    // Story 4.11: a newer reset link, or a password change, leaves only the newest unused one working, by deleting the rest.
    private const string DeleteUnusedResetLinks =
        """
        DELETE FROM one_time_token
        WHERE tenant_id = @tenant_id AND user_id = @user_id AND purpose = @purpose AND used_at IS NULL
        """;

    // Found by the hash alone, whatever its state, with the User's active credential now and its email (for the
    // personal-data rule). With no lock, so a page view or a hash waits on nothing.
    private const string SelectResetLink =
        """
        SELECT t.id, t.user_id, t.credential_id, t.application_id, t.expires_at, t.used_at,
               (SELECT c.id FROM password_credential c WHERE c.tenant_id = t.tenant_id AND c.user_id = t.user_id AND c.status = 'active'),
               u.email
        FROM one_time_token t
        JOIN "user" u ON u.tenant_id = t.tenant_id AND u.id = t.user_id
        WHERE t.tenant_id = @tenant_id AND t.token_hash = @token_hash AND t.purpose = @purpose
        """;

    // The same, locked with its User, read again just before a reset's writes, so two uses of one link run one at a time.
    private const string LockResetLink = SelectResetLink + " FOR UPDATE OF t, u";

    // The new password replaces the active credential's in place: links reference credentials ON DELETE RESTRICT.
    private const string ReplaceHash =
        """
        UPDATE password_credential SET password_hash = @password_hash, updated_at = @now
        WHERE tenant_id = @tenant_id AND id = @id AND user_id = @user_id AND status = 'active'
        """;

    private const string SelectHistory =
        """
        SELECT password_hash FROM password_history
        WHERE tenant_id = @tenant_id AND user_id = @user_id
        ORDER BY created_at DESC, id DESC
        LIMIT @count
        """;

    /// <summary>The longest PHC string a credential holds, as the table checks.</summary>
    private const int MaxHashLength = 512;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));

    public async Task<Registration> RegisterAsync(
        CommandContext context,
        string email,
        Guid connectionId,
        string passwordHash,
        bool activate,
        string? acceptedTermsUrl,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        if (string.IsNullOrWhiteSpace(email) || email.Length > SecurityLimits.MaxEmailLength)
        {
            throw new ArgumentException("A sign-up's email is 1 to 254 characters.", nameof(email));
        }

        if (string.IsNullOrEmpty(passwordHash) || passwordHash.Length > MaxHashLength)
        {
            throw new ArgumentException("A password hash is a PHC string of 1 to 512 characters.", nameof(passwordHash));
        }

        if (connectionId == Guid.Empty)
        {
            throw new ArgumentException("A credential names its Connection.", nameof(connectionId));
        }

        if (acceptedTermsUrl is not null && (acceptedTermsUrl.Length == 0 || acceptedTermsUrl.Length > SecurityLimits.MaxTermsUrlLength))
        {
            throw new ArgumentException("An accepted terms URL is 1 to 2048 characters.", nameof(acceptedTermsUrl));
        }

        var now = _time.GetUtcNow();
        var user = await FindUserAsync(context, tenantId, email, cancellationToken);
        var created = false;
        if (user is null)
        {
            await using (var command = context.CreateCommand())
            {
                command.CommandText = InsertUser;
                Add(command, "tenant_id", tenantId);
                Add(command, "id", Guid.CreateVersion7(now));
                Add(command, "email", email);
                Add(command, "now", now);
                Add(command, "terms_url", acceptedTermsUrl);
                Add(command, "terms_at", acceptedTermsUrl is null ? null : now);
                created = await command.ExecuteNonQueryAsync(cancellationToken) == 1;
            }

            user = await FindUserAsync(context, tenantId, email, cancellationToken)
                ?? throw new InvalidOperationException("The User a sign-up created can't be read back.");
        }

        // A sign-up never changes an account someone already holds: the caller only notifies its owner.
        if (user.Value.Verified || user.Value.HasActive)
        {
            return Registration.Existing(user.Value.Id);
        }

        var userId = user.Value.Id;
        if (!created && acceptedTermsUrl is not null)
        {
            await ExecuteAsync(
                context, RecordTerms, cancellationToken, ("tenant_id", tenantId), ("id", userId), ("terms_url", acceptedTermsUrl), ("now", now));
        }

        var credentialId = Guid.CreateVersion7(now);
        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertCredential;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", credentialId);
            Add(command, "user_id", userId);
            Add(command, "connection_id", connectionId);
            Add(command, "password_hash", passwordHash);
            Add(command, "status", activate ? Active : Pending);
            Add(command, "now", now);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (activate)
        {
            await ExecuteAsync(context, DeleteOtherPendingLinks, cancellationToken, ("tenant_id", tenantId), ("user_id", userId), ("keep", credentialId));
            await ExecuteAsync(context, DeleteOtherPendingCredentials, cancellationToken, ("tenant_id", tenantId), ("user_id", userId), ("keep", credentialId));
            await InsertHistoryAsync(context, tenantId, userId, passwordHash, now, cancellationToken);
        }

        await _audit.AppendAsync(
            context, new AuditEvent(IdentityEvents.UserSignedUp.Code, Actor.Anonymous, AuditTargetKind.User, userId), detail: null, cancellationToken);
        return Registration.New(new RegisteredUser(userId, credentialId));
    }

    public async Task<Secret<string>> IssueVerificationLinkAsync(
        CommandContext context, Guid userId, Guid credentialId, Guid? applicationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        var now = _time.GetUtcNow();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockLinkableCredential;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", credentialId);
            Add(command, "user_id", userId);
            if (await command.ExecuteScalarAsync(cancellationToken) is null)
            {
                throw new InvalidOperationException("No pending credential, or credential of an unverified User, has that ID in this Tenant.");
            }
        }

        await ExecuteAsync(
            context, DeleteUnusedLinks, cancellationToken, ("tenant_id", tenantId), ("credential_id", credentialId), ("purpose", EmailVerificationPurpose));

        var (token, hash) = VerificationLinks.New(tenantId);
        await ExecuteAsync(
            context,
            InsertLink,
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", Guid.CreateVersion7(now)),
            ("user_id", userId),
            ("credential_id", credentialId),
            ("purpose", EmailVerificationPurpose),
            ("token_hash", hash),
            ("application_id", applicationId),
            ("expires_at", now + SecurityLimits.EmailVerificationLinkLifetime),
            ("now", now));
        return token;
    }

    public async Task<CredentialState?> FindCredentialAsync(CommandContext context, Guid credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = SelectCredential;
        Add(command, "tenant_id", tenantId);
        Add(command, "id", credentialId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new CredentialState(reader.GetGuid(0), reader.GetBoolean(1), reader.GetBoolean(2))
            : null;
    }

    public async Task<VerificationLink?> FindVerificationLinkAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        var tenantId = TenantOf(context);

        // Another Tenant's link, or no link at all, is refused here, before any lookup.
        if (token.Use(value => VerificationLinks.OwnHash(tenantId, value)) is not { } hash)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = SelectLink;
        Add(command, "tenant_id", tenantId);
        Add(command, "token_hash", hash);
        Add(command, "purpose", EmailVerificationPurpose);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new VerificationLink(
            reader.GetGuid(0),
            reader.GetGuid(1),
            reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5),
            reader.GetBoolean(6));
    }

    public async Task<EmailVerification> VerifyEmailAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        var now = _time.GetUtcNow();

        if (await FindVerificationLinkAsync(context, token, cancellationToken) is not { } link || !link.IsUsableAt(now))
        {
            return new EmailVerification(EmailVerificationStatus.Unusable);
        }

        if (await ExecuteAsync(context, UseLink, cancellationToken, ("tenant_id", tenantId), ("id", link.TokenId), ("now", now)) != 1)
        {
            return new EmailVerification(EmailVerificationStatus.Unusable);
        }

        // Already verified: the User keeps the password they verified with, and the link is only spent.
        if (link.UserVerified)
        {
            return new EmailVerification(EmailVerificationStatus.AlreadyVerified, link.UserId, link.CredentialId);
        }

        await ExecuteAsync(context, MarkVerified, cancellationToken, ("tenant_id", tenantId), ("id", link.UserId), ("now", now));
        await ExecuteAsync(
            context, DeleteOtherLinks, cancellationToken, ("tenant_id", tenantId), ("user_id", link.UserId), ("keep", link.CredentialId));
        await ExecuteAsync(
            context, DeleteOtherCredentials, cancellationToken, ("tenant_id", tenantId), ("user_id", link.UserId), ("keep", link.CredentialId));

        string? activated;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = ActivateCredential;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", link.CredentialId);
            Add(command, "user_id", link.UserId);
            Add(command, "now", now);
            activated = await command.ExecuteScalarAsync(cancellationToken) as string;
        }

        if (activated is not null)
        {
            await InsertHistoryAsync(context, tenantId, link.UserId, activated, now, cancellationToken);
        }

        await _audit.AppendAsync(
            context, new AuditEvent(IdentityEvents.UserEmailVerified.Code, Actor.Anonymous, AuditTargetKind.User, link.UserId), detail: null, cancellationToken);
        return new EmailVerification(EmailVerificationStatus.Verified, link.UserId, link.CredentialId);
    }

    public async Task<SignInAccount?> FindSignInAccountAsync(CommandContext context, string email, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        if (string.IsNullOrWhiteSpace(email) || email.Length > SecurityLimits.MaxEmailLength)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = SelectSignInAccount;
        Add(command, "tenant_id", tenantId);
        Add(command, "email", email);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new SignInAccount(
            reader.GetGuid(0),
            reader.IsDBNull(1) ? null : reader.GetGuid(1),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3),
            reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4));
    }

    public async Task<bool> UpdatePasswordHashAsync(
        CommandContext context, Guid credentialId, string previousHash, string passwordHash, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        if (string.IsNullOrEmpty(passwordHash) || passwordHash.Length > MaxHashLength)
        {
            throw new ArgumentException("A password hash is a PHC string of 1 to 512 characters.", nameof(passwordHash));
        }

        return await ExecuteAsync(
            context,
            UpdateHash,
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", credentialId),
            ("password_hash", passwordHash),
            ("previous_hash", previousHash),
            ("now", _time.GetUtcNow())) == 1;
    }

    public async Task<IReadOnlyList<string>> ReadPasswordHistoryAsync(CommandContext context, Guid userId, int count, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        if (count <= 0)
        {
            return [];
        }

        await using var command = context.CreateCommand();
        command.CommandText = SelectHistory;
        Add(command, "tenant_id", tenantId);
        Add(command, "user_id", userId);
        Add(command, "count", count);
        var hashes = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            hashes.Add(reader.GetString(0));
        }

        return hashes;
    }

    public async Task<Secret<string>?> IssueResetLinkAsync(
        CommandContext context, Guid userId, Guid credentialId, Guid? applicationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        var now = _time.GetUtcNow();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockActiveCredential;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", credentialId);
            Add(command, "user_id", userId);
            // The credential changed since the caller read it: nothing is written.
            if (await command.ExecuteScalarAsync(cancellationToken) is null)
            {
                return null;
            }
        }

        // The newest link wins: every other unused one is deleted first.
        await SupersedeResetLinksAsync(context, userId, cancellationToken);

        var (token, hash) = VerificationLinks.New(tenantId);
        await ExecuteAsync(
            context,
            InsertLink,
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", Guid.CreateVersion7(now)),
            ("user_id", userId),
            ("credential_id", credentialId),
            ("purpose", PasswordResetPurpose),
            ("token_hash", hash),
            ("application_id", applicationId),
            ("expires_at", now + SecurityLimits.PasswordResetLinkLifetime),
            ("now", now));
        return token;
    }

    public async Task<ResetLink?> FindResetLinkAsync(CommandContext context, Secret<string> token, bool lockRows, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(token);
        var tenantId = TenantOf(context);

        // Another Tenant's link, or no link at all, is refused here, before any lookup.
        if (token.Use(value => VerificationLinks.OwnHash(tenantId, value)) is not { } hash)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = lockRows ? LockResetLink : SelectResetLink;
        Add(command, "tenant_id", tenantId);
        Add(command, "token_hash", hash);
        Add(command, "purpose", PasswordResetPurpose);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ResetLink(
            reader.GetGuid(0),
            reader.GetGuid(1),
            reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5),
            reader.IsDBNull(6) ? null : reader.GetGuid(6),
            reader.IsDBNull(7) ? null : reader.GetString(7));
    }

    public async Task<bool> ResetPasswordAsync(CommandContext context, ResetLink link, string passwordHash, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(link);
        var tenantId = TenantOf(context);
        if (string.IsNullOrEmpty(passwordHash) || passwordHash.Length > MaxHashLength)
        {
            throw new ArgumentException("A password hash is a PHC string of 1 to 512 characters.", nameof(passwordHash));
        }

        var now = _time.GetUtcNow();
        if (!link.IsUsableAt(now))
        {
            return false;
        }

        // The link first: a link used meanwhile, or expired since it was read, changes nothing.
        if (await ExecuteAsync(context, UseLink, cancellationToken, ("tenant_id", tenantId), ("id", link.TokenId), ("now", now)) != 1)
        {
            return false;
        }

        if (await ExecuteAsync(
                context,
                ReplaceHash,
                cancellationToken,
                ("tenant_id", tenantId),
                ("id", link.CredentialId),
                ("user_id", link.UserId),
                ("password_hash", passwordHash),
                ("now", now)) != 1)
        {
            throw new InvalidOperationException("The reset link's credential is no longer the User's active one.");
        }

        await InsertHistoryAsync(context, tenantId, link.UserId, passwordHash, now, cancellationToken);

        // The link proved the mailbox (T-62): any pending credential, an earlier unverified sign-up's, goes with its links,
        // and the email is verified.
        await ExecuteAsync(
            context, DeleteOtherPendingLinks, cancellationToken, ("tenant_id", tenantId), ("user_id", link.UserId), ("keep", link.CredentialId));
        await ExecuteAsync(
            context, DeleteOtherPendingCredentials, cancellationToken, ("tenant_id", tenantId), ("user_id", link.UserId), ("keep", link.CredentialId));
        await ExecuteAsync(context, MarkVerified, cancellationToken, ("tenant_id", tenantId), ("id", link.UserId), ("now", now));

        await _audit.AppendAsync(
            context,
            new AuditEvent(IdentityEvents.PasswordReset.Code, Actor.User(link.UserId), AuditTargetKind.User, link.UserId),
            detail: null,
            cancellationToken);
        return true;
    }

    public Task<int> SupersedeResetLinksAsync(CommandContext context, Guid userId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = TenantOf(context);
        return ExecuteAsync(
            context, DeleteUnusedResetLinks, cancellationToken, ("tenant_id", tenantId), ("user_id", userId), ("purpose", PasswordResetPurpose));
    }

    private static async Task<(Guid Id, bool Verified, bool HasActive)?> FindUserAsync(
        CommandContext context, Guid tenantId, string email, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = SelectUserByEmail;
        Add(command, "tenant_id", tenantId);
        Add(command, "email", email);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? (reader.GetGuid(0), reader.GetBoolean(1), reader.GetBoolean(2)) : null;
    }

    private static Task<int> InsertHistoryAsync(
        CommandContext context, Guid tenantId, Guid userId, string passwordHash, DateTimeOffset now, CancellationToken cancellationToken) =>
        ExecuteAsync(
            context,
            InsertHistory,
            cancellationToken,
            ("tenant_id", tenantId),
            ("id", Guid.CreateVersion7(now)),
            ("user_id", userId),
            ("password_hash", passwordHash),
            ("now", now));

    private static async Task<int> ExecuteAsync(
        CommandContext context, string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            Add(command, name, value);
        }

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static Guid TenantOf(CommandContext context) =>
        context.TenantId ?? throw new InvalidOperationException("Identity's Users are reached only in a Tenant context.");

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
