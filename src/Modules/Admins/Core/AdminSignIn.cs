using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Admin sign-in over <c>admin_signin_challenge</c>, <c>admin_credential</c>, <c>admin</c> and
/// <c>admin_session</c> (Story 1.23), and nothing else: no Identity, Authentication or Sessions
/// table. A pending challenge is a row holding only its SHA-256 and its binding cookie's, with an
/// expiry from the database clock; taking it deletes it, in a transaction of its own, so it never
/// verifies twice. The credential's row and its Admin's are locked for the finish, so sign-ins
/// with one credential run one at a time, and the counter moves only by a compare-and-set on the
/// value that was verified. Only a refusal after the signature verified is audited: before it, the
/// response proves nothing about who sent it, and anyone with a credential ID could write events
/// against a chosen Admin.
/// </summary>
internal sealed class AdminSignIn(IAuditAppender appender, IWebAuthnVerifier verifier) : IAdminSignIn
{
    private const int ChallengeBytes = 32;

    // admin_credential's CHECK on the credential ID, refused here before the database sees it.
    private const int MaxCredentialIdBytes = 1023;

    private const string SweepExpired = "DELETE FROM admin_signin_challenge WHERE expires_at <= clock_timestamp()";

    private const string DeleteBinding = "DELETE FROM admin_signin_challenge WHERE binding_hash = @binding";

    private const string InsertChallenge =
        """
        INSERT INTO admin_signin_challenge (id, binding_hash, challenge_sha256, created_at, expires_at)
        SELECT @id, @binding, @challenge, c.t, c.t + @lifetime
        FROM (SELECT clock_timestamp() AS t) AS c
        """;

    // An expired row goes too: whatever the binding named is used up by asking.
    private const string TakeChallenge =
        """
        DELETE FROM admin_signin_challenge
        WHERE binding_hash = @binding
        RETURNING challenge_sha256, expires_at > clock_timestamp()
        """;

    private const string LockCredential =
        """
        SELECT c.id, c.admin_id, c.public_key, c.sign_count, a.webauthn_handle
        FROM admin_credential AS c
        JOIN admin AS a ON a.id = c.admin_id
        WHERE c.credential_id = @credential
        FOR UPDATE OF c, a
        """;

    private const string AdvanceCounter =
        """
        UPDATE admin_credential SET sign_count = @new, last_used_at = clock_timestamp()
        WHERE id = @id AND sign_count = @stored
        """;

    private const string CountCredentials = "SELECT count(*)::int FROM admin_credential WHERE admin_id = @admin";

    private static readonly AuditTypeCode Succeeded = AdminsEvents.SignInSucceeded.Code;

    private static readonly AuditTypeCode Failed = AdminsEvents.SignInFailed.Code;

    private static readonly AuditTypeCode Regressed = AdminsEvents.CredentialSignCountRegressed.Code;

    public async Task<AdminSignInStart> BeginAsync(
        CommandContext context,
        WebAuthnRelyingParty relyingParty,
        Secret<string>? presentedBinding,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(relyingParty);

        // Bounded by the sweep: the table holds at most 5 minutes of begins.
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SweepExpired;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (SessionSecrets.TryHash(presentedBinding) is { } presented)
        {
            await using var command = context.CreateCommand();
            command.CommandText = DeleteBinding;
            AdminSessions.Add(command, "binding", presented);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var challenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
        var (binding, bindingHash) = SessionSecrets.GenerateValue();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertChallenge;
            AdminSessions.Add(command, "id", Guid.CreateVersion7());
            AdminSessions.Add(command, "binding", bindingHash);
            AdminSessions.Add(command, "challenge", SHA256.HashData(challenge));
            AdminSessions.Add(command, "lifetime", SecurityLimits.WebAuthnChallengeLifetime);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var options = verifier.BeginAssertion(new WebAuthnAssertionBegin(relyingParty, challenge));
        return new AdminSignInStart(options, binding);
    }

    public async Task<byte[]?> TakeChallengeAsync(CommandContext context, Secret<string>? binding, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        if (SessionSecrets.TryHash(binding) is not { } bindingHash)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = TakeChallenge;
        AdminSessions.Add(command, "binding", bindingHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var hash = reader.GetFieldValue<byte[]>(0);
        return reader.GetBoolean(1) ? hash : null;
    }

    public async Task<AdminSignInOutcome> FinishAsync(
        CommandContext context,
        WebAuthnRelyingParty relyingParty,
        byte[] challengeSha256,
        WebAuthnAssertion assertion,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(relyingParty);
        ArgumentNullException.ThrowIfNull(challengeSha256);
        ArgumentNullException.ThrowIfNull(assertion);

        if (assertion.CredentialId is not { Length: >= 1 and <= MaxCredentialIdBytes })
        {
            return AdminSignInOutcome.Unattributed(WebAuthnRefusal.Malformed);
        }

        Guid credentialRow;
        Guid adminId;
        byte[] publicKey;
        uint storedCount;
        byte[]? handle;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockCredential;
            AdminSessions.Add(command, "credential", assertion.CredentialId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                // No Admin credential has this ID, a Tenant User's passkey included: nobody to audit.
                return AdminSignInOutcome.Unattributed(WebAuthnRefusal.Invalid);
            }

            credentialRow = reader.GetGuid(0);
            adminId = reader.GetGuid(1);
            publicKey = reader.GetFieldValue<byte[]>(2);
            storedCount = checked((uint)reader.GetInt64(3));
            handle = reader.IsDBNull(4) ? null : reader.GetFieldValue<byte[]>(4);
        }

        // Every credential's Admin has a handle, made at their first registration's begin; one
        // without is refused before any signature is checked, so it is only logged.
        var result = handle is null
            ? WebAuthnAssertionResult.Refused(WebAuthnRefusal.UserHandleMismatch)
            : await verifier.FinishAssertionAsync(
                new WebAuthnAssertionFinish(
                    relyingParty,
                    challengeSha256,
                    assertion,
                    new WebAuthnStoredCredential(assertion.CredentialId, publicKey, storedCount, handle)),
                cancellationToken);

        if (!result.Verified || !result.UserVerified)
        {
            var refusal = result.Refusal ?? WebAuthnRefusal.UserNotVerified;
            if (!result.SignatureVerified)
            {
                // A bad signature, a user handle or RP that isn't this credential's, and the rest:
                // nothing proves the credential's holder sent it, so it is logged, not audited.
                return AdminSignInOutcome.Unattributed(refusal);
            }

            // The holder's own signature with a counter that didn't go up. Under the row lock a
            // lower counter after a higher one is indistinguishable from a clone, and is one here.
            await AppendRefusalAsync(context, refusal == WebAuthnRefusal.SignCountRegressed ? Regressed : Failed, adminId, cancellationToken);
            return new AdminSignInOutcome(AdminSignInStatus.Refused, null, false, refusal, Audited: true);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = AdvanceCounter;
            AdminSessions.Add(command, "new", (long)result.SignCount);
            AdminSessions.Add(command, "id", credentialRow);
            AdminSessions.Add(command, "stored", (long)storedCount);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // Defence in depth: the row lock serialises sign-ins with one credential, so the
                // counter can't move between the read and here. If it ever did, the signature had
                // verified, so the refusal is the credential holder's and is audited as failed.
                await AppendRefusalAsync(context, Failed, adminId, cancellationToken);
                return new AdminSignInOutcome(AdminSignInStatus.Refused, null, false, WebAuthnRefusal.Invalid, Audited: true);
            }
        }

        // One browser holds one live Admin Session: the one it presented is replaced.
        if (presentedSession is not null)
        {
            await AdminSessions.SupersedeAsync(context, appender, presentedSession, adminId, cancellationToken);
        }

        var session = await AdminSessions.StartAsync(context, adminId, AdminSessionKind.Full, cancellationToken);

        int credentials;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = CountCredentials;
            AdminSessions.Add(command, "admin", adminId);
            credentials = (int)(await command.ExecuteScalarAsync(cancellationToken))!;
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(Succeeded, Actor.Admin(adminId), AuditTargetKind.Admin, adminId),
            detail: null,
            cancellationToken);

        return new AdminSignInOutcome(
            AdminSignInStatus.SignedIn,
            session,
            credentials >= AdminsContract.RequiredCredentials,
            null,
            Audited: true);
    }

    private Task AppendRefusalAsync(CommandContext context, AuditTypeCode code, Guid adminId, CancellationToken cancellationToken) =>
        appender.AppendAsync(context, new AuditEvent(code, Actor.Anonymous, AuditTargetKind.Admin, adminId), detail: null, cancellationToken);
}
