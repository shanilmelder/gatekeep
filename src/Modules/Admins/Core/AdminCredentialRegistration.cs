using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Admin credential registration over <c>admin</c>, <c>admin_session</c> and
/// <c>admin_credential</c> (Story 1.22). Each step locks the Admin's row first, so a begin, a
/// take and a finish for one Admin never interleave. The challenge lives on the Session row only
/// as its SHA-256 with an expiry from the database clock; taking it clears it, in a transaction
/// of its own, so a used or refused challenge never verifies again.
/// </summary>
internal sealed class AdminCredentialRegistration(IAuditAppender appender, IWebAuthnVerifier verifier) : IAdminCredentialRegistration
{
    private const int ChallengeBytes = 32;

    private const int UserHandleBytes = 64;

    // admin_credential's CHECKs, refused here as malformed before they're reached.
    private const int MaxCredentialIdBytes = 1023;

    private const int MaxPublicKeyBytes = 2048;

    private static readonly HashSet<string> KnownTransports =
        new(StringComparer.Ordinal) { "usb", "nfc", "ble", "smart-card", "hybrid", "internal" };

    private const string LockAdmin =
        """
        SELECT a.webauthn_handle, a.deployment_owner
        FROM admin AS a
        WHERE a.id = @admin
        FOR UPDATE
        """;

    private const string Credentials =
        "SELECT credential_id, transports FROM admin_credential WHERE admin_id = @admin ORDER BY created_at, id";

    private const string SetHandle =
        "UPDATE admin SET webauthn_handle = @handle WHERE id = @admin AND webauthn_handle IS NULL";

    private const string SetChallenge =
        """
        UPDATE admin_session
        SET registration_challenge_sha256 = @hash,
            registration_challenge_expires_at = clock_timestamp() + @lifetime
        WHERE id = @id AND ended_at IS NULL
        """;

    // The row is locked first, so a take racing another reads the challenge once.
    private const string ReadChallenge =
        """
        SELECT registration_challenge_sha256, registration_challenge_expires_at > clock_timestamp()
        FROM admin_session
        WHERE id = @id AND ended_at IS NULL
        FOR UPDATE
        """;

    private const string ClearChallenge =
        """
        UPDATE admin_session
        SET registration_challenge_sha256 = NULL, registration_challenge_expires_at = NULL
        WHERE id = @id AND registration_challenge_sha256 IS NOT NULL
        """;

    private const string CredentialExists = "SELECT EXISTS (SELECT 1 FROM admin_credential WHERE credential_id = @credential)";

    private const string InsertCredential =
        """
        INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid, transports, backup_eligible, backed_up)
        VALUES (@id, @admin, @credential, @public_key, @sign_count, @aaguid, @transports, @backup_eligible, @backed_up)
        """;

    private static readonly AuditTypeCode Registered = AdminsEvents.CredentialRegistered.Code;

    public async Task<CredentialRegistrationStart> BeginAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(relyingParty);

        var admin = await LockAdminAsync(context, session.AdminId, cancellationToken);
        var existing = await CredentialsAsync(context, session.AdminId, cancellationToken);
        var (_, recoveryCode) = await AdminSessions.FloorAsync(context, session.AdminId, cancellationToken);
        if (Barred(session, existing.Count, recoveryCode) is { } barred)
        {
            return new CredentialRegistrationStart(barred, null);
        }

        var challenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SetChallenge;
            AdminSessions.Add(command, "hash", SHA256.HashData(challenge));
            AdminSessions.Add(command, "lifetime", SecurityLimits.WebAuthnChallengeLifetime);
            AdminSessions.Add(command, "id", session.Id);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // Ended since the request checks authenticated it: nothing else is written.
                return new CredentialRegistrationStart(CredentialRegistrationStatus.SessionEnded, null);
            }
        }

        var handle = admin.Handle ?? await CreateHandleAsync(context, session.AdminId, cancellationToken);
        var options = verifier.BeginRegistration(new WebAuthnRegistrationBegin(relyingParty, User(admin, handle), existing, challenge));
        return new CredentialRegistrationStart(CredentialRegistrationStatus.Accepted, options);
    }

    public async Task<CredentialRegistrationChallenge> TakeChallengeAsync(
        CommandContext context,
        AdminSession session,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        await LockAdminAsync(context, session.AdminId, cancellationToken);
        var existing = await CredentialsAsync(context, session.AdminId, cancellationToken);
        var (_, recoveryCode) = await AdminSessions.FloorAsync(context, session.AdminId, cancellationToken);

        bool found;
        byte[]? hash = null;
        var live = false;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReadChallenge;
            AdminSessions.Add(command, "id", session.Id);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            found = await reader.ReadAsync(cancellationToken);
            if (found && !reader.IsDBNull(0))
            {
                hash = reader.GetFieldValue<byte[]>(0);
                live = reader.GetBoolean(1);
            }
        }

        if (!found)
        {
            return new CredentialRegistrationChallenge(CredentialRegistrationStatus.SessionEnded, null);
        }

        if (hash is not null)
        {
            await using var command = context.CreateCommand();
            command.CommandText = ClearChallenge;
            AdminSessions.Add(command, "id", session.Id);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (Barred(session, existing.Count, recoveryCode) is { } barred)
        {
            return new CredentialRegistrationChallenge(barred, null);
        }

        return hash is not null && live
            ? new CredentialRegistrationChallenge(CredentialRegistrationStatus.Accepted, hash)
            : CredentialRegistrationChallenge.None;
    }

    public async Task<CredentialRegistrationOutcome> FinishAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        byte[] challengeSha256,
        WebAuthnAttestation attestation,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(relyingParty);
        ArgumentNullException.ThrowIfNull(challengeSha256);
        ArgumentNullException.ThrowIfNull(attestation);

        var admin = await LockAdminAsync(context, session.AdminId, cancellationToken);
        var existing = await CredentialsAsync(context, session.AdminId, cancellationToken);
        var (_, recoveryCode) = await AdminSessions.FloorAsync(context, session.AdminId, cancellationToken);
        var metBefore = AdminSession.MeetsFloor(existing.Count, recoveryCode);
        if (Barred(session, existing.Count, recoveryCode) is { } barred)
        {
            return new CredentialRegistrationOutcome(barred, existing.Count, metBefore);
        }

        // A challenge was handed out, so the handle exists; without one nothing can match.
        if (admin.Handle is null)
        {
            return Refused(existing.Count, WebAuthnRefusal.ChallengeMismatch);
        }

        var result = await verifier.FinishRegistrationAsync(
            new WebAuthnRegistrationFinish(relyingParty, User(admin, admin.Handle), existing, challengeSha256, attestation),
            cancellationToken);
        if (result.Credential is not { } credential)
        {
            return Refused(existing.Count, result.Refusal ?? WebAuthnRefusal.Invalid);
        }

        // What the table's CHECKs would refuse, refused here as malformed instead.
        if (credential.CredentialId is not { Length: >= 1 and <= MaxCredentialIdBytes }
            || credential.PublicKey is not { Length: >= 1 and <= MaxPublicKeyBytes })
        {
            return Refused(existing.Count, WebAuthnRefusal.Malformed);
        }

        if (!credential.UserVerified)
        {
            return Refused(existing.Count, WebAuthnRefusal.UserNotVerified);
        }

        // Unique Deployment-wide: an authenticator that returns another Admin's credential too.
        await using (var command = context.CreateCommand())
        {
            command.CommandText = CredentialExists;
            AdminSessions.Add(command, "credential", credential.CredentialId);
            if (await command.ExecuteScalarAsync(cancellationToken) is true)
            {
                return Refused(existing.Count, WebAuthnRefusal.ExcludedCredential);
            }
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertCredential;
            AdminSessions.Add(command, "id", Guid.CreateVersion7());
            AdminSessions.Add(command, "admin", session.AdminId);
            AdminSessions.Add(command, "credential", credential.CredentialId);
            AdminSessions.Add(command, "public_key", credential.PublicKey);
            AdminSessions.Add(command, "sign_count", (long)credential.SignCount);
            AdminSessions.Add(command, "aaguid", credential.Aaguid);
            AdminSessions.Add(command, "transports", credential.Transports.Where(KnownTransports.Contains).Distinct(StringComparer.Ordinal).ToArray());
            AdminSessions.Add(command, "backup_eligible", credential.BackupEligible);
            // BS without BE is no state a credential can be in: it is stored as not backed up.
            AdminSessions.Add(command, "backed_up", credential.BackedUp && credential.BackupEligible);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var actor = Actor.Admin(session.AdminId);
        await appender.AppendAsync(context, new AuditEvent(Registered, actor, AuditTargetKind.Admin, session.AdminId), detail: null, cancellationToken);

        var credentials = existing.Count + 1;
        var meets = AdminSession.MeetsFloor(credentials, recoveryCode);
        if (meets)
        {
            // A recovery Session follows a lost device: whoever holds it may hold another Session of
            // this Admin, signed in with the lost credential. Back at the floor, every other one ends.
            if (session.Kind == AdminSessionKind.Recovery)
            {
                await AdminSessions.RevokeAsync(context, appender, session.AdminId, session.AdminId, keep: session.Id, cancellationToken);
            }

            // Setup and recovery Sessions become full; completion is audited only when this step reached the floor.
            await AdminSessions.MeetFloorAsync(context, appender, session.AdminId, metBefore, cancellationToken);
        }

        return new CredentialRegistrationOutcome(CredentialRegistrationStatus.Accepted, credentials, meets);
    }

    /// <summary>
    /// Why the Session may not register now, or null when it may: at the maximum, never; in a
    /// restricted Session, only while the Admin is below the floor, or once in a recovery Session.
    /// A full Session's begin passed its fresh-assertion gate in the handler.
    /// </summary>
    private static CredentialRegistrationStatus? Barred(AdminSession session, int credentials, bool recoveryCode)
    {
        if (credentials >= AdminsContract.MaxCredentials)
        {
            return CredentialRegistrationStatus.Maximum;
        }

        if (session.Restricted && session.Kind != AdminSessionKind.Recovery && AdminSession.MeetsFloor(credentials, recoveryCode))
        {
            return CredentialRegistrationStatus.Complete;
        }

        return null;
    }

    private static CredentialRegistrationOutcome Refused(int credentials, WebAuthnRefusal refusal) =>
        new(CredentialRegistrationStatus.Refused, credentials, SetupComplete: false, refusal);

    /// <summary>
    /// What an authenticator shows for the account. Admins have no name or email yet, so it is
    /// their role; the handle, not the name, is what identifies them.
    /// </summary>
    private static WebAuthnUser User(LockedAdmin admin, byte[] handle)
    {
        var name = admin.DeploymentOwner ? "Deployment Owner" : "Gatekeep Admin";
        return new WebAuthnUser(handle, name, name);
    }

    private static async Task<LockedAdmin> LockAdminAsync(CommandContext context, Guid adminId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = LockAdmin;
        AdminSessions.Add(command, "admin", adminId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("An authenticated Admin Session has no Admin.");
        }

        return new LockedAdmin(reader.IsDBNull(0) ? null : reader.GetFieldValue<byte[]>(0), reader.GetBoolean(1));
    }

    /// <summary>The Admin's credentials, with the transports each reported, as the exclude list.</summary>
    private static async Task<IReadOnlyList<WebAuthnCredentialDescriptor>> CredentialsAsync(
        CommandContext context,
        Guid adminId,
        CancellationToken cancellationToken)
    {
        var credentials = new List<WebAuthnCredentialDescriptor>();
        await using var command = context.CreateCommand();
        command.CommandText = Credentials;
        AdminSessions.Add(command, "admin", adminId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            credentials.Add(new WebAuthnCredentialDescriptor("public-key", reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<string[]>(1)));
        }

        return credentials;
    }

    /// <summary>The Admin's WebAuthn user handle, made once: 64 CSPRNG bytes, never their ID.</summary>
    private static async Task<byte[]> CreateHandleAsync(CommandContext context, Guid adminId, CancellationToken cancellationToken)
    {
        var handle = RandomNumberGenerator.GetBytes(UserHandleBytes);
        await using var command = context.CreateCommand();
        command.CommandText = SetHandle;
        AdminSessions.Add(command, "handle", handle);
        AdminSessions.Add(command, "admin", adminId);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("The Admin's user handle was set under the row lock.");
        }

        return handle;
    }

    private sealed record LockedAdmin(byte[]? Handle, bool DeploymentOwner);
}
