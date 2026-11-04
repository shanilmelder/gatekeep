using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.WebAuthn;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>What one checked assertion came to.</summary>
internal enum AssertionCheckKind
{
    /// <summary>Verified: the counter advanced by compare-and-set and the BS flag is stored.</summary>
    Verified,

    /// <summary>Refused before any signature verified, or naming no credential it may use: nothing proves who sent it.</summary>
    Unattributed,

    /// <summary>The holder's own signature with a counter that didn't go up: a possible clone.</summary>
    Regressed,

    /// <summary>The holder's own signature, refused after it for another reason, the compare-and-set's miss included.</summary>
    Failed,
}

/// <summary>A checked assertion: its kind, the credential row and Admin it named when known, and why it was refused.</summary>
internal sealed record AssertionCheck(AssertionCheckKind Kind, Guid CredentialRow, Guid AdminId, WebAuthnRefusal? Refusal)
{
    public static AssertionCheck Unattributed(WebAuthnRefusal refusal) => new(AssertionCheckKind.Unattributed, Guid.Empty, Guid.Empty, refusal);
}

/// <summary>
/// The one WebAuthn assertion check Admin sign-in (Story 1.23) and fresh assertions (Story 1.26)
/// share, in the caller's transaction. It locks the credential's row and its Admin's, so assertions
/// with one credential run one at a time; for a fresh assertion the credential must be the
/// Session's Admin's own. The ceremony itself is the Kernel verifier's, with the Admin's user
/// handle and the stored BE flag. A verified one advances the counter only by compare-and-set on
/// the value that was verified, and stores the latest BS flag and the time of use. It writes no
/// event: what a refusal comes to is each caller's.
/// </summary>
internal static class AdminAssertions
{
    // admin_credential's CHECK on the credential ID, refused here before the database sees it.
    private const int MaxCredentialIdBytes = 1023;

    private const string FindOwner = "SELECT admin_id FROM admin_credential WHERE credential_id = @credential";

    // The Admin's row first, then the credential's: the order a removal and a registration take them in,
    // so an assertion and a removal for one Admin never lock in opposite orders.
    private const string LockAdmin = "SELECT webauthn_handle FROM admin WHERE id = @admin FOR UPDATE";

    private const string LockCredential =
        """
        SELECT id, public_key, sign_count, backup_eligible
        FROM admin_credential
        WHERE credential_id = @credential AND admin_id = @admin
        FOR UPDATE
        """;

    private const string AdvanceCounter =
        """
        UPDATE admin_credential
        SET sign_count = @new, backup_eligible = COALESCE(backup_eligible, @backup_eligible), backed_up = @backed_up,
            last_used_at = clock_timestamp()
        WHERE id = @id AND sign_count = @stored
        """;

    /// <summary>
    /// Checks <paramref name="assertion"/> against <paramref name="challengeSha256"/>. With
    /// <paramref name="owner"/>, a credential of any other Admin is unattributed, before its
    /// signature is checked, exactly as an unknown one is.
    /// </summary>
    public static async Task<AssertionCheck> CheckAsync(
        CommandContext context,
        IWebAuthnVerifier verifier,
        WebAuthnRelyingParty relyingParty,
        byte[] challengeSha256,
        WebAuthnAssertion assertion,
        Guid? owner,
        CancellationToken cancellationToken)
    {
        if (assertion.CredentialId is not { Length: >= 1 and <= MaxCredentialIdBytes })
        {
            return AssertionCheck.Unattributed(WebAuthnRefusal.Malformed);
        }

        Guid adminId;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = FindOwner;
            AdminSessions.Add(command, "credential", assertion.CredentialId);
            if (await command.ExecuteScalarAsync(cancellationToken) is not Guid found)
            {
                // No Admin credential has this ID, a Tenant User's passkey included: nobody to audit.
                return AssertionCheck.Unattributed(WebAuthnRefusal.Invalid);
            }

            adminId = found;
        }

        // Another Admin's credential confirms nothing in this Session: the same as an unknown one.
        if (owner is { } required && required != adminId)
        {
            return AssertionCheck.Unattributed(WebAuthnRefusal.Invalid);
        }

        byte[]? handle;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockAdmin;
            AdminSessions.Add(command, "admin", adminId);
            handle = await command.ExecuteScalarAsync(cancellationToken) as byte[];
        }

        Guid credentialRow;
        byte[] publicKey;
        uint storedCount;
        bool? backupEligible;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockCredential;
            AdminSessions.Add(command, "credential", assertion.CredentialId);
            AdminSessions.Add(command, "admin", adminId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                // Removed while this waited for the Admin's lock: the same as an unknown one.
                return AssertionCheck.Unattributed(WebAuthnRefusal.Invalid);
            }

            credentialRow = reader.GetGuid(0);
            publicKey = reader.GetFieldValue<byte[]>(1);
            storedCount = checked((uint)reader.GetInt64(2));
            backupEligible = reader.IsDBNull(3) ? null : reader.GetBoolean(3);
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
                    new WebAuthnStoredCredential(assertion.CredentialId, publicKey, storedCount, handle, backupEligible)),
                cancellationToken);

        if (!result.Verified || !result.UserVerified)
        {
            var refusal = result.Refusal ?? WebAuthnRefusal.UserNotVerified;
            if (!result.SignatureVerified)
            {
                // A bad signature, a user handle or RP that isn't this credential's, and the rest:
                // nothing proves the credential's holder sent it.
                return AssertionCheck.Unattributed(refusal);
            }

            // The holder's own signature with a counter that didn't go up. Under the row lock a
            // lower counter after a higher one is indistinguishable from a clone, and is one here.
            return new AssertionCheck(
                refusal == WebAuthnRefusal.SignCountRegressed ? AssertionCheckKind.Regressed : AssertionCheckKind.Failed,
                credentialRow,
                adminId,
                refusal);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = AdvanceCounter;
            AdminSessions.Add(command, "new", (long)result.SignCount);
            // An unknown BE, from a credential stored before its flags were kept, is recorded now. BS
            // without BE is no state a credential can be in: it is stored as not backed up.
            var eligible = backupEligible ?? result.BackupEligible;
            AdminSessions.Add(command, "backup_eligible", eligible);
            AdminSessions.Add(command, "backed_up", result.BackedUp && eligible);
            AdminSessions.Add(command, "id", credentialRow);
            AdminSessions.Add(command, "stored", (long)storedCount);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // Defence in depth: the row lock serialises assertions with one credential, so the
                // counter can't move between the read and here. If it ever did, the signature had
                // verified, so the refusal is the credential holder's.
                return new AssertionCheck(AssertionCheckKind.Failed, credentialRow, adminId, WebAuthnRefusal.Invalid);
            }
        }

        return new AssertionCheck(AssertionCheckKind.Verified, credentialRow, adminId, null);
    }
}
