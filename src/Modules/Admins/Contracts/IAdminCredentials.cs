using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>What kind of authenticator a credential is, as far as its flags and transports say.</summary>
public enum AdminCredentialKind
{
    /// <summary>Backup-eligible, or reported <c>internal</c> or <c>hybrid</c>.</summary>
    Passkey,

    /// <summary>Anything else, such as a USB or NFC key.</summary>
    SecurityKey,
}

/// <summary>
/// One of an Admin's credentials as Your credentials shows it: its row's ID, its kind, whether it
/// is backed up now, when it was added and last used, and whether removing it keeps the floor.
/// Never its WebAuthn credential ID, public key, AAGUID, counter or user handle.
/// </summary>
public sealed record AdminCredentialSummary(
    Guid Id,
    AdminCredentialKind Kind,
    bool BackedUp,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    bool Removable);

/// <summary>An Admin's credentials, oldest first, and whether they hold a confirmed, unused Recovery Code.</summary>
public sealed record AdminCredentialList(IReadOnlyList<AdminCredentialSummary> Credentials, bool RecoveryCode);

/// <summary>What a removal came to.</summary>
public enum CredentialRemovalStatus
{
    /// <summary>Removed, its grants with it, and the Admin's other live Sessions ended.</summary>
    Removed,

    /// <summary>
    /// Removed, and the credential was the one that confirmed the removal: the current Session ended
    /// too, as nothing it holds proves its Admin any more.
    /// </summary>
    RemovedSessionEnded,

    /// <summary>No such credential among the Session's Admin's own: nothing changed.</summary>
    NotFound,

    /// <summary>Fewer than <see cref="AdminsContract.RequiredCredentials"/> would remain: nothing changed.</summary>
    Minimum,
}

/// <summary>
/// Your credentials (Story 1.26): the Session's own Admin's credentials, and removing one of them.
/// Every call runs as <c>gk_admin</c>, in a Deployment scope. A removal locks the Admin's row,
/// so it and a registration or another removal for that Admin take turns, and the database's
/// own trigger refuses any delete that would leave fewer than two.
/// </summary>
public interface IAdminCredentials
{
    /// <summary>The Session's Admin's credentials, oldest first, each with <c>removable</c> by the floor.</summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    Task<AdminCredentialList> ListAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the credential whose row is <paramref name="credentialId"/>, when it is the
    /// Session's Admin's own and at least two would remain: deletes every grant made with it, then
    /// the credential, ends every other live Session of that Admin as <c>revoked</c> with
    /// <see cref="AdminsEvents.SessionRevoked"/> each, and appends
    /// <see cref="AdminsEvents.CredentialRemoved"/>, all in the caller's transaction. The current
    /// Session stays, unless <paramref name="confirmedWith"/>, the credential whose fresh assertion
    /// confirmed this removal, is the one removed: then it ends as <c>revoked</c> too. The caller has
    /// already used up that fresh assertion.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<CredentialRemovalStatus> RemoveAsync(CommandContext context, AdminSession session, Guid credentialId, Guid? confirmedWith, CancellationToken cancellationToken);
}
