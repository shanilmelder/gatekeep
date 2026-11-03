using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>What a bootstrap claim came to.</summary>
public enum BootstrapClaimStatus
{
    /// <summary>The first Admin exists, bootstrap is complete and their setup Session started.</summary>
    Claimed,

    /// <summary>There is no bootstrap to claim: no token was issued, or bootstrap is complete.</summary>
    NotFound,

    /// <summary>The token is wrong, malformed or expired. Nothing was written.</summary>
    Refused,
}

/// <summary>Where bootstrap stands, read without a lock.</summary>
public enum BootstrapOpenness
{
    /// <summary><c>gatekeep init</c> hasn't issued a token yet.</summary>
    NotIssued,

    /// <summary>A token was issued and hasn't been claimed. It may have expired.</summary>
    Open,

    /// <summary>Bootstrap is complete. That is final: nothing reopens it.</summary>
    Complete,
}

/// <summary>
/// A started Admin Session's secrets: its ID, 32 CSPRNG bytes as base64url of which only the
/// SHA-256 is stored, and the CSRF token derived from it.
/// </summary>
public sealed record AdminSessionGrant(Guid AdminId, Guid SessionId, Secret<string> SessionToken, Secret<string> CsrfToken);

/// <summary>A claim's outcome: the new Session when <see cref="Status"/> is <see cref="BootstrapClaimStatus.Claimed"/>.</summary>
public sealed record BootstrapClaimResult(BootstrapClaimStatus Status, AdminSessionGrant? Session)
{
    public static BootstrapClaimResult NotFound { get; } = new(BootstrapClaimStatus.NotFound, null);

    public static BootstrapClaimResult Refused { get; } = new(BootstrapClaimStatus.Refused, null);
}

/// <summary>
/// Claims the one-time bootstrap token (Story 1.21, AD-31): the one command that creates the first
/// Admin. It runs as <c>gk_admin</c>, in a Deployment scope. The caller counts the attempt under
/// <see cref="AdminsContract.BootstrapClaimPolicy"/> first, in its own committed transaction.
/// </summary>
public interface IBootstrapClaimer
{
    /// <summary>
    /// Where bootstrap stands: open once a token was issued, until bootstrap is complete. Read
    /// without a lock, so the Bootstrap page can be gone once bootstrap is complete. The claim
    /// itself decides under the row lock.
    /// </summary>
    Task<BootstrapOpenness> ReadStateAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// These must be the transaction's first statements: it runs READ COMMITTED with the
    /// claimer's <c>lock_timeout</c>, and locks the <c>bootstrap_state</c> row first, so
    /// concurrent claims serialise and a claim can't race a reissue. A lock wait past the timeout
    /// fails with SQL state 55P03. With no row, or a completed one, it returns
    /// <see cref="BootstrapClaimStatus.NotFound"/>. <paramref name="submittedToken"/> is the token's
    /// UTF-8 bytes: one that is wrong, malformed or expired is <see cref="BootstrapClaimStatus.Refused"/>,
    /// compared in constant time with the stored hash. Otherwise it creates the Admin as Deployment
    /// Owner, completes bootstrap, starts a setup Admin Session and appends
    /// <see cref="AdminsEvents.BootstrapAdminCreated"/>, all in the caller's transaction.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<BootstrapClaimResult> ClaimAsync(
        CommandContext context,
        Secret<byte[]> submittedToken,
        CancellationToken cancellationToken);
}
