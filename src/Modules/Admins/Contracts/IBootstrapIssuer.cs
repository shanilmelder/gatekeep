using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>One issued bootstrap token: the database's times, and whether it replaced an earlier one.</summary>
public sealed record BootstrapIssue(DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, bool Reissued);

/// <summary>
/// Issues the one-time bootstrap token (Story 1.19). Story 1.21 consumes it and completes
/// bootstrap; nothing here completes it.
/// </summary>
public interface IBootstrapIssuer
{
    /// <summary>
    /// Whether bootstrap is complete, read without a lock. <c>gatekeep init</c> asks first, so a
    /// completed Deployment is refused before custody or the token file is touched.
    /// </summary>
    Task<bool> IsCompleteAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Stores only the SHA-256 of <paramref name="token"/> (<see cref="BootstrapToken.Hash(ReadOnlySpan{byte})"/>),
    /// with issue and expiry times 15 minutes apart from one <c>clock_timestamp()</c>, and appends
    /// the issue event, in the context's Deployment transaction. These must be the transaction's
    /// first statements: it runs READ COMMITTED with a 30-second <c>lock_timeout</c>. The upsert
    /// takes the row lock, held until the caller commits or rolls back, so concurrent issues
    /// serialise, even on an empty table, through the primary key. Returns null, having written
    /// nothing, when bootstrap completed meanwhile.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    /// <exception cref="ArgumentException">The token isn't 64 lower-case hex characters.</exception>
    [StateChanging]
    Task<BootstrapIssue?> IssueAsync(CommandContext context, Secret<byte[]> token, CancellationToken cancellationToken);
}
