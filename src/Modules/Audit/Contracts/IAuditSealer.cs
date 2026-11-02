using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// Seals one chain (AD-16): the context's Tenant chain, or the Deployment chain when the
/// context has no Tenant. Runs as <c>gk_sealer</c>, in the caller's transaction, so work the
/// caller adds there lands with the seal.
/// </summary>
public interface IAuditSealer
{
    /// <summary>
    /// Takes the chain's transaction-level lock, reads its head and seals up to
    /// <paramref name="maxEvents"/> unsealed rows in ID order. The caller's transaction must be
    /// READ COMMITTED, the default of both Kernel scopes, so a sealer that waited on the lock
    /// reads the head the other sealer left. At a stricter isolation level a waiting sealer
    /// fails, on the unique <c>seq</c> key or as a serialization failure, instead of forking the chain.
    /// </summary>
    /// <returns>How many rows were sealed. Zero when none was waiting.</returns>
    [StateChanging]
    Task<int> SealAsync(CommandContext context, int maxEvents, CancellationToken cancellationToken);
}
