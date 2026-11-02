namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>
/// Seals every chain as <c>gk_sealer</c> (AD-16): the Deployment chain, then each Tenant's,
/// one transaction per chain. A failing chain is logged by Tenant ID and the rest go on.
/// </summary>
public interface IAuditSealLoop : IAsyncDisposable
{
    /// <summary>The most rows one pass seals on one chain, so a flood drains over several passes.</summary>
    const int MaxEventsPerChain = 500;

    /// <summary>One pass over every chain.</summary>
    /// <returns>How many rows were sealed, across all chains.</returns>
    Task<int> PassAsync(CancellationToken cancellationToken);

    /// <summary>Runs a pass every interval until cancelled.</summary>
    Task RunAsync(CancellationToken cancellationToken);
}
