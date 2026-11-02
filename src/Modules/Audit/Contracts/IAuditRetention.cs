using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// Deletes audit events past <c>RetentionPeriods.LogDays</c> (NFR-15, AD-16). Runs as
/// <c>gk_retention</c>, the only role that may delete events, on the context's chain: its
/// Tenant's, or the Deployment's when the context has no Tenant. Both methods take the
/// sealer's chain lock, so neither races a seal, and work in the caller's transaction. Ages
/// are measured on the database's clock, the one that set each <c>occurred_at</c>.
/// </summary>
public interface IAuditRetention
{
    /// <summary>
    /// Deletes the longest sealed prefix of the chain whose every row is older than the
    /// period, never the last event that isn't a checkpoint nor anything after it: detail
    /// first, then the events, then one <c>audit.retention.checkpoint</c> event naming the
    /// last deleted row's <c>epoch</c>, <c>seq</c> and <c>hash</c>. The checkpoint is sealed by
    /// the next seal pass. A prefix of checkpoints alone isn't cut, so a dormant chain stays as it is.
    /// </summary>
    /// <exception cref="InvalidOperationException">The prefix has a gap: a cut would hide it.</exception>
    /// <returns>How many events were deleted. Zero when nothing was due, and then nothing is written.</returns>
    [StateChanging]
    Task<int> ApplyAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes a Tenant's whole chain and its detail, once its retention has ended: only if
    /// every event is sealed and older than the period. Checkpoints don't count as events
    /// there. Otherwise it deletes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant: the Deployment chain is never purged.</exception>
    /// <returns>Whether the Tenant has no audit event left. True for a chain that was already empty.</returns>
    [StateChanging]
    Task<bool> PurgeAsync(CommandContext context, CancellationToken cancellationToken);
}
