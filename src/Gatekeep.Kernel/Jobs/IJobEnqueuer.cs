using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Kernel.Jobs;

/// <summary>
/// The only way to enqueue a job (AD-15). The job is written in the caller's own
/// transaction, so it commits or rolls back with the state change that asked for it.
/// The database refuses a type the registry doesn't let the connected role enqueue.
/// </summary>
public interface IJobEnqueuer
{
    /// <summary>
    /// Enqueues a Tenant job. The Tenant is the context's own, never a parameter.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    /// <exception cref="ArgumentException">
    /// The type isn't a Tenant type in the registry, or it carries a credential its type doesn't allow.
    /// Nothing has been written.
    /// </exception>
    /// <returns>The job's ID.</returns>
    [StateChanging]
    Task<Guid> EnqueueAsync(
        CommandContext context,
        JobType type,
        JobPayload? payload,
        DateTimeOffset? runAfter,
        CancellationToken cancellationToken);

    /// <summary>
    /// Enqueues a Deployment-wide job. Its only parameter is an optional Operation ID,
    /// and it carries no payload.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    /// <exception cref="ArgumentException">The type isn't a Deployment-wide type in the registry.</exception>
    /// <returns>The job's ID.</returns>
    [StateChanging]
    Task<Guid> EnqueueAsync(
        CommandContext context,
        JobType type,
        Guid? operationId,
        DateTimeOffset? runAfter,
        CancellationToken cancellationToken);
}
