using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>One planned step: a stage, and the Tenant it runs for when it's a Tenant stage.</summary>
public sealed record OperationStepPlan(OperationCode Stage, Guid? TenantId = null);

/// <summary>An Operation's status. Active means <see cref="Running"/> or <see cref="Failed"/>.</summary>
public enum OperationStatus
{
    Running,
    Failed,
    Succeeded,
}

public enum OperationStepStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,
}

/// <summary>One step as the <c>operation</c> resource lists it. It holds codes and IDs only.</summary>
public sealed record OperationStepResource(
    Guid Id,
    OperationCode Stage,
    Guid? TenantId,
    OperationStepStatus Status,
    OperationCode? ResultCode,
    int Attempts,
    DateTimeOffset UpdatedAt);

/// <summary>The <c>operation</c> resource (AD-30): the Operation and the steps its reader may see.</summary>
public sealed record OperationResource(
    Guid Id,
    OperationType Type,
    Guid? TenantId,
    OperationStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? FinishedAt,
    IReadOnlyList<OperationStepResource> Steps);

/// <summary>An Operation of the same type and scope is already running or failed. Nothing was written.</summary>
public sealed class OperationAlreadyActiveException(OperationType type, Guid? tenantId)
    : Exception($"An Operation of type {type} is already active for {(tenantId is null ? "the Deployment" : "this Tenant")}.")
{
    public OperationType Type { get; } = type;

    public Guid? TenantId { get; } = tenantId;
}

/// <summary>Only a <c>failed</c> Operation can be retried, and none with this ID is (Story 1.27).</summary>
public sealed class OperationNotFailedException(Guid operationId)
    : InvalidOperationException("Only a failed Operation can be retried.")
{
    public Guid OperationId { get; } = operationId;
}

/// <summary>
/// Starts, retries and reads Operations (AD-30). Start and retry run in the caller's
/// Deployment context: the Operation, its steps and its run job are written together.
/// </summary>
public interface IOperations
{
    /// <summary>
    /// Writes a <c>running</c> Operation with one <c>pending</c> step per plan entry, and
    /// enqueues <c>operations.operation.run</c> carrying only its ID.
    /// </summary>
    /// <param name="tenantId">The Tenant the Operation is scoped to, or null for the Deployment.</param>
    /// <exception cref="OperationAlreadyActiveException">
    /// An Operation of this type and scope is running or failed. The caller's transaction stays usable.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// The type or a stage isn't in the registry, a plan entry doesn't fit its stage, or a Tenant doesn't exist.
    /// </exception>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<OperationResource> StartAsync(
        CommandContext context,
        OperationType type,
        Guid? tenantId,
        IReadOnlyList<OperationStepPlan> steps,
        CancellationToken cancellationToken);

    /// <summary>
    /// Sets only the <c>failed</c> steps of a <c>failed</c> Operation back to <c>pending</c>, the
    /// Operation to <c>running</c>, and enqueues its run job again. Succeeded steps never run again.
    /// </summary>
    /// <exception cref="OperationNotFailedException">No <c>failed</c> Operation has this ID.</exception>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<OperationResource> RetryAsync(CommandContext context, Guid operationId, CancellationToken cancellationToken);

    /// <summary>The Operation with every step, or null.</summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant: a Tenant's path reads through <see cref="GetForTenantAsync"/>.</exception>
    Task<OperationResource?> GetAsync(CommandContext context, Guid operationId, CancellationToken cancellationToken);

    /// <summary>
    /// The <c>running</c> or <c>failed</c> Operation of <paramref name="type"/> scoped to
    /// <paramref name="tenantId"/>, or to the Deployment when null, with every step; or null when
    /// there is none. The one-active index allows at most one.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    Task<OperationResource?> FindActiveAsync(CommandContext context, OperationType type, Guid? tenantId, CancellationToken cancellationToken);

    /// <summary>
    /// The <c>running</c> or <c>failed</c> Operation of <paramref name="type"/> for each of
    /// <paramref name="tenantIds"/> that has one, by Tenant, in one query, without their steps.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    Task<IReadOnlyDictionary<Guid, (Guid OperationId, OperationStatus Status)>> FindActiveForTenantsAsync(
        CommandContext context,
        OperationType type,
        IReadOnlyCollection<Guid> tenantIds,
        CancellationToken cancellationToken);

    /// <summary>
    /// The Operation with only <paramref name="tenantId"/>'s steps. Null when it doesn't exist,
    /// is scoped to another Tenant, or is a Deployment Operation with no step for this Tenant.
    /// </summary>
    Task<OperationResource?> GetForTenantAsync(
        CommandContext context,
        Guid operationId,
        Guid tenantId,
        CancellationToken cancellationToken);
}
