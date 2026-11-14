using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// One search of the Deployment Log (Story 7.7, FR-40). Every filter set is ANDed, and each one is
/// on an indexed envelope column of <c>deployment_audit_event</c>. Codes are already resolved by the
/// caller: an event type is one code, an outcome the codes the catalogues give it.
/// </summary>
public sealed record DeploymentLogQuery
{
    /// <summary>The page size: newest first, at most this many events.</summary>
    public const int MaxLimit = TenantLogQuery.MaxLimit;

    /// <summary>Only events whose code is one of these, when set. An empty set matches nothing.</summary>
    public IReadOnlyCollection<AuditTypeCode>? Types { get; init; }

    /// <summary>Only events whose code is one of these too, when set: the codes of one outcome.</summary>
    public IReadOnlyCollection<AuditTypeCode>? OutcomeTypes { get; init; }

    /// <summary>Only events whose Actor or target is this Admin, when set.</summary>
    public Guid? AdminId { get; init; }

    /// <summary>Only events whose target is this Tenant (its internal ID), when set.</summary>
    public Guid? TenantId { get; init; }

    /// <summary>Only events at or after this instant, when set.</summary>
    public DateTimeOffset? From { get; init; }

    /// <summary>Only events before this instant, when set.</summary>
    public DateTimeOffset? To { get; init; }

    /// <summary>Only events older than this one, by ID: the previous page's last event.</summary>
    public Guid? After { get; init; }

    /// <summary>How many events a page holds, 1 to <see cref="MaxLimit"/>.</summary>
    public int Limit { get; init; } = MaxLimit;
}

/// <summary>
/// Reads the Deployment Log (Story 7.7), in a Deployment scope: the one chain in
/// <c>deployment_audit_event</c>, with <c>deployment_audit_detail</c> beside it. It only reads.
/// Rows take the same shapes as a Tenant's Log, so one response serves both.
/// </summary>
public interface IDeploymentLogReader
{
    /// <summary>One page, newest first.</summary>
    /// <exception cref="InvalidOperationException"><paramref name="context"/> is in a Tenant scope.</exception>
    /// <exception cref="ArgumentException">The query is out of range.</exception>
    Task<TenantLogPage> SearchAsync(CommandContext context, DeploymentLogQuery query, CancellationToken cancellationToken);

    /// <summary>
    /// The event, with its seal (null while unsealed) and its detail (null when it has no detail
    /// row), or null when the Deployment Log has none with <paramref name="eventId"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException"><paramref name="context"/> is in a Tenant scope.</exception>
    Task<TenantLogEvent?> FindAsync(CommandContext context, Guid eventId, CancellationToken cancellationToken);
}
