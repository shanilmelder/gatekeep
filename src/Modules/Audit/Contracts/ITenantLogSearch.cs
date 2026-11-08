using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// One search of a Tenant's Log (Story 7.4, FR-40). Every filter set is ANDed, and each one is
/// on an indexed envelope column. Codes are already resolved by the caller: an event type is one
/// code, an outcome the codes the catalogues give it. A User is an internal reference, or an
/// email, which <see cref="ITenantLogSearch"/> resolves to the User references first.
/// </summary>
public sealed record TenantLogQuery
{
    /// <summary>The page size: newest first, at most this many events.</summary>
    public const int MaxLimit = 50;

    /// <summary>Only events whose code is one of these, when set. An empty set matches nothing.</summary>
    public IReadOnlyCollection<AuditTypeCode>? Types { get; init; }

    /// <summary>Only events whose code is one of these too, when set: the codes of one outcome.</summary>
    public IReadOnlyCollection<AuditTypeCode>? OutcomeTypes { get; init; }

    /// <summary>Only events whose Actor or target is this User, when set.</summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// Only events whose Actor or target is a User some event's detail names with exactly this
    /// email, when set. Exclusive with <see cref="UserId"/>.
    /// </summary>
    public string? UserEmail { get; init; }

    /// <summary>Only events whose Actor or target is this Application (a <c>client</c> reference), when set.</summary>
    public Guid? ApplicationId { get; init; }

    /// <summary>Only events at or after this instant, when set.</summary>
    public DateTimeOffset? From { get; init; }

    /// <summary>Only events before this instant, when set.</summary>
    public DateTimeOffset? To { get; init; }

    /// <summary>Only events older than this one, by ID: the previous page's last event.</summary>
    public Guid? After { get; init; }

    /// <summary>How many events a page holds, 1 to <see cref="MaxLimit"/>.</summary>
    public int Limit { get; init; } = MaxLimit;
}

/// <summary>One event as a Log lists it: the envelope, and nothing from its detail.</summary>
public sealed record TenantLogEntry(
    Guid Id,
    DateTimeOffset OccurredAt,
    AuditTypeCode Type,
    ActorKind ActorKind,
    Guid? ActorId,
    AuditTargetKind? TargetKind,
    Guid? TargetId);

/// <summary>A page of events, newest first, and the last one's ID when an older page follows.</summary>
public sealed record TenantLogPage(IReadOnlyList<TenantLogEntry> Events, Guid? NextAfter);

/// <summary>
/// Reads a Tenant's Log, in the caller's Tenant scope, so row-level security limits it to that
/// Tenant (AD-4). It only reads, and reads no detail column but <c>email</c>, and that only to
/// resolve a User.
/// </summary>
public interface ITenantLogSearch
{
    /// <exception cref="InvalidOperationException"><paramref name="context"/> isn't in a Tenant scope.</exception>
    /// <exception cref="ArgumentException">The query is out of range.</exception>
    Task<TenantLogPage> SearchAsync(CommandContext context, TenantLogQuery query, CancellationToken cancellationToken);
}
