using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>An event's seal (AD-16): its place in the chain and its hashes. <paramref name="PrevHash"/> is null for a chain's first event.</summary>
public sealed record TenantLogSeal(long Seq, byte[]? PrevHash, byte[] Hash);

/// <summary>An event's detail row: the personal data kept outside the hash, each value nullable.</summary>
public sealed record TenantLogDetail(string? IpAddress, string? UserAgent, string? Email);

/// <summary>
/// One event of a Tenant's Log, opened (Story 7.5): its envelope, its seal (null while unsealed)
/// and, only when asked for, its detail (null when it has no detail row, or when not asked for).
/// </summary>
public sealed record TenantLogEvent(TenantLogEntry Entry, TenantLogSeal? Seal, TenantLogDetail? Detail);

/// <summary>
/// Opens one event of a Tenant's Log, in the caller's Tenant scope, so row-level security limits
/// it to that Tenant (AD-4): another Tenant's event is found exactly as an unknown one is, not at
/// all. It only reads, and reads <c>audit_detail</c> only when the caller asks for detail.
/// </summary>
public interface ITenantLogEventReader
{
    /// <summary>The event, or null when this Tenant has none with <paramref name="eventId"/>.</summary>
    /// <exception cref="InvalidOperationException"><paramref name="context"/> isn't in a Tenant scope.</exception>
    Task<TenantLogEvent?> FindAsync(CommandContext context, Guid eventId, bool includeDetail, CancellationToken cancellationToken);
}
