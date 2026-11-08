using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// The audit events Protocol writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class ProtocolEvents
{
    /// <summary>
    /// Written to the probed Tenant's Log when a client credential of another Tenant is refused at its
    /// token endpoint (AD-9, SM-2): every authenticated attempt, and an unauthenticated one at most once
    /// per source per hour. Anonymous, with no target, and naming nothing of the other Tenant.
    /// </summary>
    public static readonly AuditEventDefinition ClientCrossTenantRejected = new(
        new AuditTypeCode("protocol.client.cross_tenant_rejected"),
        "A client credential issued by another Tenant was refused at this Tenant's token endpoint. Names nothing of the other Tenant.",
        TenantLogClass.CrossTenantRejection);
}
