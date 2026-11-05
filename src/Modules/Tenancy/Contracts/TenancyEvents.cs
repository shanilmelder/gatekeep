using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>
/// The audit events Tenancy's flows write. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break. None holds a
/// Tenant's name, subdomain or host.
/// </summary>
public static class TenancyEvents
{
    /// <summary>
    /// Written on the Deployment chain by Tenant creation (Story 1.27), in the transaction that
    /// inserts the Tenant, its host, its creator's Owner role and its creation Operation. The Actor
    /// is the Admin; the target the Tenant.
    /// </summary>
    public static readonly AuditEventDefinition TenantCreated = new(
        new AuditTypeCode("tenancy.tenant.created"),
        "A Deployment Owner created a Tenant and became its Tenant Owner, and its creation Operation started. Names the Tenant only.");

    /// <summary>
    /// Written on the new Tenant's own chain, with a <c>system</c> Actor, in the transaction that
    /// marks its creation Operation succeeded, inserts its settings and makes it active.
    /// </summary>
    public static readonly AuditEventDefinition TenantActivated = new(
        new AuditTypeCode("tenancy.tenant.activated"),
        "A Tenant's creation Operation succeeded: its settings exist and its Tenant Subdomain now resolves.");

    /// <summary>
    /// Written on the Tenant's own chain by a label change other than removing Prod (Story 1.28),
    /// in the transaction that writes the label. The Actor is the Admin; the target the Tenant.
    /// </summary>
    public static readonly AuditEventDefinition LabelChanged = new(
        new AuditTypeCode("tenancy.tenant.label_changed"),
        "A Tenant Owner changed a Tenant's environment label, other than removing Prod. Names the Tenant only.");

    /// <summary>
    /// Written on the Tenant's own chain when a Tenant Owner removes its Prod label (Story 1.28),
    /// after a fresh WebAuthn assertion, in the transaction that writes the label. The Actor is the
    /// Admin; the target the Tenant.
    /// </summary>
    public static readonly AuditEventDefinition ProdLabelRemoved = new(
        new AuditTypeCode("tenancy.tenant.prod_label_removed"),
        "A Tenant Owner removed a Tenant's Prod label after a fresh WebAuthn assertion. No setting changed with it.");
}
