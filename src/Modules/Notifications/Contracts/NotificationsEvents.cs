using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Notifications.Contracts;

/// <summary>
/// The audit events Notifications writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break. None holds a provider
/// setting, an address, a secret or a ciphertext.
/// </summary>
public static class NotificationsEvents
{
    /// <summary>
    /// Written on the Tenant's own chain, with the Tenant Owner as Actor and the Tenant as target, in the
    /// transaction that saves a changed email provider (Story 4.4). A save that changes nothing writes none.
    /// </summary>
    public static readonly AuditEventDefinition EmailProviderUpdated = new(
        new AuditTypeCode("notifications.email_provider.updated"),
        "A Tenant Owner saved the Tenant's email provider. Records no setting, address or secret.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Tenant's own chain, with the Tenant Owner as Actor and the Tenant as target, in the
    /// transaction that removes the Tenant's email provider (Story 4.4). Removing none writes none.
    /// </summary>
    public static readonly AuditEventDefinition EmailProviderRemoved = new(
        new AuditTypeCode("notifications.email_provider.removed"),
        "A Tenant Owner removed the Tenant's email provider and its stored secret.",
        AuditOutcome.Success);
}
