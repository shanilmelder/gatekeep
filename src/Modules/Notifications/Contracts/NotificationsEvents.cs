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

    /// <summary>
    /// Written on the Tenant's own chain, with actor System and the User as target, when Host.Worker's send job hands an
    /// email to the Tenant's provider and the provider accepts it (Story 4.5).
    /// </summary>
    public static readonly AuditEventDefinition EmailSent = new(
        new AuditTypeCode("notifications.email.sent"),
        "An email to a User was accepted by the Tenant's provider. Records no address, link or code.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Tenant's own chain, with actor System and the User as target, when a send job ends without sending
    /// (Story 4.5): no provider, no User or no email address, a template or credential the job may not use, or the provider
    /// refused the message for good. The job completes, with no retry.
    /// </summary>
    public static readonly AuditEventDefinition EmailUndeliverable = new(
        new AuditTypeCode("notifications.email.undeliverable"),
        "An email to a User couldn't be delivered and won't be retried. Records no address, link or code.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the Tenant's own chain, with actor System and the User as target, when a send job would pass the User's
    /// per-recipient limit (Story 4.5): the email is dropped, never delayed.
    /// </summary>
    public static readonly AuditEventDefinition EmailHeldBack = new(
        new AuditTypeCode("notifications.email.held_back"),
        "An email to a User was dropped: the User's per-recipient email limit was reached. Records no address, link or code.",
        AuditOutcome.Failure);
}
