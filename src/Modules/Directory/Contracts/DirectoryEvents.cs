using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// The audit events Directory writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class DirectoryEvents
{
    /// <summary>Written when an Application is created, by an Admin or the System. The target is the Application.</summary>
    public static readonly AuditEventDefinition ApplicationCreated = new(
        new AuditTypeCode("directory.application.created"),
        "An Application was created. Names the Application only: no client secret is created with it, and any secret is stored only as its hash.",
        AuditOutcome.Success);

    /// <summary>Written when an Admin changes an Application's URLs or grants (Story 3.2). The target is the Application.</summary>
    public static readonly AuditEventDefinition ApplicationUpdated = new(
        new AuditTypeCode("directory.application.updated"),
        "An Application's callback, logout or web origin URLs or its grant types were changed. Names the Application only, never a URL. A save that changes nothing writes no event.",
        AuditOutcome.Success);

    /// <summary>
    /// Written with <see cref="ApplicationUpdated"/> when a Prod Tenant's Application gains a callback URL
    /// (Story 3.2, FR-46). Story 11.1 raises the "Prod callback added" Security Alert from it. The target is the Application.
    /// </summary>
    public static readonly AuditEventDefinition ApplicationProdCallbackAdded = new(
        new AuditTypeCode("directory.application.prod_callback_added"),
        "A callback URL was added to an Application in a Prod Tenant, after a fresh assertion. Names the Application only, never the URL.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a Tenant Owner creates an Application's client secret while it holds no current one
    /// (Story 3.3, FR-12). The target is the Application.
    /// </summary>
    public static readonly AuditEventDefinition ClientSecretCreated = new(
        new AuditTypeCode("directory.client_secret.created"),
        "A client secret was created for an Application. Names the Application only: the secret is shown once to its creator and stored only as its hash.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a Tenant Owner rotates an Application's client secret (Story 3.3, FR-12): a new secret is
    /// created and the current one keeps working for the fixed overlap. The target is the Application.
    /// </summary>
    public static readonly AuditEventDefinition ClientSecretRotated = new(
        new AuditTypeCode("directory.client_secret.rotated"),
        "An Application's client secret was rotated: a new secret was created, and the old one stays valid for 24 hours unless ended sooner. Names the Application only, never a secret.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a Tenant Owner revokes one of an Application's live client secrets, or ends a rotated-out
    /// secret's overlap now (Story 3.3, FR-12). It stops working at once. The target is the Application.
    /// </summary>
    public static readonly AuditEventDefinition ClientSecretRevoked = new(
        new AuditTypeCode("directory.client_secret.revoked"),
        "One of an Application's client secrets was revoked, or a rotated-out secret was ended early: it is refused at once. Names the Application only, never a secret.",
        AuditOutcome.Success);
}
