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
}
