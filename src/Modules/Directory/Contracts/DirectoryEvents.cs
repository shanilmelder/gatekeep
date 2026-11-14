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
    /// Written when an Editor, Owner or machine client deletes an Application (Story 3.5, FR-11), with the
    /// <c>sessions.access.revoked</c> of its refresh tokens and grants. The target is the Application.
    /// </summary>
    public static readonly AuditEventDefinition ApplicationDeleted = new(
        new AuditTypeCode("directory.application.deleted"),
        "An Application was deleted: hidden at once, its secrets, refresh tokens and grants revoked. Access tokens it holds stay valid until they expire. Names the Application only.",
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

    /// <summary>Written when an Editor, Owner or machine client creates an API (Story 3.6, FR-16). The target is the API.</summary>
    public static readonly AuditEventDefinition ApiCreated = new(
        new AuditTypeCode("directory.api.created"),
        "An API was created with its identifier, which can't be changed. Names the API only.",
        AuditOutcome.Success);

    /// <summary>Written when an API's offline access, RBAC or token lifetimes change (Story 3.6). The target is the API.</summary>
    public static readonly AuditEventDefinition ApiUpdated = new(
        new AuditTypeCode("directory.api.updated"),
        "An API's offline access, RBAC or token lifetimes were changed. Names the API only. A save that changes nothing writes no event.",
        AuditOutcome.Success);

    /// <summary>Written when a Permission is added to an API (Story 3.6). The target is the API.</summary>
    public static readonly AuditEventDefinition ApiPermissionAdded = new(
        new AuditTypeCode("directory.api.permission_added"),
        "A Permission was added to an API. Names the API only.",
        AuditOutcome.Success);

    /// <summary>Written when a Permission is removed from an API (Story 3.6). The target is the API.</summary>
    public static readonly AuditEventDefinition ApiPermissionRemoved = new(
        new AuditTypeCode("directory.api.permission_removed"),
        "A Permission was removed from an API. Names the API only.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when an Editor, Owner or machine client changes the Permissions of an API granted to a machine-to-machine
    /// Application (Story 3.7, FR-16). A save that changes nothing writes no event. The target is the API.
    /// </summary>
    public static readonly AuditEventDefinition ApiGrantUpdated = new(
        new AuditTypeCode("directory.api.grant_updated"),
        "The Permissions of an API granted to a machine-to-machine Application were changed. The next token it gets carries only those. Names the API only. A save that changes nothing writes no event.",
        AuditOutcome.Success);

    /// <summary>Written when a machine-to-machine Application's grant on an API is removed (Story 3.7). The target is the API.</summary>
    public static readonly AuditEventDefinition ApiGrantRemoved = new(
        new AuditTypeCode("directory.api.grant_removed"),
        "A machine-to-machine Application's authorization on an API was removed: its next token for the API carries no Permission. Names the API only. Removing a grant that doesn't exist writes no event.",
        AuditOutcome.Success);
}
