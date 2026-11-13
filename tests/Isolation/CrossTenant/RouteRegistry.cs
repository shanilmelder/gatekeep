namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>The one cross-Tenant case a route's registry entry runs (Story 1.31, FR-8, AD-25).</summary>
public enum CaseKind
{
    /// <summary>
    /// The route names <c>{tenantId}</c>. An Admin holding Owner in Tenant A only calls it with Tenant
    /// B in the path and in <c>X-Gatekeep-Tenant</c>: 403 <c>access_denied</c> and exactly one
    /// <c>admin.access.denied</c> on the Deployment chain, targeting B.
    /// </summary>
    TenantPath,

    /// <summary>
    /// A Deployment route naming <c>{targetTenantId}</c>. The same A-only Owner, who isn't the
    /// Deployment Owner, targets B: 403 <c>access_denied</c> and exactly one <c>admin.access.denied</c>.
    /// </summary>
    TargetTenant,

    /// <summary>
    /// A Host.Hosted route. Requested on Tenant B's host, the response carries only B's issuer and
    /// keys, never A's; the token endpoint refuses the request.
    /// </summary>
    HostResolved,

    /// <summary>A pre-auth, self-service or fixed route with no Tenant in its path, with the reason.</summary>
    NotTenantBound,
}

/// <summary>
/// One live route and its cross-Tenant case. <paramref name="Method"/> is upper case, or <c>*</c>
/// for a route that answers any method; <paramref name="Pattern"/> is the route as mapped.
/// <paramref name="Body"/> is the JSON a state-changing case sends, and
/// <paramref name="RouteValues"/> fills the pattern's other parameters.
/// </summary>
public sealed record RouteCase(
    string Method,
    string Pattern,
    CaseKind Kind,
    string? Reason = null,
    string? Body = null,
    IReadOnlyDictionary<string, string>? RouteValues = null)
{
    public override string ToString() => $"{Method} {Pattern}";
}

/// <summary>
/// Story 1.31 (FR-8, AD-25, SM-2): every live route of Host.Admin and Host.Hosted, each with its
/// one cross-Tenant case. <see cref="RouteRegistryTests"/> compares these with the routes the
/// running hosts serve, so a new route fails the build until it is listed here, and a listed route
/// the host no longer maps fails too. Every <see cref="CaseKind.TenantPath"/> and
/// <see cref="CaseKind.TargetTenant"/> entry runs in <see cref="CrossTenantRouteTests"/> with no new
/// test code.
/// </summary>
public static class RouteRegistry
{
    private const string SelfService = "self-service: acts only on the caller's own Session, credentials or list; no Tenant in the path";

    public static readonly IReadOnlyList<RouteCase> Admin =
    [
        // Pre-auth.
        new("POST", "/api/v1/deployment/bootstrap", CaseKind.NotTenantBound, Reason: "pre-auth bootstrap claim, before any Tenant exists"),
        new("POST", "/api/v1/deployment/signin", CaseKind.NotTenantBound, Reason: "pre-auth Admin sign-in; Admins are Deployment-scoped"),
        new("POST", "/api/v1/deployment/signin/complete", CaseKind.NotTenantBound, Reason: "pre-auth Admin sign-in; Admins are Deployment-scoped"),
        new("POST", "/api/v1/deployment/signin/recovery-code", CaseKind.NotTenantBound, Reason: "pre-auth Admin Recovery Code sign-in; Admins are Deployment-scoped"),
        new("POST", "/api/v1/deployment/signin/enrolment", CaseKind.NotTenantBound, Reason: "pre-auth recover-admin enrolment sign-in; Admins are Deployment-scoped"),

        // Self-service.
        new("GET", "/api/v1/deployment/session", CaseKind.NotTenantBound, Reason: SelfService),
        new("DELETE", "/api/v1/deployment/session", CaseKind.NotTenantBound, Reason: SelfService),
        new("POST", "/api/v1/deployment/credentials/registration", CaseKind.NotTenantBound, Reason: SelfService),
        new("POST", "/api/v1/deployment/credentials/registration/complete", CaseKind.NotTenantBound, Reason: SelfService),
        new("GET", "/api/v1/deployment/credentials", CaseKind.NotTenantBound, Reason: SelfService),
        new("DELETE", "/api/v1/deployment/credentials/{credentialId}", CaseKind.NotTenantBound, Reason: SelfService),
        new("POST", "/api/v1/deployment/credentials/recovery-code", CaseKind.NotTenantBound, Reason: SelfService),
        new("POST", "/api/v1/deployment/credentials/recovery-code/confirm", CaseKind.NotTenantBound, Reason: SelfService),
        new("GET", "/api/v1/deployment/capabilities", CaseKind.NotTenantBound, Reason: SelfService),
        new("GET", "/api/v1/deployment/my-tenants", CaseKind.NotTenantBound, Reason: "self-service: lists only the caller's own Tenant Roles"),
        new("POST", "/api/v1/deployment/assertions", CaseKind.NotTenantBound, Reason: "self-service: a grant binds to this Session, and the action's own route decides its Tenant"),
        new("POST", "/api/v1/deployment/assertions/complete", CaseKind.NotTenantBound, Reason: SelfService),

        // Deployment Owner only, naming no existing Tenant.
        new("GET", "/api/v1/deployment/tenants", CaseKind.NotTenantBound, Reason: "Deployment Owner only (deployment.tenants.read); lists the Deployment, names no Tenant"),
        new("POST", "/api/v1/deployment/tenants", CaseKind.NotTenantBound, Reason: "Deployment Owner only (deployment.tenants.create); creates a new Tenant, names no existing one"),
        new("POST", "/api/v1/deployment/operations/{operationId}/retry", CaseKind.NotTenantBound, Reason: "Deployment Owner only (deployment.tenants.create); names an Operation, not a Tenant"),

        // Deployment Owner only, naming a target Tenant.
        new("POST", "/api/v1/deployment/tenants/{targetTenantId}/deletion", CaseKind.TargetTenant, Body: """{"confirmation":"cross-tenant.gatekeep.test"}"""),
        new("GET", "/api/v1/deployment/tenants/{targetTenantId}/deletion", CaseKind.TargetTenant),
        new("POST", "/api/v1/deployment/tenants/{targetTenantId}/deletion/retry", CaseKind.TargetTenant),

        // The Tenant surface.
        new("GET", "/api/v1/tenants/{tenantId}/capabilities", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/operations/{operationId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["operationId"] = "opr_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("GET", "/api/v1/tenants/{tenantId}/label", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/logs", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/signing-keys", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/signing-keys/jwks", CaseKind.TenantPath),
        new("POST", "/api/v1/tenants/{tenantId}/signing-keys/rotate", CaseKind.TenantPath),
        new("POST", "/api/v1/tenants/{tenantId}/signing-keys/{keyId}/revoke", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["keyId"] = "sig-0190a000-0000-7000-8000-00000000000a-0190a000-0000-7000-8000-0000000000b1.v1" }, Body: """{"revokeAccess":false}"""),
        new("GET", "/api/v1/tenants/{tenantId}/applications", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/applications/{applicationId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("PUT", "/api/v1/tenants/{tenantId}/label", CaseKind.TenantPath, Body: """{"label":"staging"}"""),
        new("POST", "/api/v1/tenants/{tenantId}/applications", CaseKind.TenantPath, Body: """{"name":"Cross-Tenant","type":"spa"}"""),
        new("PUT", "/api/v1/tenants/{tenantId}/applications/{applicationId}/settings", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, Body: """{"callbackUrls":["https://cross-tenant.example/cb"],"logoutUrls":[],"webOrigins":[],"grantTypes":["authorization_code"]}"""),
        new("DELETE", "/api/v1/tenants/{tenantId}/applications/{applicationId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("PUT", "/api/v1/tenants/{tenantId}/applications/{applicationId}/tokens", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, Body: """{"accessTokenLifetime":300,"idTokenLifetime":300,"refreshTokenAbsoluteLifetime":86400,"refreshTokenInactivityLifetime":3600}"""),
        new("GET", "/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("POST", "/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("POST", "/api/v1/tenants/{tenantId}/applications/{applicationId}/secrets/{secretId}/revoke", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa", ["secretId"] = "sec_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("POST", "/api/v1/tenants/{tenantId}/assertions", CaseKind.TenantPath, Body: """{"action":"tenant.label.manage","target":null}"""),

        // Program.cs's fallbacks.
        new("*", "/api/{**path}", CaseKind.NotTenantBound, Reason: "the fixed unknown-path 404, whatever the path"),
        new("GET", "{*path:nonfile}", CaseKind.NotTenantBound, Reason: "the static Admin Dashboard bundle, the same for every caller"),
        new("HEAD", "{*path:nonfile}", CaseKind.NotTenantBound, Reason: "the static Admin Dashboard bundle, the same for every caller"),
    ];

    public static readonly IReadOnlyList<RouteCase> Hosted =
    [
        // OpenIddict's endpoints, which are middleware rather than endpoints (AD-8).
        new("*", "/.well-known/openid-configuration", CaseKind.HostResolved),
        new("*", "/.well-known/jwks", CaseKind.HostResolved),
        new("*", "/connect/token", CaseKind.HostResolved),
        new("*", "/connect/authorize", CaseKind.HostResolved),
        new("*", "/connect/userinfo", CaseKind.HostResolved),
        new("*", "/connect/revoke", CaseKind.HostResolved),

        new("*", "{*path:nonfile}", CaseKind.NotTenantBound, Reason: "the one fixed 404, the same as an unknown host's (AD-6)"),
    ];
}
