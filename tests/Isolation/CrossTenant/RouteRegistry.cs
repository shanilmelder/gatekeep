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
        new("GET", "/api/v1/deployment/logs", CaseKind.NotTenantBound, Reason: "Deployment Owner only (deployment.log.read); reads the Deployment Log, names no path Tenant"),
        new("GET", "/api/v1/deployment/logs/{eventId}", CaseKind.NotTenantBound, Reason: "Deployment Owner only (deployment.log.read); names a Deployment Log event, not a Tenant"),

        // Deployment Owner only, naming a target Tenant.
        new("POST", "/api/v1/deployment/tenants/{targetTenantId}/deletion", CaseKind.TargetTenant, Body: """{"confirmation":"cross-tenant.gatekeep.test"}"""),
        new("GET", "/api/v1/deployment/tenants/{targetTenantId}/deletion", CaseKind.TargetTenant),
        new("POST", "/api/v1/deployment/tenants/{targetTenantId}/deletion/retry", CaseKind.TargetTenant),

        // The Tenant surface.
        new("GET", "/api/v1/tenants/{tenantId}/capabilities", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/operations/{operationId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["operationId"] = "opr_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("GET", "/api/v1/tenants/{tenantId}/label", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/logs", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/logs/{eventId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["eventId"] = "evt_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("GET", "/api/v1/tenants/{tenantId}/signing-keys", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/signing-keys/jwks", CaseKind.TenantPath),
        new("POST", "/api/v1/tenants/{tenantId}/signing-keys/rotate", CaseKind.TenantPath),
        new("POST", "/api/v1/tenants/{tenantId}/signing-keys/{keyId}/revoke", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["keyId"] = "sig-0190a000-0000-7000-8000-00000000000a-0190a000-0000-7000-8000-0000000000b1.v1" }, Body: """{"revokeAccess":false}"""),
        new("GET", "/api/v1/tenants/{tenantId}/email-provider", CaseKind.TenantPath),
        new("PUT", "/api/v1/tenants/{tenantId}/email-provider", CaseKind.TenantPath, Body: """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"no-reply@cross-tenant.example","secret":"cnry-cross-tenant"}"""),
        new("DELETE", "/api/v1/tenants/{tenantId}/email-provider", CaseKind.TenantPath),
        new("GET", "/api/v1/tenants/{tenantId}/connections/database", CaseKind.TenantPath),
        new("PUT", "/api/v1/tenants/{tenantId}/connections/database/settings", CaseKind.TenantPath, Body: """{"signupEnabled":false}"""),
        new("PUT", "/api/v1/tenants/{tenantId}/connections/database/password-policy", CaseKind.TenantPath, Body: """{"minLength":16,"strength":"excellent","historyCount":3,"dictionary":true,"personalData":true}"""),
        new("GET", "/api/v1/tenants/{tenantId}/settings", CaseKind.TenantPath),
        new("PUT", "/api/v1/tenants/{tenantId}/settings", CaseKind.TenantPath, Body: """{"termsUrl":"https://cross-tenant.example/terms","emailVerificationOff":false,"defaultAudience":null}"""),
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
        new("GET", "/api/v1/tenants/{tenantId}/apis", CaseKind.TenantPath),
        new("POST", "/api/v1/tenants/{tenantId}/apis", CaseKind.TenantPath, Body: """{"name":"Cross-Tenant","identifier":"https://cross-tenant.example"}"""),
        new("GET", "/api/v1/tenants/{tenantId}/apis/{apiId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["apiId"] = "api_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
        new("PUT", "/api/v1/tenants/{tenantId}/apis/{apiId}/settings", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["apiId"] = "api_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, Body: """{"offlineAccess":true,"rbac":true,"accessTokenLifetime":300,"idTokenLifetime":300,"refreshTokenAbsoluteLifetime":86400,"refreshTokenInactivityLifetime":3600}"""),
        new("POST", "/api/v1/tenants/{tenantId}/apis/{apiId}/permissions", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["apiId"] = "api_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, Body: """{"value":"cross:tenant","description":""}"""),
        new("DELETE", "/api/v1/tenants/{tenantId}/apis/{apiId}/permissions/{value}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["apiId"] = "api_aaaaaaaaaaaaaaaaaaaaaaaaaa", ["value"] = "cross:tenant" }),
        new("PUT", "/api/v1/tenants/{tenantId}/apis/{apiId}/grants/{applicationId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["apiId"] = "api_aaaaaaaaaaaaaaaaaaaaaaaaaa", ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, Body: """{"permissions":["cross:tenant"]}"""),
        new("DELETE", "/api/v1/tenants/{tenantId}/apis/{apiId}/grants/{applicationId}", CaseKind.TenantPath, RouteValues: new Dictionary<string, string> { ["apiId"] = "api_aaaaaaaaaaaaaaaaaaaaaaaaaa", ["applicationId"] = "app_aaaaaaaaaaaaaaaaaaaaaaaaaa" }),
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

        // Hosted Login (Story 4.1): the resolved Tenant's theme stylesheet. Its assets are static files, not routes.
        new("GET", "/login/theme/{hash}.css", CaseKind.HostResolved),

        // Hosted Login's sign-in surface (Story 4.2): the step page and its two API requests, each on the
        // resolved Tenant's sign-in transaction only.
        new("GET", "/login", CaseKind.HostResolved),
        new("POST", "/login/api/identifier", CaseKind.HostResolved),
        new("POST", "/login/api/transaction/extend", CaseKind.HostResolved),

        // Story 4.7: sign-up and email verification, each on the resolved Tenant's sign-in transaction, or, for the
        // verification link's page and its "Send a new link", on a link whose Tenant prefix is checked before any lookup.
        new("POST", "/login/api/signup/open", CaseKind.HostResolved),
        new("POST", "/login/api/signup/back", CaseKind.HostResolved),
        new("POST", "/login/api/signup", CaseKind.HostResolved),
        new("POST", "/login/api/verification/resend", CaseKind.HostResolved),
        new("POST", "/login/api/verification/continue", CaseKind.HostResolved),
        new("GET", "/login/verify-email", CaseKind.HostResolved),
        new("POST", "/login/api/verification/new-link", CaseKind.HostResolved),

        // Story 4.9: the Password step's Log in and Edit, each on the resolved Tenant's sign-in transaction.
        new("POST", "/login/api/password", CaseKind.HostResolved),
        new("POST", "/login/api/password/back", CaseKind.HostResolved),

        // Story 4.11: password reset, Forgot password and its confirmation on the resolved Tenant's sign-in transaction,
        // and the reset link's page, Reset password and "Send a new link" on a link whose Tenant prefix is checked before
        // any lookup.
        new("POST", "/login/api/reset/open", CaseKind.HostResolved),
        new("POST", "/login/api/reset", CaseKind.HostResolved),
        new("POST", "/login/api/reset/back", CaseKind.HostResolved),
        new("GET", "/login/reset-password", CaseKind.HostResolved),
        new("POST", "/login/api/reset/complete", CaseKind.HostResolved),
        new("POST", "/login/api/reset/new-link", CaseKind.HostResolved),

        new("*", "{*path:nonfile}", CaseKind.NotTenantBound, Reason: "the one fixed 404, the same as an unknown host's (AD-6)"),
    ];
}
