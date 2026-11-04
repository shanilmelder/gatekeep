using System.Data.Common;
using System.Net;
using System.Net.Sockets;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>Marks an endpoint under <c>/api/v1/deployment</c>, so the request checks apply to it.</summary>
internal sealed class DeploymentApiEndpoint
{
    public static readonly DeploymentApiEndpoint Instance = new();
}

/// <summary>
/// Marks an endpoint under <c>/api/v1/tenants/{tenantId}</c> (Story 1.24, AD-19), so the request
/// checks apply to it and take its Tenant from that path segment only. It declares a Tenant capability.
/// </summary>
internal sealed class TenantApiEndpoint
{
    public static readonly TenantApiEndpoint Instance = new();
}

/// <summary>
/// An access declaration (Story 1.24): the endpoint needs <see cref="Capability"/>, decided by
/// the authorizer from <see cref="AdminCapabilities"/> after the Session checks. A refusal is 403
/// <c>access_denied</c>, audited.
/// </summary>
internal sealed class RequiresCapability(Capability capability)
{
    public Capability Capability { get; } = capability ?? throw new ArgumentNullException(nameof(capability));
}

/// <summary>
/// An access declaration (Story 1.24): any Admin with a live Session, acting only on their own
/// Session, credentials or capability list. On the reviewed list only: no capability is checked.
/// </summary>
internal sealed class SelfService
{
    public static readonly SelfService Instance = new();
}

/// <summary>The kinds of access an API endpoint declares: exactly one each.</summary>
internal enum AccessKind
{
    Capability,
    Self,
    Sessionless,
}

/// <summary>An endpoint's one valid access declaration, and whether it is on the Tenant surface.</summary>
internal sealed record AccessDeclaration(AccessKind Kind, Capability? Capability, bool Tenant)
{
    /// <summary>
    /// The declaration <paramref name="metadata"/> makes, or null when it isn't exactly one API
    /// marker and exactly one access declaration, or the two disagree: a Tenant endpoint declares
    /// a Tenant capability and nothing else, a Deployment capability is declared on a Deployment
    /// endpoint only, and no setup-allowed endpoint declares a capability, as a restricted Session
    /// holds none. The <c>{tenantId}</c> route value belongs to the Tenant surface alone: a Tenant
    /// endpoint's <paramref name="routePattern"/> has it, and no other endpoint's may, so no
    /// Deployment or self-service handler ever sees a Tenant it might act on. Null is denied at
    /// runtime and refused by the OpenAPI build.
    /// </summary>
    public static AccessDeclaration? Of(IEnumerable<object> metadata, string? routePattern)
    {
        var items = metadata.ToList();
        var namesTenant = routePattern is not null
            && routePattern.Contains("{" + AdminRequestChecks.TenantRouteValue, StringComparison.OrdinalIgnoreCase);
        if (items.Any(m => m is TenantApiEndpoint) != namesTenant)
        {
            return null;
        }

        var deployment = items.Count(m => m is DeploymentApiEndpoint);
        var tenant = items.Count(m => m is TenantApiEndpoint);
        var capabilities = items.OfType<RequiresCapability>().ToList();
        var self = items.Count(m => m is SelfService);
        var sessionless = items.Count(m => m is BootstrapClaimEndpoint or SignInEndpoint);

        if (deployment + tenant != 1 || capabilities.Count + self + sessionless != 1)
        {
            return null;
        }

        var onTenant = tenant == 1;
        if (capabilities.Count == 1)
        {
            var capability = capabilities[0].Capability;
            var scope = onTenant ? CapabilityScope.Tenant : CapabilityScope.Deployment;
            return capability.Scope != scope || items.Any(m => m is SetupAllowed)
                ? null
                : new AccessDeclaration(AccessKind.Capability, capability, onTenant);
        }

        return onTenant ? null : new AccessDeclaration(self == 1 ? AccessKind.Self : AccessKind.Sessionless, null, false);
    }

    /// <summary>Whether <paramref name="metadata"/> holds any API marker or access declaration, valid or not.</summary>
    public static bool AnyApiMetadata(IEnumerable<object> metadata) =>
        metadata.Any(m => m is DeploymentApiEndpoint or TenantApiEndpoint or RequiresCapability or SelfService or BootstrapClaimEndpoint or SignInEndpoint);
}

/// <summary>
/// The path Tenant the request checks parsed and authorized, for the endpoint (AD-4, AD-19), with
/// the Tenant Role grant they read in their own transaction to decide. The endpoint answers from
/// this grant and never reads the role again, so a role changed between the check and the
/// handler can't give an allowed request a different answer.
/// </summary>
internal sealed record PathTenantFeature(Guid TenantId, TenantRoleGrant? Grant);

/// <summary>
/// Marks an endpoint a setup Admin Session, or an Admin without their two credentials, may call.
/// Every other one refuses them with 403.
/// </summary>
internal sealed class SetupAllowed
{
    public static readonly SetupAllowed Instance = new();
}

/// <summary>
/// The JSON body an endpoint takes, for the OpenAPI document only. The endpoint reads the body
/// itself, so a body of another type reaches it, to be refused and counted, rather than being
/// turned away by routing.
/// </summary>
internal sealed class JsonRequestBody(Type type)
{
    public Type Type { get; } = type;
}

/// <summary>
/// Marks the bootstrap claim: it has no session, so it is exempt from the session and CSRF
/// checks, but it still needs the exact Origin. Once bootstrap is closed it is the unknown-path 404.
/// </summary>
internal sealed class BootstrapClaimEndpoint
{
    public static readonly BootstrapClaimEndpoint Instance = new();
}

/// <summary>
/// Marks Admin sign-in's begin and complete (Story 1.23): there is no session yet, so they are
/// exempt from the session and CSRF checks, but they still need the exact Origin. Until bootstrap
/// is complete there is no Admin to sign in, and they are the unknown-path 404.
/// </summary>
internal sealed class SignInEndpoint
{
    public static readonly SignInEndpoint Instance = new();
}

/// <summary>
/// The one server-side gate in front of every <c>/api/</c> endpoint (NFR-5), denying by default,
/// in order: an endpoint under <c>/api/</c> without exactly one API marker and exactly one valid
/// <see cref="AccessDeclaration"/> is the unknown-path 404, so a route mapped there by mistake,
/// the fallback included, is never reached unchecked; a state-changing request needs an
/// <c>Origin</c> exactly equal to the Admin origin (403); then a live Admin Session from the
/// <c>__Host-gk-admin</c> cookie (401, clearing a stale cookie, and an expired Session is ended),
/// whose idle expiry slides; a state-changing request's <c>X-Gatekeep-CSRF</c> must be the
/// Session's (403); a setup Session, or any Session of an Admin with fewer than two WebAuthn
/// credentials, reaches only setup-allowed endpoints (403); and a capability endpoint's
/// capability must be allowed by the authorizer, for a Tenant endpoint in the Tenant its
/// <c>{tenantId}</c> path segment names and no other (403 <c>access_denied</c>, audited).
/// </summary>
internal static class AdminRequestChecks
{
    /// <summary>Everything under it is checked or is the unknown-path 404.</summary>
    public const string ApiPrefix = "/api";

    public const string Prefix = "/api/v1/deployment";

    /// <summary>The route value that names the path Tenant on <c>/api/v1/tenants/{tenantId}</c> (AD-19), and nothing else does.</summary>
    public const string TenantRouteValue = "tenantId";

    public const string SessionCookie = "__Host-gk-admin";

    /// <summary>The cookie binding a pending sign-in's challenge to the browser that began it (Story 1.23).</summary>
    public const string SignInCookie = "__Host-gk-admin-signin";

    public const string CsrfHeader = "X-Gatekeep-CSRF";

    public static IApplicationBuilder UseAdminRequestChecks(this IApplicationBuilder app) =>
        app.Use(static (context, next) => CheckAsync(context, next));

    /// <summary>
    /// The Bootstrap page's document request, before the bundle: the unknown-path 404 unless there
    /// is a bootstrap to claim. The page itself is gone, not just its API. Only the page's own
    /// path matches, exactly; any other path is the bundle's.
    /// </summary>
    public static IApplicationBuilder UseBootstrapPage(this IApplicationBuilder app) =>
        app.Use(static async (context, next) =>
        {
            if (!(HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method))
                || !IsBootstrapPath(context.Request.Path))
            {
                await next(context);
                return;
            }

            var services = context.RequestServices.GetRequiredService<AdminApiServices>();
            bool open;
            try
            {
                open = await services.IsBootstrapOpenAsync(context.RequestAborted);
            }
            catch (DbException e)
            {
                Log(context, e);
                await AdminResponses.UnavailableAsync(context);
                return;
            }

            if (!open)
            {
                await AdminResponses.NotFoundAsync(context);
                return;
            }

            await next(context);
        });

    /// <summary>The authenticated Session the checks found, for the endpoint.</summary>
    /// <summary>Whether <paramref name="path"/> is under <c>/api</c>, in any case: checked, or the unknown-path 404, never a file.</summary>
    public static bool IsApiPath(PathString path) => path.StartsWithSegments(ApiPrefix, StringComparison.OrdinalIgnoreCase);

    public static AdminSession Session(HttpContext context) =>
        context.Features.Get<AdminSession>() ?? throw new InvalidOperationException("No Admin Session passed the checks.");

    /// <summary>
    /// The Tenant the path named and the checks authorized: the only Tenant a Tenant endpoint may
    /// act in, and the only one it may open a Tenant scope with (AD-4, AD-19).
    /// </summary>
    public static Guid PathTenant(HttpContext context) => PathTenantGrant(context).TenantId;

    /// <summary>The path Tenant and the Tenant Role grant the checks read there to allow the request.</summary>
    public static PathTenantFeature PathTenantGrant(HttpContext context) =>
        context.Features.Get<PathTenantFeature>() ?? throw new InvalidOperationException("No path Tenant passed the checks.");

    /// <summary>The principal the checks built from the authenticated Session.</summary>
    public static AdminPrincipal Principal(HttpContext context)
    {
        var session = Session(context);
        return new AdminPrincipal(session.AdminId, session.DeploymentOwner);
    }

    /// <summary>
    /// The client bootstrap claims are counted by, after any forwarding Caddy did: an IPv4
    /// address, or an IPv6 client's /64, which one host can hold all of. Null with no address,
    /// which mustn't share one count with every other such client.
    /// </summary>
    public static string? Client(HttpContext context)
    {
        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4().ToString();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            Array.Clear(bytes, 8, 8);
            return $"{new IPAddress(bytes)}/64";
        }

        return address.ToString();
    }

    private static async Task CheckAsync(HttpContext context, RequestDelegate next)
    {
        var endpoint = context.GetEndpoint();
        var underApi = IsApiPath(context.Request.Path);
        var declaration = endpoint is null ? null : AccessDeclaration.Of(endpoint.Metadata, (endpoint as RouteEndpoint)?.RoutePattern.RawText);
        if (declaration is null)
        {
            if (endpoint is not null && (underApi || AccessDeclaration.AnyApiMetadata(endpoint.Metadata)))
            {
                // Deny by default: whatever answers here undeclared, or declared twice, the
                // unknown-path fallback included, answers exactly as the fallback does.
                await AdminResponses.NotFoundAsync(context);
                return;
            }

            await next(context);
            return;
        }

        try
        {
            if (await PassesAsync(context, endpoint!, declaration))
            {
                await next(context);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            Log(context, e);
            await AdminResponses.UnavailableAsync(context);
        }
    }

    private static async Task<bool> PassesAsync(HttpContext context, Endpoint endpoint, AccessDeclaration declaration)
    {
        var request = context.Request;
        var services = context.RequestServices.GetRequiredService<AdminApiServices>();
        var origin = context.RequestServices.GetRequiredService<HostOrigin>();
        var cancellationToken = context.RequestAborted;

        if (endpoint.Metadata.GetMetadata<BootstrapClaimEndpoint>() is not null)
        {
            // Gone once bootstrap is, whatever the request carries: the unknown-path 404.
            if (!await services.IsBootstrapOpenAsync(cancellationToken))
            {
                await AdminResponses.NotFoundAsync(context);
                return false;
            }

            if (!origin.Matches(SingleValue(request.Headers.Origin)))
            {
                await AdminResponses.ForbiddenAsync(context);
                return false;
            }

            return true;
        }

        if (endpoint.Metadata.GetMetadata<SignInEndpoint>() is not null)
        {
            // Not there before bootstrap, whatever the request carries: the unknown-path 404.
            if (!await services.IsBootstrapCompleteAsync(cancellationToken))
            {
                await AdminResponses.NotFoundAsync(context);
                return false;
            }

            // No session to carry a CSRF token: the exact Origin refuses a cross-site post.
            if (!origin.Matches(SingleValue(request.Headers.Origin)))
            {
                await AdminResponses.ForbiddenAsync(context);
                return false;
            }

            return true;
        }

        var stateChanging = IsStateChanging(request.Method);
        if (stateChanging && !origin.Matches(SingleValue(request.Headers.Origin)))
        {
            await AdminResponses.ForbiddenAsync(context);
            return false;
        }

        if (!request.Cookies.TryGetValue(SessionCookie, out var cookie) || string.IsNullOrEmpty(cookie))
        {
            // The parsed cookies drop an empty value, but a browser sending one still holds it.
            await AdminResponses.UnauthorizedAsync(context, clearCookie: SessionCookieSent(request));
            return false;
        }

        AdminSession? session;
        var refusal = Refusal.None;
        Guid? pathTenant = null;
        TenantRoleGrant? grant = null;
        var audited = false;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            var command = scope.CreateCommandContext();
            session = await services.Sessions.AuthenticateAsync(command, new Secret<string>(cookie), cancellationToken);

            if (session is null)
            {
                refusal = Refusal.Unauthenticated;
            }
            else if (stateChanging && !session.CsrfMatches(SingleValue(request.Headers[CsrfHeader])))
            {
                refusal = Refusal.Forbidden;
            }
            else if (session.Restricted && endpoint.Metadata.GetMetadata<SetupAllowed>() is null)
            {
                // A setup Session, and any Session of an Admin without their two credentials (FR-2, FR-46).
                refusal = Refusal.Forbidden;
            }
            else if (declaration.Kind == AccessKind.Capability)
            {
                // The Tenant comes from the path segment only. A malformed one is no Tenant, so
                // every Tenant capability is denied, exactly as an unknown or role-less one is.
                if (declaration.Tenant
                    && PublicId.TryParse(PublicIdType.Tenant, context.GetRouteValue(TenantRouteValue) as string, out var parsed))
                {
                    pathTenant = parsed;
                }

                var principal = new AdminPrincipal(session.AdminId, session.DeploymentOwner);
                var decision = await services.Authorization.AuthorizeAsync(command, principal, declaration.Capability!, pathTenant, cancellationToken);
                grant = decision.Grant;
                if (!decision.Allowed)
                {
                    refusal = Refusal.AccessDenied;

                    // Counted per Admin, in the transaction that authenticated the Session, with its
                    // slide: within the cap the refusal is audited (AD-9); past it, only logged.
                    var count = await services.Limiter.AttemptAsync(
                        command,
                        AdminsContract.AccessDeniedAuditPolicy,
                        session.AdminId.ToString("N"),
                        cancellationToken);
                    if (count.Allowed)
                    {
                        await services.Authorization.DenyAsync(command, principal, pathTenant, cancellationToken);
                        audited = true;
                    }
                }
            }

            // The slide, or the ending of an expired Session, and any refusal's event, either way.
            await scope.CommitAsync(cancellationToken);
        }

        switch (refusal)
        {
            case Refusal.Unauthenticated:
                await AdminResponses.UnauthorizedAsync(context, clearCookie: true);
                return false;

            case Refusal.Forbidden:
                await AdminResponses.ForbiddenAsync(context);
                return false;

            case Refusal.AccessDenied:
                context.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("Gatekeep.Host.Admin")
                    .LogInformation(
                        "An Admin request was refused with {Problem} for {Capability}, audited {Audited}, trace {TraceId}.",
                        AdminResponses.AccessDenied,
                        declaration.Capability!.Name,
                        audited,
                        AdminResponses.TraceId(context));
                await AdminResponses.AccessDeniedAsync(context);
                return false;
        }

        context.Features.Set(session!);
        if (pathTenant is { } tenant)
        {
            context.Features.Set(new PathTenantFeature(tenant, grant));
        }

        return true;
    }

    private enum Refusal
    {
        None,
        Unauthenticated,
        Forbidden,
        AccessDenied,
    }

    private static bool IsStateChanging(string method) =>
        !(HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method));

    /// <summary>A header sent exactly once, or null.</summary>
    private static string? SingleValue(Microsoft.Extensions.Primitives.StringValues values) =>
        values.Count == 1 ? values[0] : null;

    /// <summary>Whether the <c>Cookie</c> header names the Session cookie, whatever its value.</summary>
    private static bool SessionCookieSent(HttpRequest request)
    {
        foreach (var header in request.Headers.Cookie)
        {
            foreach (var pair in (header ?? string.Empty).Split(';', StringSplitOptions.TrimEntries))
            {
                var name = pair.Split('=', 2)[0].Trim();
                if (name.Equals(SessionCookie, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsBootstrapPath(PathString path) =>
        path.Value is "/bootstrap" or "/bootstrap/";

    /// <summary>The type and SQL state only: a message can quote a value.</summary>
    internal static void Log(HttpContext context, DbException e) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogWarning(
                "The Admin database failed on {ErrorType} {SqlState}, trace {TraceId}.",
                e.GetType().Name,
                e.SqlState,
                AdminResponses.TraceId(context));
}
