using System.Data.Common;
using System.Net;
using System.Net.Sockets;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>Marks an endpoint under <c>/api/v1/deployment</c>, so the request checks apply to it.</summary>
internal sealed class DeploymentApiEndpoint
{
    public static readonly DeploymentApiEndpoint Instance = new();
}

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
/// The one server-side gate in front of every <c>/api/v1/deployment</c> endpoint (NFR-5), in order:
/// an endpoint under the prefix without the <see cref="DeploymentApiEndpoint"/> marker is the
/// unknown-path 404, so a route mapped there by mistake is never reached unchecked; a
/// state-changing request needs an <c>Origin</c> exactly equal to the Admin origin (403); then a
/// live Admin Session from the <c>__Host-gk-admin</c> cookie (401, clearing a stale cookie, and an
/// expired Session is ended), whose idle expiry slides; a state-changing request's
/// <c>X-Gatekeep-CSRF</c> must be the Session's (403); and a setup Session, or any Session of an
/// Admin with fewer than two WebAuthn credentials, reaches only setup-allowed endpoints (403).
/// </summary>
internal static class AdminRequestChecks
{
    public const string Prefix = "/api/v1/deployment";

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
    public static AdminSession Session(HttpContext context) =>
        context.Features.Get<AdminSession>() ?? throw new InvalidOperationException("No Admin Session passed the checks.");

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
        var underPrefix = context.Request.Path.StartsWithSegments(Prefix, StringComparison.OrdinalIgnoreCase);
        if (endpoint?.Metadata.GetMetadata<DeploymentApiEndpoint>() is null)
        {
            if (underPrefix && endpoint is not null)
            {
                // Deny by prefix: whatever answers here unmarked, the unknown-path fallback
                // included, answers exactly as the fallback does.
                await AdminResponses.NotFoundAsync(context);
                return;
            }

            await next(context);
            return;
        }

        try
        {
            if (await PassesAsync(context, endpoint))
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

    private static async Task<bool> PassesAsync(HttpContext context, Endpoint endpoint)
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
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            // Commits the slide, or the ending of an expired Session, either way.
            session = await services.Sessions.AuthenticateAsync(scope.CreateCommandContext(), new Secret<string>(cookie), cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        if (session is null)
        {
            await AdminResponses.UnauthorizedAsync(context, clearCookie: true);
            return false;
        }

        if (stateChanging && !session.CsrfMatches(SingleValue(request.Headers[CsrfHeader])))
        {
            await AdminResponses.ForbiddenAsync(context);
            return false;
        }

        // A setup Session, and any Session of an Admin without their two credentials (FR-2, FR-46).
        if (session.Restricted && endpoint.Metadata.GetMetadata<SetupAllowed>() is null)
        {
            await AdminResponses.ForbiddenAsync(context);
            return false;
        }

        context.Features.Set(session);
        return true;
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
