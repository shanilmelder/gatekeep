using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Adapters.Hosting;

/// <summary>
/// The AD-21 response headers, defined once for every browser surface: the Admin Dashboard
/// now, Hosted Login and the Account Portal later. The policy allows only this origin, no
/// inline script or style, no nonce or hash, and no framing. A bundle that breaks it is fixed
/// in its build, never by loosening this.
/// </summary>
public static class SecurityHeaders
{
    public const string ContentSecurityPolicy =
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

    public const string ReferrerPolicy = "no-referrer";

    public const string FrameOptions = "DENY";

    public const string ContentTypeOptions = "nosniff";

    /// <summary>
    /// Sends the four headers on every response the pipeline produces from this point, 404s
    /// included. They're set again just before the response starts, so nothing later in the
    /// pipeline can drop or change them. Kestrel's own 400, 413 and 431 responses never reach
    /// middleware, and an unhandled exception's 500 may lose them. The health branch runs
    /// earlier and never reaches here.
    /// </summary>
    public static IApplicationBuilder UseGatekeepSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use(async (context, next) =>
        {
            Apply(context.Response.Headers);
            context.Response.OnStarting(
                static state =>
                {
                    Apply(((HttpResponse)state).Headers);
                    return Task.CompletedTask;
                },
                context.Response);

            await next(context);
        });
    }

    /// <summary>
    /// Sets the four headers on <paramref name="headers"/>: for a host that sends them on one page only,
    /// such as Host.Hosted's authorization error page (Story 2.9), rather than on every response.
    /// </summary>
    public static void Apply(IHeaderDictionary headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        headers.ContentSecurityPolicy = ContentSecurityPolicy;
        headers["Referrer-Policy"] = ReferrerPolicy;
        headers.XFrameOptions = FrameOptions;
        headers.XContentTypeOptions = ContentTypeOptions;
    }
}
