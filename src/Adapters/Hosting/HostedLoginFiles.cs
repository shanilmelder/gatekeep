using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.FileProviders;

namespace Gatekeep.Adapters.Hosting;

/// <summary>Hosted Login's files under <c>/login/</c> on Host.Hosted (AD-21, Story 4.1).</summary>
public static class HostedLoginFiles
{
    /// <summary>Every Hosted Login path is under this one.</summary>
    public const string BasePath = "/login";

    /// <summary>The bundle's built assets, content-hashed by Vite, served from the web root's <c>assets</c> folder.</summary>
    public const string AssetsPath = "/login/assets";

    /// <summary>The web root the image copies the built bundle to, unless <c>--webroot</c> names another.</summary>
    public static string WebRoot(IWebHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        return environment.WebRootPath is { Length: > 0 } root ? root : Path.Combine(environment.ContentRootPath, "wwwroot");
    }

    /// <summary>
    /// The AD-21 headers on every response under <c>/login/</c>, 404s included, and the bundle's assets
    /// under <c>/login/assets/</c>. Nothing else in the web root is served: its <c>index.html</c> is only
    /// ever a step page (<see cref="StepPageTemplate"/>). An unknown asset falls through to what follows.
    /// </summary>
    public static IApplicationBuilder UseHostedLoginFiles(this IApplicationBuilder app, string webRoot)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(webRoot);

        app.UseWhen(
            static context => context.Request.Path.StartsWithSegments(BasePath, StringComparison.OrdinalIgnoreCase),
            static branch => branch.UseGatekeepSecurityHeaders());

        // The folder exists: StepPageTemplate.TryLoad checked it, or the host refused to start.
        return app.UseStaticFiles(new StaticFileOptions
        {
            RequestPath = AssetsPath,
            FileProvider = new PhysicalFileProvider(Path.Combine(webRoot, "assets")),
        });
    }
}
