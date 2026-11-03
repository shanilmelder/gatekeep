using System.Reflection;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Logging;
using Gatekeep.Host.Admin;

if (HealthProbe.IsRequested(args))
{
    Environment.ExitCode = await HealthProbe.RunAsync(args);
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddGatekeepLogging();
builder.AddGatekeepHost(new HostProfile(
    "Host.Admin",
    ["Admin"],
    HasPublicEndpoint: true,
    HasPublicOrigin: true,
    HasForwardingProxy: true,
    RefusedHostSettings: AdminApiServices.RefusedSettings));
builder.Services.AddAdminApi();
var app = builder.Build();

// Every public-port response carries the AD-21 headers, 404s and API paths included.
app.UseGatekeepSecurityHeaders();

// The client Caddy forwarded, which bootstrap claims are counted by.
app.UseGatekeepForwardedClient();

// Once bootstrap is complete the Bootstrap page is gone: the same 404 as an unknown path.
app.UseBootstrapPage();

// The Admin Dashboard bundle (apps/admin-dashboard), copied into the web root by the image.
app.UseStaticFiles();

// The session, CSRF, Origin and setup checks run on every /api/v1/deployment endpoint (NFR-5).
app.UseRouting();
app.UseAdminRequestChecks();
app.MapAdminApi();

// An unknown API path is a 404, never the bundle. API endpoints mapped above still win: a
// fallback matches only when nothing else does.
app.MapFallback("/api/{**path}", AdminResponses.NotFoundAsync);

// Any other path without a file extension is a deep link into the bundle.
app.MapFallbackToFile("index.html");

// The build generates docs/api/openapi-v1.json by running this entry point under GetDocument
// with a stand-in server and no settings: it reads the endpoints, so nothing is refused.
Environment.ExitCode = Assembly.GetEntryAssembly()?.GetName().Name == "GetDocument.Insider"
    ? await RunForDocumentAsync(app)
    : await app.RunGatekeepAsync();

static async Task<int> RunForDocumentAsync(WebApplication app)
{
    await app.RunAsync();
    return 0;
}
