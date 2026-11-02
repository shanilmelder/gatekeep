using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Logging;

if (HealthProbe.IsRequested(args))
{
    Environment.ExitCode = await HealthProbe.RunAsync(args);
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddGatekeepLogging();
builder.AddGatekeepHost(new HostProfile("Host.Admin", ["Admin"], HasPublicEndpoint: true));
var app = builder.Build();

// Every public-port response carries the AD-21 headers, 404s and API paths included.
app.UseGatekeepSecurityHeaders();

// The Admin Dashboard bundle (apps/admin-dashboard), copied into the web root by the image.
app.UseStaticFiles();

// An unknown API path is a 404, never the bundle. API endpoints mapped later still win: a
// fallback matches only when nothing else does.
app.MapFallback("/api/{**path}", static context =>
{
    context.Response.StatusCode = StatusCodes.Status404NotFound;
    return Task.CompletedTask;
});

// Any other path without a file extension is a deep link into the bundle.
app.MapFallbackToFile("index.html");

Environment.ExitCode = await app.RunGatekeepAsync();
