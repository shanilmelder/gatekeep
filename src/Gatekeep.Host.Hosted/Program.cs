using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Logging;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

if (HealthProbe.IsRequested(args))
{
    Environment.ExitCode = await HealthProbe.RunAsync(args);
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddGatekeepLogging();
builder.AddGatekeepHost(new HostProfile("Host.Hosted", ["Hosted"], HasPublicEndpoint: true));

// Each Tenant's OpenID Provider (Story 2.3): discovery and JWKS so far, as gk_hosted.
builder.Services.AddGatekeepProtocol(services => services.GetRequiredService<HostDatabases>()["Hosted"]);
var app = builder.Build();

// First on the public port, before routing (AD-6): the whole host, matched exactly against an
// active Tenant's stored host, is the only Tenant source here (AD-4). Any other host gets the one
// fixed 404 before any Tenant code runs. The private health port keeps its own branch.
app.UseTenantResolution(() => app.Services.GetRequiredService<HostDatabases>()["Hosted"]);

// OpenIddict, on the resolved Tenant only: its first handler takes the Tenant from resolution.
app.UseGatekeepProtocol();
app.UseRouting();

// Any other path on a resolved host gets the same fixed 404 as an unknown host.
app.MapFallback(TenancyContract.NotFoundAsync);

Environment.ExitCode = await app.RunGatekeepAsync();
