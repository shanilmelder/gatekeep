using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Logging;
using Gatekeep.Kernel.Audit;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

if (HealthProbe.IsRequested(args))
{
    Environment.ExitCode = await HealthProbe.RunAsync(args);
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddGatekeepLogging();
builder.AddGatekeepHost(new HostProfile("Host.Hosted", ["Hosted"], HasPublicEndpoint: true, HasForwardingProxy: true));

// Each Tenant's OpenID Provider (Stories 2.3, 2.5 and 2.9): discovery, JWKS, Client Credentials and
// the code flow with PKCE, as gk_hosted. Its audit events, such as a refused cross-Tenant credential,
// go to the Tenant's Log. No sign-in screen exists before Stories 4.1 and 4.2, so a release build
// completes no sign-in (Protocol's default UnavailableSignIn): every valid authorization request gets
// temporarily_unavailable and no code.
// The one page the authorization endpoint shows carries the AD-21 Hosted headers.
builder.Services.AddSingleton<IAuditAppender>(AuditContract.CreateAppender());
builder.Services.AddGatekeepProtocol(services => services.GetRequiredService<HostDatabases>()["Hosted"], SecurityHeaders.Apply);
var app = builder.Build();

// First on the public port, before routing (AD-6): the whole host, matched exactly against an
// active Tenant's stored host, is the only Tenant source here (AD-4). Any other host gets the one
// fixed 404 before any Tenant code runs. The private health port keeps its own branch.
app.UseTenantResolution(() => app.Services.GetRequiredService<HostDatabases>()["Hosted"]);

// The client Caddy forwarded, which token requests are counted by (Story 2.5), believed only from
// Caddy's edge network (Gatekeep:ForwardedBy).
app.UseGatekeepForwardedClient();

// OpenIddict, on the resolved Tenant only: its first handler takes the Tenant from resolution.
app.UseGatekeepProtocol();
app.UseRouting();

// Any other path on a resolved host gets the same fixed 404 as an unknown host.
app.MapFallback(TenancyContract.NotFoundAsync);

Environment.ExitCode = await app.RunGatekeepAsync();
