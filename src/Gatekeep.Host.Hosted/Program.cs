using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Logging;
using Gatekeep.Host.Hosted;
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

// Hosted Login (Story 4.1): the built apps/hosted-login bundle in the web root, its index.html read
// and checked once here. Without a valid one the host refuses to start, naming the web root.
var webRoot = HostedLoginFiles.WebRoot(builder.Environment);
var stepPage = StepPageTemplate.TryLoad(webRoot);
builder.AddGatekeepHost(new HostProfile(
    "Host.Hosted",
    ["Hosted"],
    HasPublicEndpoint: true,
    HasForwardingProxy: true,
    RefusedHostSettings: _ => stepPage is null ? [StepPageTemplate.WebRootSetting] : []));

// Each Tenant's OpenID Provider (Stories 2.3, 2.5 and 2.9): discovery, JWKS, Client Credentials and
// the code flow with PKCE, as gk_hosted. Its audit events, such as a refused cross-Tenant credential,
// go to the Tenant's Log. From Story 4.2 a valid authorization request reuses a live Session or goes to
// Login under a bound sign-in transaction. No credential step exists in a release build before Story
// 4.9, so after Login's email the step is Generic error temporarily_unavailable.
// Every Hosted Login step page is the bundle's index.html with the step embedded as JSON and the
// Tenant's theme linked, under the AD-21 headers. The authorization endpoint shows Generic error
// through it for a request it can't send back. A refused host never builds it.
builder.Services.AddSingleton<IAuditAppender>(AuditContract.CreateAppender());
builder.Services.AddGatekeepProtocol(
    services => services.GetRequiredService<HostDatabases>()["Hosted"],
    _ => new HostedStepPages(stepPage!));
var app = builder.Build();

// First on the public port, before routing (AD-6): the whole host, matched exactly against an
// active Tenant's stored host, is the only Tenant source here (AD-4). Any other host gets the one
// fixed 404 before any Tenant code runs. The private health port keeps its own branch.
app.UseTenantResolution(() => app.Services.GetRequiredService<HostDatabases>()["Hosted"]);

// The client Caddy forwarded, which token requests are counted by (Story 2.5), believed only from
// Caddy's edge network (Gatekeep:ForwardedBy).
app.UseGatekeepForwardedClient();

// Hosted Login's files (Story 4.1): the AD-21 headers on everything under /login/, and the bundle's
// assets under /login/assets/. The theme stylesheet is an endpoint, below.
// A host refused for its web root never serves: RunGatekeepAsync stops it before the first request.
if (stepPage is not null)
{
    app.UseHostedLoginFiles(webRoot);
}

// OpenIddict, on the resolved Tenant only: its first handler takes the Tenant from resolution.
app.UseGatekeepProtocol();
app.UseRouting();

// The request's Tenant's theme stylesheet, at its content hash (Story 4.1).
app.MapThemeStylesheet();

// Hosted Login's sign-in surface (Story 4.2): the /login step page and its two Origin- and
// CSRF-checked API requests.
app.MapGatekeepLogin();

// Any other path on a resolved host gets the same fixed 404 as an unknown host.
app.MapFallback(TenancyContract.NotFoundAsync);

Environment.ExitCode = await app.RunGatekeepAsync();
