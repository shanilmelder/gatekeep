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
Environment.ExitCode = await app.RunGatekeepAsync();
