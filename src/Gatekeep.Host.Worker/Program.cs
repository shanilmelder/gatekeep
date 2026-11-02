using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Logging;
using Gatekeep.Host.Worker;

if (HealthProbe.IsRequested(args))
{
    Environment.ExitCode = await HealthProbe.RunAsync(args);
    return;
}

// A web host only for /healthz on its private port: Host.Worker has no other inbound port.
var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddGatekeepLogging();
builder.AddGatekeepHost(WorkerSettings.Profile);
builder.Services.AddGatekeepJobs();
var app = builder.Build();
Environment.ExitCode = await app.RunGatekeepAsync();
