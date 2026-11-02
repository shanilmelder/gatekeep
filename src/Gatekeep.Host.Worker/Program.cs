using Gatekeep.Adapters.Logging;
using Gatekeep.Host.Worker;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.AddGatekeepLogging();
builder.Services.AddGatekeepJobs();
var host = builder.Build();

var missing = WorkerSettings.Missing(host.Services.GetRequiredService<IConfiguration>());
if (missing.Count == 0)
{
    await host.RunAsync();
}
else
{
    // Names the settings only, never a value. Disposing the host flushes the log.
    host.Services.GetRequiredService<ILoggerFactory>()
        .CreateLogger("Gatekeep.Host.Worker")
        .LogCritical("Host.Worker refuses to start. Missing settings: {Settings}.", string.Join(", ", missing));
    host.Dispose();
    Environment.ExitCode = 1;
}
