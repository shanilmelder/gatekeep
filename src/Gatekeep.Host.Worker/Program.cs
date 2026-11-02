using Gatekeep.Adapters.Logging;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.AddGatekeepLogging();
var host = builder.Build();
host.Run();
