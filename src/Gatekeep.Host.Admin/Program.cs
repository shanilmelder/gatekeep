using Gatekeep.Adapters.Logging;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddGatekeepLogging();
var app = builder.Build();
app.Run();
