using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;

namespace Gatekeep.Adapters.Logging;

public static class LoggingExtensions
{
    /// <summary>
    /// Makes <see cref="ScrubbingLoggerProvider"/> the only provider. Console is built here,
    /// not registered, as a registered one would also log straight to the sink.
    /// </summary>
    public static ILoggingBuilder AddGatekeepLogging(this ILoggingBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ClearProviders();

        // Brings console's options and JSON formatter, and its provider, removed below.
        builder.AddJsonConsole();
        builder.Services.RemoveAll<ILoggerProvider>();

        builder.Services.AddSingleton<ILoggerProvider>(services => new ScrubbingLoggerProvider(
            new ConsoleLoggerProvider(
                services.GetRequiredService<IOptionsMonitor<ConsoleLoggerOptions>>(),
                services.GetServices<ConsoleFormatter>())));

        return builder;
    }
}
