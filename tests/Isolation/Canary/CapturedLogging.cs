using System.Text;
using Gatekeep.Adapters.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace Gatekeep.Tests.Isolation.Canary;

/// <summary>The hosts' own logging call, ending at a console formatter a test reads.</summary>
internal static class CapturedLogging
{
    /// <summary>
    /// <see cref="LoggingExtensions.AddGatekeepLogging"/>, as every host calls it, at
    /// <paramref name="minimumLevel"/>. Canary flows run at <see cref="LogLevel.Trace"/>, so
    /// debug output is scanned too.
    /// </summary>
    public static ServiceProvider Create(CapturedConsole captured, LogLevel minimumLevel = LogLevel.Information)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddGatekeepLogging().SetMinimumLevel(minimumLevel));
        services.AddSingleton<ConsoleFormatter>(captured);
        services.Configure<ConsoleLoggerOptions>(options => options.FormatterName = captured.Name);
        return services.BuildServiceProvider();
    }
}

/// <summary>
/// Sees the real console provider's output on the logging thread. Writing nothing to the
/// console itself keeps test output clean, and needs no process-wide redirect.
/// </summary>
internal sealed class CapturedConsole() : ConsoleFormatter("capture")
{
    private readonly StringBuilder _text = new();
    private readonly Lock _lock = new();

    public string Text
    {
        get
        {
            lock (_lock)
            {
                return _text.ToString();
            }
        }
    }

    public void Plant(string raw)
    {
        lock (_lock)
        {
            _text.AppendLine(raw);
        }
    }

    public override void Write<TState>(
        in LogEntry<TState> logEntry,
        IExternalScopeProvider? scopeProvider,
        TextWriter textWriter)
    {
        Plant(logEntry.Formatter(logEntry.State, logEntry.Exception));
        scopeProvider?.ForEachScope((scope, _) => Plant(scope?.ToString() ?? string.Empty), (object?)null);
    }
}
