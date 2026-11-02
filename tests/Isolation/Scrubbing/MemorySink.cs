using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace Gatekeep.Tests.Isolation.Scrubbing;

/// <summary>
/// An inner sink that records exactly what the scrubbing provider passes on. With a
/// <paramref name="formatter"/>, it also renders each record as console would.
/// </summary>
internal sealed class MemorySink(ConsoleFormatter? formatter = null) : ILoggerProvider, ILogger
{
    public StringWriter Formatted { get; } = new();

    public bool Disposed { get; private set; }

    public List<string> Lines { get; } = [];

    public List<object?> States { get; } = [];

    public List<Exception?> Exceptions { get; } = [];

    public int ScopesBegun { get; private set; }

    public ILogger CreateLogger(string categoryName) => this;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull
    {
        ScopesBegun++;
        return null;
    }

    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> message)
    {
        States.Add(state);
        Exceptions.Add(exception);
        Lines.Add(message(state, exception));
        formatter?.Write(new LogEntry<TState>(logLevel, "Test", eventId, state, exception, message), null, Formatted);
    }

    public void Dispose() => Disposed = true;
}
