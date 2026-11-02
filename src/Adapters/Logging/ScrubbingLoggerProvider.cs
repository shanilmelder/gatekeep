using System.Collections;
using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Adapters.Logging;

/// <summary>
/// Wraps the one real sink, which sees only scrubbed text. It doesn't implement
/// <c>ISupportExternalScope</c> and doesn't forward scopes, so a scope never reaches the sink.
/// The alias keeps <c>Logging:Console</c> rules applying to the console it wraps.
/// </summary>
[ProviderAlias("Console")]
public sealed class ScrubbingLoggerProvider(ILoggerProvider inner) : ILoggerProvider
{
    /// <summary>Written in place of a record that couldn't be scrubbed, so it names no value.</summary>
    public const string FailedRecord = "Log record withheld: scrubbing failed.";

    private const string OriginalFormat = "{OriginalFormat}";

    public ILogger CreateLogger(string categoryName) => new ScrubbingLogger(inner.CreateLogger(categoryName));

    public void Dispose() => inner.Dispose();

    private sealed class ScrubbingLogger(ILogger inner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            // A null exception, as a sink would otherwise print the raw one.
            inner.Log(
                logLevel,
                eventId,
                new ScrubbedRecord(ScrubbedLine(state, exception, formatter)),
                null,
                static (record, _) => record.ToString());
        }

        private static string ScrubbedLine<TState>(
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            try
            {
                var text = formatter(state, exception);
                if (exception is not null)
                {
                    text = $"{text}{Environment.NewLine}{exception}";
                }

                return Scrubber.Scrub(text, SensitiveValues(state));
            }
            catch (Exception)
            {
                return FailedRecord;
            }
        }

        private static List<string> SensitiveValues<TState>(TState state) =>
            state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? pairs
                    .Where(p => p.Key != OriginalFormat && Scrubber.IsSensitiveName(p.Key))
                    .SelectMany(p => Texts(p.Value))
                    .ToList()
                : [];

        /// <summary>
        /// A log message prints a collection one level deep, item by item, so each item is a
        /// value and a collection that holds itself can't recurse. A number or boolean is
        /// skipped, as replacing its text would garble the line.
        /// </summary>
        private static IEnumerable<string> Texts(object? value) => value switch
        {
            null or bool or sbyte or byte or short or ushort or int or uint or long or ulong
                or nint or nuint or Int128 or UInt128 or float or double or decimal => [],
            string text => [text],
            IEnumerable items => items.Cast<object?>().Select(Text),
            _ => [Text(value)],
        };

        private static string Text(object? value) =>
            Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
    }

    /// <summary>
    /// The scrubbed line as text, with the current W3C IDs as named state. The IDs are random
    /// and hold no value, so they need no scrubbing.
    /// </summary>
    private sealed class ScrubbedRecord : List<KeyValuePair<string, object?>>
    {
        private readonly string _line;

        public ScrubbedRecord(string line)
        {
            _line = line;

            if (Activity.Current is { IdFormat: ActivityIdFormat.W3C } activity)
            {
                Add(new("TraceId", activity.TraceId.ToString()));
                Add(new("SpanId", activity.SpanId.ToString()));
            }
        }

        public override string ToString() => _line;
    }
}
