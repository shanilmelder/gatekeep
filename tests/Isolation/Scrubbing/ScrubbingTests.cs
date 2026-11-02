using System.Diagnostics;
using System.Text.Json;
using Gatekeep.Adapters.Logging;
using Gatekeep.Kernel.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Xunit;

namespace Gatekeep.Tests.Isolation.Scrubbing;

public sealed class ScrubbingTests
{
    private const string Value = "canary-value-1234";
    private const string Masked = Scrubber.Mask;

    private readonly MemorySink _sink = new();
    private readonly ILogger _logger;

    public ScrubbingTests()
    {
        _logger = new ScrubbingLoggerProvider(_sink).CreateLogger("Test");
    }

    private string Line => Assert.Single(_sink.Lines);

    [Fact]
    public void Secret_argument_prints_only_the_mask()
    {
        _logger.LogInformation("{S}", new Secret<string>(Value));

        Assert.Equal("[secret]", Line);
    }

    [Theory]
    [InlineData("Password")]
    [InlineData("db_password")]
    [InlineData("PASSWD")]
    [InlineData("Pwd")]
    [InlineData("ClientSecret")]
    [InlineData("AccessToken")]
    [InlineData("api_key")]
    [InlineData("ApiKey")]
    [InlineData("Authorization")]
    [InlineData("SessionCookie")]
    [InlineData("Code")]
    [InlineData("code")]
    [InlineData("code_verifier")]
    [InlineData("device_code")]
    [InlineData("user_code")]
    [InlineData("api-key")]
    [InlineData("Passphrase")]
    [InlineData("Credential")]
    [InlineData("ClientAssertion")]
    [InlineData("private_key")]
    public void Sensitive_name_loses_its_value_and_the_message_stays(string name)
    {
        _logger.LogInformation($"Signing in with {{{name}}} now", Value);

        Assert.Equal($"Signing in with {Masked} now", Line);
    }

    [Fact]
    public void Sensitive_name_in_a_defined_message_is_scrubbed()
    {
        var log = LoggerMessage.Define<string, string>(LogLevel.Information, default, "{Host} used {Password}");

        log(_logger, "db", Value, null);

        Assert.Equal($"db used {Masked}", Line);
    }

    [Fact]
    public void Sensitive_collection_loses_each_item()
    {
        _logger.LogInformation("{Tokens}", new List<string> { Value, "second-canary" });

        Assert.DoesNotContain(Value, Line);
        Assert.DoesNotContain("second-canary", Line);
    }

    [Fact]
    public void Collection_that_holds_itself_is_read_one_level_deep()
    {
        var loop = new List<object>();
        loop.Add(loop);

        _logger.LogInformation("{Tokens}", loop);

        Assert.DoesNotContain(ScrubbingLoggerProvider.FailedRecord, Line);
    }

    [Fact]
    public void Overlapping_sensitive_values_leave_no_part()
    {
        _logger.LogInformation("{Password} and {Token}", Value, $"{Value}-suffix");

        Assert.Equal($"{Masked} and {Masked}", Line);
    }

    [Fact]
    public void Number_under_a_sensitive_name_leaves_other_digits_alone()
    {
        _logger.LogInformation("Run 5 used {TokenCount} of 15", 5);

        Assert.Equal("Run 5 used 5 of 15", Line);
    }

    [Fact]
    public void Boolean_under_a_sensitive_name_keeps_the_line()
    {
        _logger.LogInformation("{TokenValid} is True here", true);

        Assert.Equal("True is True here", Line);
    }

    [Fact]
    public void Value_of_a_sensitive_name_is_also_removed_from_the_exception()
    {
        _logger.LogError(new InvalidOperationException($"refused {Value}"), "Failed with {Password}", Value);

        Assert.DoesNotContain(Value, Line);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(null, "(null)")]
    public void Empty_or_null_sensitive_value_keeps_the_record(string? value, string printed)
    {
        _logger.LogInformation("Value {Password} end", value);

        Assert.Equal($"Value {printed} end", Line);
    }

    [Theory]
    [InlineData("Host=db;Username=gk;Password=canary-value-1234;Database=gk", $"Host=db;Username=gk;Password={Masked};Database=gk")]
    [InlineData("Host=db;Password=canary value 1234;Database=gk", $"Host=db;Password={Masked};Database=gk")]
    [InlineData("Host=db;Password=\"canary;value\";Database=gk", $"Host=db;Password={Masked};Database=gk")]
    [InlineData("Host=db;Password='canary;value';Database=gk", $"Host=db;Password={Masked};Database=gk")]
    [InlineData("User ID=gk;Pwd = canary-value-1234;", $"User ID=gk;Pwd = {Masked};")]
    [InlineData("client_secret=canary-value-1234&grant=x", $"client_secret={Masked}")]
    [InlineData("GET /cb?access_token=canary-value-1234&state=1", $"GET /cb?access_token={Masked}&state=1")]
    [InlineData("password: canary-value-1234", $"password: {Masked}")]
    [InlineData("password : canary-value-1234", $"password : {Masked}")]
    [InlineData("{\"client_secret\":\"canary-value-1234\"}", $"{{\"client_secret\":{Masked}")]
    [InlineData("{ \"password\" : \"canary-value-1234\" }", $"{{ \"password\" : {Masked}")]
    [InlineData("Authorization: rawvalue", $"Authorization: {Masked}")]
    [InlineData("Authorization: Bearer canary-value-1234", $"Authorization: {Masked}")]
    [InlineData("authorization: bearer canary.value~1234+/=", $"authorization: {Masked}")]
    [InlineData("Authorization: Basic Y2FuYXJ5OnZhbHVl", $"Authorization: {Masked}")]
    [InlineData("api-key=canary-value-1234", $"api-key={Masked}")]
    [InlineData("passphrase=canary-value-1234", $"passphrase={Masked}")]
    [InlineData("credential=canary-value-1234", $"credential={Masked}")]
    [InlineData("assertion=canary-value-1234", $"assertion={Masked}")]
    [InlineData("private_key=canary-value-1234", $"private_key={Masked}")]
    [InlineData("code_verifier=canary-value-1234", $"code_verifier={Masked}")]
    [InlineData("device_code=canary-value-1234", $"device_code={Masked}")]
    [InlineData("user_code=canary-value-1234", $"user_code={Masked}")]
    [InlineData("Password=p&ssw0rd;Database=x", $"Password={Masked};Database=x")]
    [InlineData("Password=\"canary;value", $"Password={Masked}")]
    [InlineData("Password='canary;value\nnext line", $"Password={Masked}\nnext line")]
    [InlineData("Password=\"canary\"tail;Database=x", $"Password={Masked};Database=x")]
    [InlineData("Password='canary'tail;Database=x", $"Password={Masked};Database=x")]
    [InlineData("postgres://gk:canary@db/x", $"postgres://{Masked}@db/x")]
    [InlineData("https://canary@db/x", $"https://{Masked}@db/x")]
    [InlineData("postgres://gk:ca@nary@db/x", $"postgres://{Masked}@db/x")]
    [InlineData("Cookie: a=b; c=d", $"Cookie: {Masked}")]
    [InlineData("Set-Cookie: a=b; Path=/; HttpOnly", $"Set-Cookie: {Masked}")]
    [InlineData("sent Bearer canary-value-123456 now", $"sent Bearer {Masked} now")]
    [InlineData("sent Basic Y2FuYXJ5OnZhbHVlMTIz now", $"sent Basic {Masked} now")]
    [InlineData("code=canary-value-1234&state=1", $"code={Masked}&state=1")]
    [InlineData("/cb#code=canary-value-1234&state=1", $"/cb#code={Masked}&state=1")]
    [InlineData("/cb%3Fcode%3Dcanary-value-1234%26state%3D1", $"/cb%3Fcode%3D{Masked}%26state%3D1")]
    [InlineData("issued eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl to app", $"issued {Masked} to app")]
    [InlineData("issued eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0. to app", $"issued {Masked} to app")]
    [InlineData("GET /cb?code=canary-value-1234 HTTP/1.1", $"GET /cb?code={Masked} HTTP/1.1")]
    [InlineData("GET /cb?state=1&code=canary-value-1234&x=2", $"GET /cb?state=1&code={Masked}&x=2")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nY2FuYXJ5\nLXZhbHVl\n-----END PRIVATE KEY----- loaded", $"{Masked} loaded")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nY2FuYXJ5\n-----END RSA PRIVATE KEY-----", Masked)]
    [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----\r\nY2FuYXJ5\r\n", Masked)]
    public void Shape_in_a_message_is_scrubbed(string message, string expected)
    {
        // As an argument, so the text isn't parsed as a message template.
        _logger.LogInformation("{Text}", message);

        Assert.Equal(expected, Line);
    }

    [Fact]
    public void Exception_keeps_its_type_and_loses_the_value()
    {
        _logger.LogError(new InvalidOperationException($"Password={Value}"), "Query failed");

        Assert.Contains("Query failed", Line);
        Assert.Contains(typeof(InvalidOperationException).FullName!, Line);
        Assert.DoesNotContain(Value, Line);
    }

    [Fact]
    public void Inner_exception_is_scrubbed()
    {
        var thrown = new InvalidOperationException("Outer", new ArgumentException($"Password={Value}"));

        _logger.LogError(thrown, "Query failed");

        Assert.Contains(typeof(ArgumentException).FullName!, Line);
        Assert.DoesNotContain(Value, Line);
    }

    [Fact]
    public void Sink_gets_only_scrubbed_text_and_no_exception()
    {
        _logger.LogError(new InvalidOperationException($"Password={Value}"), "{Password}", Value);

        var state = Assert.IsAssignableFrom<IReadOnlyList<KeyValuePair<string, object?>>>(Assert.Single(_sink.States));

        Assert.Empty(state);
        Assert.Equal(Line, state.ToString());
        Assert.DoesNotContain(Value, Line);
        Assert.Null(Assert.Single(_sink.Exceptions));
    }

    [Fact]
    public void Sink_gets_the_trace_and_span_IDs_as_named_state()
    {
        using var activity = new Activity("Test").SetIdFormat(ActivityIdFormat.W3C).Start();

        _logger.LogInformation("Inside");

        var state = Assert.IsAssignableFrom<IReadOnlyList<KeyValuePair<string, object?>>>(Assert.Single(_sink.States));

        Assert.Equal(
            [new("TraceId", activity.TraceId.ToString()), new("SpanId", activity.SpanId.ToString())],
            state);
    }

    [Fact]
    public void Console_formatter_is_JSON_and_prints_the_message_and_both_IDs()
    {
        using var services = Logging();
        var options = services.GetRequiredService<IOptions<ConsoleLoggerOptions>>().Value;
        var json = services.GetServices<ConsoleFormatter>().Single(f => f.Name == ConsoleFormatterNames.Json);
        var sink = new MemorySink(json);
        var logger = new ScrubbingLoggerProvider(sink).CreateLogger("Test");
        using var activity = new Activity("Test").SetIdFormat(ActivityIdFormat.W3C).Start();

        logger.LogInformation("Used {Password}", Value);

        using var output = JsonDocument.Parse(sink.Formatted.ToString());
        var state = output.RootElement.GetProperty("State");

        Assert.Equal(ConsoleFormatterNames.Json, options.FormatterName);
        Assert.Equal($"Used {Masked}", output.RootElement.GetProperty("Message").GetString());
        Assert.Equal(activity.TraceId.ToString(), state.GetProperty("TraceId").GetString());
        Assert.Equal(activity.SpanId.ToString(), state.GetProperty("SpanId").GetString());
    }

    [Fact]
    public void Console_log_level_rule_applies_to_the_scrubbing_provider()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Logging:Console:LogLevel:Default"] = "Warning" })
            .Build();

        using var services = Logging(logging => logging.AddConfiguration(configuration.GetSection("Logging")));
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Test");

        Assert.False(logger.IsEnabled(LogLevel.Information));
        Assert.True(logger.IsEnabled(LogLevel.Warning));
    }

    [Fact]
    public void Disposing_the_wrapper_disposes_the_sink()
    {
        new ScrubbingLoggerProvider(_sink).Dispose();

        Assert.True(_sink.Disposed);
    }

    [Fact]
    public void Scope_never_reaches_the_sink()
    {
        using (_logger.BeginScope("Scope {Password}", Value))
        {
            _logger.LogInformation("Inside");
        }

        Assert.Equal(0, _sink.ScopesBegun);
        Assert.Equal("Inside", Line);
    }

    [Theory]
    [InlineData("{S}")]
    [InlineData("{Password}")]
    public void Argument_that_throws_writes_the_fixed_line(string template)
    {
        var thrower = new ThrowingArgument();

        var escaped = Record.Exception(() => _logger.LogInformation(template, thrower));

        Assert.Null(escaped);
        Assert.Equal(ScrubbingLoggerProvider.FailedRecord, Line);
    }

    [Fact]
    public void Exception_that_throws_when_printed_writes_the_fixed_line()
    {
        var escaped = Record.Exception(() => _logger.LogError(new ThrowingException(), "Failed"));

        Assert.Null(escaped);
        Assert.Equal(ScrubbingLoggerProvider.FailedRecord, Line);
    }

    [Theory]
    [InlineData("Started {Host}", "gatekeep", "Started gatekeep")]
    [InlineData("Listening on {Url}", "https://a.example/cb?error_code=5", "Listening on https://a.example/cb?error_code=5")]
    [InlineData("{Text}", "Basic auth failed", "Basic auth failed")]
    [InlineData("{Text}", "Bearer token expired", "Bearer token expired")]
    public void Ordinary_log_is_unchanged(string template, string argument, string expected)
    {
        _logger.LogInformation(template, argument);

        Assert.Equal(expected, Line);
    }

    [Fact]
    public void Level_the_sink_ignores_is_not_written()
    {
        _logger.LogDebug("{Password}", Value);

        Assert.Empty(_sink.Lines);
    }

    private static ServiceProvider Logging(Action<ILoggingBuilder>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging(logging =>
        {
            configure?.Invoke(logging);
            logging.AddGatekeepLogging();
        });

        return services.BuildServiceProvider();
    }

    private sealed class ThrowingArgument
    {
        public override string ToString() => throw new InvalidOperationException(Value);
    }

    private sealed class ThrowingException : Exception
    {
        public override string ToString() => throw new InvalidOperationException(Value);
    }
}
