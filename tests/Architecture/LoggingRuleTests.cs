using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>AD-24 rules, which the compiler can't enforce alone.</summary>
public class LoggingRuleTests
{
    private const string AdapterDirectory = "src/Adapters/Logging/";
    private const string CliDirectory = "src/Gatekeep.Cli/";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    private static readonly Regex Comment = new(@"//[^\r\n]*|/\*.*?\*/", RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex AddsLoggingProvider = new(
        @"\.\s*(?:Add(?:Provider|Console|SimpleConsole|JsonConsole|SystemdConsole|Debug|EventLog|EventSourceLogger|TraceSource|Serilog|OpenTelemetry|ApplicationInsights\w*|AzureWebAppDiagnostics)|UseSerilog)\s*\(|\bILoggerProvider\b|\bLoggerFactory\s*\.\s*Create\b|\bnew\s+(?:LoggerFactory|ConsoleLoggerProvider)\b",
        RegexOptions.Compiled);

    private static readonly Regex WritesToConsole = new(
        @"\bConsole\s*\.\s*(?:Write|WriteLine|Out|Error|OpenStandardOutput|OpenStandardError)\b",
        RegexOptions.Compiled);

    public static TheoryData<string> HostPrograms =>
    [
        .. Directory.EnumerateDirectories(Path.Combine(Root, "src"), "Gatekeep.Host.*")
            .Select(d => Path.GetRelativePath(Root, Path.Combine(d, "Program.cs")).Replace('\\', '/')),
    ];

    [Fact]
    public void Three_hosts_are_discovered()
    {
        Assert.Equal(3, HostPrograms.Count);
    }

    [Theory]
    [MemberData(nameof(HostPrograms))]
    public void Host_adds_scrubbing_before_it_builds(string program)
    {
        Assert.True(AddsScrubbingBeforeBuild(File.ReadAllText(Path.Combine(Root, program))), program);
    }

    [Theory]
    [InlineData("builder.Logging.AddGatekeepLogging();\nvar app = builder.Build();", true)]
    [InlineData("var app = builder.Build();\nbuilder.Logging.AddGatekeepLogging();", false)]
    [InlineData("// builder.Logging.AddGatekeepLogging();\nvar app = builder.Build();", false)]
    [InlineData("var app = builder.Build();", false)]
    public void Scrubbing_call_detection(string source, bool expected)
    {
        Assert.Equal(expected, AddsScrubbingBeforeBuild(source));
    }

    [Fact]
    public void Only_the_adapter_adds_a_logging_provider()
    {
        var sources = SourceFiles(Path.Combine(Root, "src"))
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'))
            .ToList();

        Assert.Contains(sources, f => f.StartsWith(AdapterDirectory, StringComparison.Ordinal));
        var offenders = sources
            .Where(f => !f.StartsWith(AdapterDirectory, StringComparison.Ordinal))
            .Where(f => HasLoggingProvider(File.ReadAllText(Path.Combine(Root, f))));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("builder.Logging.AddConsole();", true)]
    [InlineData("builder.Logging.AddJsonConsole(o => { });", true)]
    [InlineData("logging.AddDebug();", true)]
    [InlineData("logging.AddEventLog();", true)]
    [InlineData("logging.AddProvider(provider);", true)]
    [InlineData("services.AddSingleton<ILoggerProvider, Sink>();", true)]
    [InlineData("internal sealed class Sink : ILoggerProvider;", true)]
    [InlineData("using var factory = LoggerFactory.Create(b => { });", true)]
    [InlineData("var factory = new LoggerFactory();", true)]
    [InlineData("var console = new ConsoleLoggerProvider(options);", true)]
    [InlineData("builder.Logging.AddSerilog();", true)]
    [InlineData("builder.Host.UseSerilog();", true)]
    [InlineData("builder.Logging.AddOpenTelemetry();", true)]
    [InlineData("builder.Logging.AddApplicationInsights();", true)]
    [InlineData("services.AddApplicationInsightsTelemetry();", true)]
    [InlineData("builder.Logging.AddAzureWebAppDiagnostics();", true)]
    [InlineData("builder.Logging.AddGatekeepLogging();", false)]
    [InlineData("// logging.AddConsole();", false)]
    [InlineData("Console.WriteLine(\"Started\");", false)]
    public void Logging_provider_detection(string source, bool expected)
    {
        Assert.Equal(expected, HasLoggingProvider(source));
    }

    [Fact]
    public void Only_the_Cli_writes_to_the_console()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .Select(f => Path.GetRelativePath(Root, f).Replace('\\', '/'))
            .Where(f => !f.StartsWith(CliDirectory, StringComparison.Ordinal))
            .Where(f => HasConsoleWrite(File.ReadAllText(Path.Combine(Root, f))));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("Console.WriteLine(\"Started\");", true)]
    [InlineData("Console.Write(value);", true)]
    [InlineData("Console.Error.WriteLine(value);", true)]
    [InlineData("Console.Out.Flush();", true)]
    [InlineData("using var stream = Console.OpenStandardOutput();", true)]
    [InlineData("// Console.WriteLine(value);", false)]
    [InlineData("logger.LogInformation(\"Started\");", false)]
    public void Console_write_detection(string source, bool expected)
    {
        Assert.Equal(expected, HasConsoleWrite(source));
    }

    private static bool HasConsoleWrite(string source) =>
        WritesToConsole.IsMatch(Comment.Replace(source, string.Empty));

    private static bool AddsScrubbingBeforeBuild(string source)
    {
        var code = Comment.Replace(source, string.Empty);
        var call = code.IndexOf("builder.Logging.AddGatekeepLogging()", StringComparison.Ordinal);
        var build = code.IndexOf("builder.Build()", StringComparison.Ordinal);

        return call >= 0 && call < build;
    }

    private static bool HasLoggingProvider(string source) =>
        AddsLoggingProvider.IsMatch(Comment.Replace(source, string.Empty));

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Directory.EnumerateFiles(directory, "*.cs").Concat(nested);
    }
}
