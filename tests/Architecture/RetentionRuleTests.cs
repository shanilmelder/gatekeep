using System.Reflection;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Retention;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// NFR-15 and PRD §5.2: Log retention is a Kernel constant of at least its 90-day floor, and
/// nothing configures it. No source outside the Kernel file declares a retention period, and
/// no host setting, route or Cli argument names retention. Job and event type codes, such as
/// <c>audit.retention.sweep</c>, are codes, not settings, so they're allowed.
/// </summary>
public class RetentionRuleTests
{
    /// <summary>The §5.2 floor. Written here, not read from the Kernel, so lowering it there fails.</summary>
    private const int SpecFloorDays = 90;

    private const string KernelFile = "src/Gatekeep.Kernel/Retention/RetentionPeriods.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj", "node_modules"];

    /// <summary>Where a host or the Cli takes a setting or argument from a string.</summary>
    private static readonly string[] SettingSources =
        ["src/Gatekeep.Host.Hosted", "src/Gatekeep.Host.Admin", "src/Gatekeep.Host.Worker", "src/Gatekeep.Cli", "src/Adapters/Hosting"];

    /// <summary>
    /// The connection of the <c>gk_retention</c> role, named after it: it says who connects,
    /// not how long anything is kept. The only setting allowed to carry the word.
    /// </summary>
    private static readonly string[] RoleConnectionNames =
        ["Retention", "ConnectionStrings:Retention", "Database:Retention:Password"];

    private static readonly Regex PeriodDeclaration = new(
        @"\b(?:int|long|short|uint|ulong|double|decimal|TimeSpan)\??\s+\w*(?i:retention|logdays|logfloor)\w*\s*(?:=|=>|\{)",
        RegexOptions.Compiled);

    private static readonly Regex NinetyDays = new(
        @"\bFromDays\s*\(\s*90(?:\.0)?\s*\)|(?i:\binterval\s*'90\s*days?')|(?i:\bdays\s*=>\s*90\b)|\b90\s*\*\s*24\s*\*",
        RegexOptions.Compiled);

    private static readonly Regex StringLiteral = new(@"@?""(?:[^""\\\r\n]|\\.)*""", RegexOptions.Compiled);

    private static readonly Regex RoutePattern = new(
        @"\b(?:Map(?:Get|Post|Put|Patch|Delete|Methods|Group)?|Route|Http(?:Get|Post|Put|Patch|Delete))\s*\(\s*@?""(?<pattern>[^""]*)""",
        RegexOptions.Compiled);

    private static readonly Regex SettingRead = new(
        @"(?:\[\s*|\bGetSection\s*\(\s*|\bGetValue\s*<[^>]+>\s*\(\s*|\bGetConnectionString\s*\(\s*)@?""(?<key>[^""]*)""",
        RegexOptions.Compiled);

    private static readonly Regex TypeCode = new(@"\A[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\z", RegexOptions.Compiled);

    [Fact]
    public void Log_retention_is_a_const_of_at_least_the_floor()
    {
        var days = Constant(nameof(RetentionPeriods.LogDays));
        var floor = Constant(nameof(RetentionPeriods.LogFloorDays));

        Assert.Equal(SpecFloorDays, floor);
        Assert.True(days >= floor, $"Log retention is {days} days, under its {floor}-day floor.");
    }

    [Fact]
    public void No_source_outside_the_Kernel_file_declares_a_retention_period()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"), "*.cs")
            .Where(f => Relative(f) != KernelFile)
            .Where(f => DeclaresPeriod(File.ReadAllText(f)))
            .Select(Relative);

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("public const int RetentionDays = 30;", true)]
    [InlineData("private static readonly TimeSpan LogRetention = TimeSpan.FromHours(1);", true)]
    [InlineData("public static TimeSpan Retention => x;", true)]
    [InlineData("var cutoff = now - TimeSpan.FromDays(90);", true)]
    [InlineData("WHERE occurred_at < now() - interval '90 days'", true)]
    [InlineData("make_interval(days => 90)", true)]
    [InlineData("public static readonly JobType SweepRetention = new(\"audit.retention.sweep\");", false)]
    [InlineData("now - TimeSpan.FromDays(RetentionPeriods.LogDays)", false)]
    [InlineData("public static readonly TimeSpan PurgeAge = TimeSpan.FromDays(30);", false)]
    public void Retention_period_declaration_detection(string source, bool expected)
    {
        Assert.Equal(expected, DeclaresPeriod(source));
    }

    [Fact]
    public void No_setting_route_or_Cli_argument_names_retention()
    {
        var hostLiterals = SettingSources
            .SelectMany(d => SourceFiles(Path.Combine(Root, d), "*.cs"))
            .SelectMany(f => StringLiteral.Matches(File.ReadAllText(f)).Select(m => (File: f, Text: Unquote(m.Value))));

        var routesAndReads = SourceFiles(Path.Combine(Root, "src"), "*.cs")
            .SelectMany(f =>
            {
                var source = File.ReadAllText(f);
                return RoutePattern.Matches(source).Select(m => (File: f, Text: m.Groups["pattern"].Value))
                    .Concat(SettingRead.Matches(source).Select(m => (File: f, Text: m.Groups["key"].Value)));
            });

        var settingFiles = SourceFiles(Path.Combine(Root, "src"), "appsettings*.json")
            .SelectMany(f => JsonKeys(File.ReadAllText(f)).Select(k => (File: f, Text: k)));

        var composeKeys = Directory.EnumerateFiles(Path.Combine(Root, "deploy"), "compose*.yaml")
            .SelectMany(f => ComposeSettingKeys(File.ReadAllText(f)).Select(k => (File: f, Text: k)));

        var offenders = hostLiterals.Concat(routesAndReads).Concat(settingFiles).Concat(composeKeys)
            .Where(x => NamesRetention(x.Text))
            .Select(x => $"{Relative(x.File)}: {x.Text}")
            .Distinct();

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("--retention-days", true)]
    [InlineData("Gatekeep:LogRetention", true)]
    [InlineData("Gatekeep__Retention__Days", true)]
    [InlineData("/api/retention", true)]
    [InlineData("audit.retention.sweep", false)]
    [InlineData("audit.retention.checkpoint", false)]
    [InlineData("Retention", false)]
    [InlineData("ConnectionStrings__Retention", false)]
    [InlineData("Database__Retention__Password", false)]
    [InlineData("--connection-file", false)]
    public void Retention_setting_detection(string text, bool expected)
    {
        Assert.Equal(expected, NamesRetention(text));
    }

    [Fact]
    public void Compose_environment_keys_are_read()
    {
        const string compose =
            """
            services:
              worker:
                environment:
                  ConnectionStrings__Worker: Host=postgres
                  Gatekeep__RetentionDays: "30"
                secrets:
                  - source: gk_worker_password
                    target: Database__Worker__Password
            """;

        Assert.Equal(
            ["ConnectionStrings__Worker", "Gatekeep__RetentionDays", "Database__Worker__Password"],
            ComposeSettingKeys(compose));
    }

    private static int Constant(string name)
    {
        var field = typeof(RetentionPeriods).GetField(name, BindingFlags.Public | BindingFlags.Static);

        Assert.NotNull(field);
        Assert.True(field.IsLiteral && !field.IsInitOnly, $"{name} isn't a const, so something could set it.");
        return (int)field.GetRawConstantValue()!;
    }

    private static bool DeclaresPeriod(string source) => PeriodDeclaration.IsMatch(source) || NinetyDays.IsMatch(source);

    private static bool NamesRetention(string text)
    {
        if (!text.Contains("retention", StringComparison.OrdinalIgnoreCase) || TypeCode.IsMatch(text))
        {
            return false;
        }

        // Compose writes the configuration separator as a double underscore.
        return !RoleConnectionNames.Contains(text.Replace("__", ":", StringComparison.Ordinal), StringComparer.Ordinal);
    }

    private static string Unquote(string literal) => literal.TrimStart('@').Trim('"');

    private static IEnumerable<string> JsonKeys(string json) =>
        Regex.Matches(json, @"""(?<key>[^""]+)""\s*:").Select(m => m.Groups["key"].Value);

    /// <summary>The keys under each <c>environment:</c> mapping, and each secret's <c>target</c>, which is a setting file.</summary>
    private static List<string> ComposeSettingKeys(string compose)
    {
        var keys = new List<string>();
        int? environmentIndent = null;

        foreach (var line in compose.ReplaceLineEndings("\n").Split('\n'))
        {
            var indent = line.Length - line.TrimStart().Length;
            var text = line.Trim();

            if (text.Length == 0 || text.StartsWith('#'))
            {
                continue;
            }

            if (environmentIndent is { } outer)
            {
                if (indent > outer && Regex.Match(text, @"\A(?<key>[A-Za-z_][\w.]*)\s*:") is { Success: true } entry)
                {
                    keys.Add(entry.Groups["key"].Value);
                    continue;
                }

                if (indent <= outer)
                {
                    environmentIndent = null;
                }
            }

            if (text == "environment:")
            {
                environmentIndent = indent;
                continue;
            }

            if (Regex.Match(text, @"\Atarget:\s*(?<key>\S+)") is { Success: true } target)
            {
                keys.Add(target.Groups["key"].Value);
            }
        }

        return keys;
    }

    private static string Relative(string path) => Path.GetRelativePath(Root, path).Replace('\\', '/');

    private static IEnumerable<string> SourceFiles(string directory, string pattern)
    {
        if (!Directory.Exists(directory))
        {
            return [];
        }

        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(d => SourceFiles(d, pattern));

        return Directory.EnumerateFiles(directory, pattern).Concat(nested);
    }
}
