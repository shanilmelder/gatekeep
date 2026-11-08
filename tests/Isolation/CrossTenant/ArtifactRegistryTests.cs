using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>
/// Story 1.31 (FR-8, AD-25): <see cref="ArtifactRegistry"/> holds every FR-8 artifact type and
/// nothing else, and each pending one waits on a story <c>sprint-status.yaml</c> lists and doesn't
/// mark done. A covered one names its test.
/// </summary>
public sealed partial class ArtifactRegistryTests
{
    private static readonly string SprintStatus = Path.Combine(
        BuildOutput.RepositoryRoot(), "_bmad-output", "implementation-artifacts", "sprint-status.yaml");

    /// <summary>The PRD's FR-8 word for a type, where it differs from the registry's.</summary>
    private static readonly Dictionary<string, string> PrdAliases = new(StringComparer.Ordinal)
    {
        ["code"] = "authorization code",
    };

    [Fact]
    public void Required_is_FR_8_s_artifact_list_in_the_committed_PRD()
    {
        var prd = Directory.EnumerateFiles(
                Path.Combine(BuildOutput.RepositoryRoot(), "_bmad-output", "planning-artifacts", "prds", "prd-gatekeep-2026-11-01"),
                "*.md")
            .Select(f => File.ReadAllText(f))
            .Select(PrdArtifactTypes)
            .Single(t => t is not null)!;

        Assert.Equal(prd.Order(StringComparer.Ordinal), ArtifactRegistry.Required.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void The_PRD_line_is_parsed_into_its_types()
    {
        Assert.Equal(
            ["authorization code", "refresh token", "Passkey"],
            PrdArtifactTypes("- It covers every endpoint, and every artifact type: code, refresh token and Passkey. More text."));
        Assert.Null(PrdArtifactTypes("No such line."));
    }

    [Fact]
    public void Every_FR_8_artifact_type_is_registered_and_nothing_else()
    {
        Assert.Empty(MissingOrExtra(ArtifactRegistry.Required, ArtifactRegistry.Types));
    }

    [Fact]
    public void A_missing_artifact_type_is_reported()
    {
        var registry = ArtifactRegistry.Types.Where(t => t.Key != "invite").ToDictionary();

        Assert.Equal(
            ["Artifact type invite has no entry: add it to ArtifactRegistry as Covered(\"<test>\") or Pending(\"<story id>\")."],
            MissingOrExtra(ArtifactRegistry.Required, registry));
    }

    [Fact]
    public async Task Every_pending_artifact_type_waits_on_a_story_that_isnt_done()
    {
        var stories = Stories(await File.ReadAllTextAsync(SprintStatus, TestContext.Current.CancellationToken));

        Assert.NotEmpty(stories);
        Assert.Empty(StaleOrUnknown(ArtifactRegistry.Types, stories));
    }

    [Fact]
    public void A_pending_type_whose_story_is_done_or_unknown_is_reported()
    {
        var stories = Stories(
            """
            development_status:
              epic-2: in-progress
              2-10-rotate-refresh-tokens-and-detect-reuse: done
              2-1-run-the-spike: done
              2-9-run-the-authorization-code-flow-with-pkce: backlog
            """);

        var problems = StaleOrUnknown(
            new Dictionary<string, ArtifactCoverage>
            {
                ["refresh token"] = ArtifactCoverage.Pending("2-10"),
                ["authorization code"] = ArtifactCoverage.Pending("2-9"),
                ["invite"] = ArtifactCoverage.Pending("8-3"),
            },
            stories);

        Assert.Equal(
            [
                "Artifact type refresh token is Pending(\"2-10\"), but 2-10-rotate-refresh-tokens-and-detect-reuse is done: add its cross-Tenant test and make it Covered(\"<test>\").",
                "Artifact type invite is Pending(\"8-3\"), which no story in sprint-status.yaml has: name the story that builds it.",
            ],
            problems);
    }

    [Fact]
    public void Every_covered_type_names_a_real_test()
    {
        Assert.Empty(UnknownTests(ArtifactRegistry.Types));
    }

    [Fact]
    public void A_covered_type_naming_no_test_is_reported()
    {
        var problems = UnknownTests(new Dictionary<string, ArtifactCoverage>
        {
            ["invite"] = ArtifactCoverage.Covered("ArtifactRegistryTests.No_such_test"),
            ["Passkey"] = ArtifactCoverage.Covered($"{nameof(ArtifactRegistryTests)}.{nameof(Every_covered_type_names_a_real_test)}"),
            ["Recovery Code"] = ArtifactCoverage.Covered(" "),
        });

        Assert.Equal(
            [
                "Artifact type invite is Covered(\"ArtifactRegistryTests.No_such_test\"), which isn't a [Fact] or [Theory] Class.Method in the Isolation or Architecture tests.",
                "Artifact type Recovery Code is Covered(\" \"), which isn't a [Fact] or [Theory] Class.Method in the Isolation or Architecture tests.",
            ],
            problems);
    }

    /// <summary>Covered entries whose name isn't a test method in the Isolation or Architecture assembly.</summary>
    private static List<string> UnknownTests(IReadOnlyDictionary<string, ArtifactCoverage> registry)
    {
        var tests = TestMethods.Value;
        return
        [
            .. registry.Where(t => t.Value is ArtifactCoverage.CoveredBy { Test: var test } && !tests.Contains(test))
                .Select(t => $"Artifact type {t.Key} is Covered(\"{((ArtifactCoverage.CoveredBy)t.Value).Test}\"), which isn't a [Fact] or [Theory] Class.Method in the Isolation or Architecture tests."),
        ];
    }

    /// <summary>Every <c>Class.Method</c> carrying <c>[Fact]</c> or <c>[Theory]</c> in this assembly and the Architecture tests' build output.</summary>
    private static readonly Lazy<HashSet<string>> TestMethods = new(() =>
    {
        var output = Path.GetRelativePath(
            Path.Combine(BuildOutput.RepositoryRoot(), "tests/Isolation"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var architecture = Path.Combine(BuildOutput.RepositoryRoot(), "tests", "Architecture", output, "Gatekeep.Tests.Architecture.dll");
        Assembly[] assemblies = [typeof(ArtifactRegistryTests).Assembly, System.Runtime.Loader.AssemblyLoadContext.Default.LoadFromAssemblyPath(architecture)];

        return
        [
            .. assemblies.SelectMany(a => a.GetTypes())
                .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                    .Where(m => m.GetCustomAttributesData().Any(d => d.AttributeType.Name is "FactAttribute" or "TheoryAttribute"))
                    .Select(m => $"{t.Name}.{m.Name}")),
        ];
    });

    /// <summary>The types FR-8's "every artifact type: a, b and c." line names, in the registry's words; null without that line.</summary>
    private static List<string>? PrdArtifactTypes(string markdown)
    {
        var match = PrdLine().Match(markdown);
        if (!match.Success)
        {
            return null;
        }

        return
        [
            .. match.Groups["list"].Value.Replace(" and ", ", ", StringComparison.Ordinal)
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(t => PrdAliases.GetValueOrDefault(t, t)),
        ];
    }

    [GeneratedRegex(@"and every artifact type: (?<list>[^.\r\n]+)\.")]
    private static partial Regex PrdLine();

    private static List<string> MissingOrExtra(IEnumerable<string> required, IReadOnlyDictionary<string, ArtifactCoverage> registry) =>
    [
        .. required.Where(r => !registry.ContainsKey(r))
            .Select(r => $"Artifact type {r} has no entry: add it to ArtifactRegistry as Covered(\"<test>\") or Pending(\"<story id>\")."),
        .. registry.Keys.Where(k => !required.Contains(k, StringComparer.Ordinal))
            .Select(k => $"ArtifactRegistry lists {k}, which isn't an FR-8 artifact type: remove it."),
    ];

    private static List<string> StaleOrUnknown(IReadOnlyDictionary<string, ArtifactCoverage> registry, IReadOnlyDictionary<string, string> stories)
    {
        var problems = new List<string>();
        foreach (var (type, coverage) in registry)
        {
            if (coverage is not ArtifactCoverage.PendingOn { Story: var story })
            {
                continue;
            }

            // The id prefix and its dash: 2-1 never matches 2-10's key.
            var matches = stories.Where(s => s.Key.StartsWith($"{story}-", StringComparison.Ordinal)).ToList();
            if (matches.Count != 1)
            {
                problems.Add($"Artifact type {type} is Pending(\"{story}\"), which no story in sprint-status.yaml has: name the story that builds it.");
            }
            else if (matches[0].Value == "done")
            {
                problems.Add($"Artifact type {type} is Pending(\"{story}\"), but {matches[0].Key} is done: add its cross-Tenant test and make it Covered(\"<test>\").");
            }
        }

        return problems;
    }

    /// <summary>Each story key under <c>development_status</c> and its status: keys that start with an epic and story number.</summary>
    private static Dictionary<string, string> Stories(string yaml) =>
        StoryLine().Matches(yaml).ToDictionary(m => m.Groups["key"].Value, m => m.Groups["status"].Value, StringComparer.Ordinal);

    [GeneratedRegex(@"^\s+(?<key>\d+-\d+-[a-z0-9-]+):\s*(?<status>[a-z-]+)\s*$", RegexOptions.Multiline)]
    private static partial Regex StoryLine();
}
