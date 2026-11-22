using System.Reflection;
using System.Text.RegularExpressions;
using Gatekeep.Tests.Isolation.CrossTenant;
using Xunit;

namespace Gatekeep.Tests.Isolation.Revocation;

/// <summary>
/// Story 4.10 (FR-48, AR-23, AD-13): the walk over FR-48's trigger list. <see cref="Fr48TriggerRegistry"/>
/// holds exactly the triggers FR-48's "Triggers:" line names, one per action, each pending one waits on a
/// story <c>sprint-status.yaml</c> lists and doesn't mark done, and each covered one names a real, unskipped
/// test tagged with its trigger. Once Story 18.1 is done, nothing may be pending.
/// </summary>
public sealed partial class Fr48WalkTests
{
    private const string ReleaseGateStory = "18-1";

    private static readonly string Prd = Path.Combine(
        BuildOutput.RepositoryRoot(), "_bmad-output", "planning-artifacts", "prds", "prd-gatekeep-2026-11-01", "prd.md");

    /// <summary>Every <c>[Fact]</c> or <c>[Theory]</c> in the test assemblies, by <c>Class.Method</c>.</summary>
    private static readonly Lazy<Dictionary<string, TestFacts>> Tests = new(() =>
        ArtifactRegistryTests.TestAssemblies.Value
            .SelectMany(a => a.GetTypes())
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(m => (Name: $"{t.Name}.{m.Name}", Attributes: m.GetCustomAttributesData())))
            .Where(m => m.Attributes.Any(IsTestAttribute))
            .GroupBy(m => m.Name, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => new TestFacts(
                    [
                        .. g.SelectMany(m => m.Attributes)
                            .Where(d => d.AttributeType.Name == "TraitAttribute"
                                && d.ConstructorArguments.Count == 2
                                && d.ConstructorArguments[0].Value is "FR-48")
                            .Select(d => (string)d.ConstructorArguments[1].Value!),
                    ],
                    g.SelectMany(m => m.Attributes).Where(IsTestAttribute)
                        .Any(d => d.NamedArguments.Any(a => a.MemberName == "Skip" && a.TypedValue.Value is not null))),
                StringComparer.Ordinal));

    [Fact]
    public async Task Required_is_FR_48_s_trigger_list_in_the_committed_PRD()
    {
        var phrases = PrdTriggerPhrases(await File.ReadAllTextAsync(Prd, TestContext.Current.CancellationToken));

        Assert.NotNull(phrases);
        Assert.NotEmpty(phrases);
        Assert.Empty(PrdMismatch(phrases, Fr48TriggerRegistry.PrdPhrases, Fr48TriggerRegistry.Required));
        Assert.Equal(13, Fr48TriggerRegistry.Required.Count);
    }

    [Fact]
    public void The_PRD_line_is_parsed_into_its_phrases()
    {
        Assert.Equal(
            ["password reset or change", "email change", "Factor reset", "Admin \"revoke\""],
            PrdTriggerPhrases("Text.\n#### FR-48: Revoke\n\n- Triggers: password reset or change, email change, Factor reset, and Admin \"revoke\".\n- Effects: more."));
        Assert.Null(PrdTriggerPhrases("No such line."));
    }

    [Fact]
    public void Only_the_Triggers_line_under_the_FR_48_heading_is_read()
    {
        const string markdown =
            "#### FR-47: Other\n\n- Triggers: something else.\n\n#### FR-48: Revoke\n\n- Triggers: email change, and Factor reset.\n\n#### FR-49: Next\n\n- Triggers: later.\n";

        Assert.Equal(["email change", "Factor reset"], PrdTriggerPhrases(markdown));
        Assert.Null(PrdTriggerPhrases("#### FR-48: Revoke\n\n- Effects: none.\n\n#### FR-49: Next\n\n- Triggers: later.\n"));
    }

    [Fact]
    public void A_PRD_phrase_the_mapping_lacks_is_reported()
    {
        var problems = PrdMismatch(
            ["password reset or change", "Session hijack detected"],
            new Dictionary<string, IReadOnlyList<string>> { ["password reset or change"] = ["password reset", "password change"] },
            ["password reset", "password change"]);

        Assert.Equal(
            ["FR-48's Triggers line names \"Session hijack detected\", which Fr48TriggerRegistry.PrdPhrases doesn't map: map it to its triggers and add them to Required."],
            problems);
    }

    [Fact]
    public void A_PRD_phrase_mapped_to_fewer_triggers_than_its_actions_is_reported()
    {
        var problems = PrdMismatch(
            ["Factor or Passkey added or removed", "email change"],
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["Factor or Passkey added or removed"] = ["Factor added", "Factor removed", "Passkey added"],
                ["email change"] = ["email change"],
            },
            ["Factor added", "Factor removed", "Passkey added", "email change"]);

        Assert.Equal(
            ["FR-48's \"Factor or Passkey added or removed\" names 4 triggers, but Fr48TriggerRegistry.PrdPhrases maps it to 3: map one entry per action."],
            problems);
    }

    [Fact]
    public void A_required_trigger_the_PRD_no_longer_names_is_reported_and_so_is_a_mapped_one_required_lacks()
    {
        var problems = PrdMismatch(
            ["password reset or change"],
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["password reset or change"] = ["password reset", "password change"],
                ["email change"] = ["email change"],
            },
            ["password reset", "email change"]);

        Assert.Equal(
            [
                "FR-48's \"password reset or change\" maps to password change, which Fr48TriggerRegistry.Required doesn't list: add it to Required.",
                "Fr48TriggerRegistry.Required lists email change, which no phrase on FR-48's Triggers line names: remove it, or fix PrdPhrases.",
            ],
            problems);
    }

    [Fact]
    public void A_trigger_listed_twice_in_Required_is_reported()
    {
        var problems = PrdMismatch(
            ["email change"],
            new Dictionary<string, IReadOnlyList<string>> { ["email change"] = ["email change"] },
            ["email change", "email change"]);

        Assert.Equal(["Fr48TriggerRegistry.Required lists email change more than once: remove the copy."], problems);
    }

    [Fact]
    public void Every_FR_48_trigger_is_registered_and_nothing_else()
    {
        Assert.Empty(MissingOrExtra(Fr48TriggerRegistry.Required, Fr48TriggerRegistry.Triggers));
    }

    [Fact]
    public void A_missing_or_extra_trigger_is_reported()
    {
        var registry = Fr48TriggerRegistry.Triggers.Where(t => t.Key != "User deleted").ToDictionary();
        registry["Session hijack"] = Fr48Trigger.Pending("5-4");

        Assert.Equal(
            [
                "FR-48 trigger User deleted has no entry: add it to Fr48TriggerRegistry as Covered(\"<test>\") or Pending(\"<story id>\").",
                "Fr48TriggerRegistry lists Session hijack, which isn't an FR-48 trigger: remove it.",
            ],
            MissingOrExtra(Fr48TriggerRegistry.Required, registry));
    }

    [Fact]
    public async Task Every_pending_trigger_waits_on_a_story_that_isnt_done()
    {
        var stories = ArtifactRegistryTests.Stories(
            await File.ReadAllTextAsync(ArtifactRegistryTests.SprintStatus, TestContext.Current.CancellationToken));

        Assert.NotEmpty(stories);
        Assert.Empty(StaleOrUnknown(Fr48TriggerRegistry.Triggers, stories));
    }

    [Fact]
    public void A_pending_trigger_whose_story_is_done_unknown_or_ambiguous_is_reported()
    {
        var stories = ArtifactRegistryTests.Stories(
            """
            development_status:
              epic-4: in-progress
              4-11-reset-a-forgotten-password: done
              4-1-serve-hosted-login-step-screens: done
              5-4-block-unblock-and-revoke-a-user: backlog
              18-1-enforce-release-gates: backlog
            """);

        var problems = StaleOrUnknown(
            new Dictionary<string, Fr48Trigger>
            {
                ["password reset"] = Fr48Trigger.Pending("4-11"),
                ["User blocked"] = Fr48Trigger.Pending("5-4"),
                ["email change"] = Fr48Trigger.Pending("9-99"),
                ["Factor reset"] = Fr48Trigger.Pending("4"),
            },
            stories);

        Assert.Equal(
            [
                "FR-48 trigger password reset is Pending(\"4-11\"), but 4-11-reset-a-forgotten-password is done: add the test proving it ends access through RevokeAccess and make it Covered(\"<test>\").",
                "FR-48 trigger email change is Pending(\"9-99\"), which no story in sprint-status.yaml has: name the story that builds it.",
                "FR-48 trigger Factor reset is Pending(\"4\"), which matches 2 stories in sprint-status.yaml: use a unique id.",
            ],
            problems);
    }

    [Fact]
    public void Once_Story_18_1_is_done_any_pending_trigger_is_reported()
    {
        var stories = ArtifactRegistryTests.Stories(
            """
            development_status:
              5-4-block-unblock-and-revoke-a-user: backlog
              18-1-enforce-release-gates: done
            """);

        var problems = StaleOrUnknown(
            new Dictionary<string, Fr48Trigger>
            {
                ["User blocked"] = Fr48Trigger.Pending("5-4"),
                ["email change"] = Fr48Trigger.Covered("EmailChangeTests.Changing_the_email_revokes_access"),
            },
            stories);

        Assert.Equal(
            ["FR-48 trigger User blocked is Pending(\"5-4\"), but 18-1-enforce-release-gates is done and needs the walk with nothing pending: make it Covered(\"<test>\")."],
            problems);
    }

    [Fact]
    public void Every_covered_trigger_names_a_tagged_unskipped_test()
    {
        Assert.Empty(UnknownTests(Fr48TriggerRegistry.Triggers, Tests.Value));
    }

    [Fact]
    public void The_test_index_reads_each_tests_FR_48_traits_and_skip()
    {
        var walk = Tests.Value[$"{nameof(Fr48WalkTests)}.{nameof(Every_covered_trigger_names_a_tagged_unskipped_test)}"];

        Assert.Empty(walk.Fr48Traits);
        Assert.False(walk.Skipped);
        Assert.Contains("RevokeAccessTests.User_scope_spares_the_acting_Session_and_its_families", Tests.Value.Keys);
    }

    [Fact]
    public void A_covered_trigger_naming_no_test_an_untagged_test_or_a_skipped_test_is_reported()
    {
        var tests = new Dictionary<string, TestFacts>(StringComparer.Ordinal)
        {
            ["UserBlockTests.Blocking_revokes_access"] = new(["User blocked"], false),
            ["UserDeleteTests.Deleting_revokes_access"] = new(["User blocked"], false),
            ["FactorResetTests.Resetting_revokes_access"] = new(["Factor reset"], true),
        };

        var problems = UnknownTests(
            new Dictionary<string, Fr48Trigger>
            {
                ["password reset"] = Fr48Trigger.Covered("PasswordResetTests.No_such_test"),
                ["User blocked"] = Fr48Trigger.Covered("UserBlockTests.Blocking_revokes_access"),
                ["User deleted"] = Fr48Trigger.Covered("UserDeleteTests.Deleting_revokes_access"),
                ["Factor reset"] = Fr48Trigger.Covered("FactorResetTests.Resetting_revokes_access"),
                ["Admin revoke"] = Fr48Trigger.Covered(" "),
            },
            tests);

        Assert.Equal(
            [
                "FR-48 trigger password reset is Covered(\"PasswordResetTests.No_such_test\"), which isn't a [Fact] or [Theory] Class.Method in the Isolation or Architecture tests.",
                "FR-48 trigger User deleted is Covered(\"UserDeleteTests.Deleting_revokes_access\"), but that test has no [Trait(\"FR-48\", \"User deleted\")]: tag it with its trigger.",
                "FR-48 trigger Factor reset is Covered(\"FactorResetTests.Resetting_revokes_access\"), but that test is skipped: a skipped test covers nothing.",
                "FR-48 trigger Admin revoke is Covered(\" \"), which isn't a [Fact] or [Theory] Class.Method in the Isolation or Architecture tests.",
            ],
            problems);
    }

    private static bool IsTestAttribute(CustomAttributeData attribute) =>
        attribute.AttributeType.Name is "FactAttribute" or "TheoryAttribute";

    /// <summary>
    /// The phrases on the "- Triggers: a, b, and c." line under the <c>#### FR-48:</c> heading, as written;
    /// null without that heading or line.
    /// </summary>
    private static List<string>? PrdTriggerPhrases(string markdown)
    {
        var start = markdown.IndexOf("#### FR-48:", StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        var end = markdown.IndexOf("\n#### ", start, StringComparison.Ordinal);
        var section = end < 0 ? markdown[start..] : markdown[start..end];

        var match = PrdLine().Match(section);
        if (!match.Success)
        {
            return null;
        }

        return
        [
            .. match.Groups["list"].Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.StartsWith("and ", StringComparison.Ordinal) ? p["and ".Length..] : p),
        ];
    }

    [GeneratedRegex(@"^- Triggers: (?<list>[^\r\n]+)\.[ \t]*\r?$", RegexOptions.Multiline)]
    private static partial Regex PrdLine();

    /// <summary>Where the PRD's phrases, mapped through <paramref name="mapping"/>, and <paramref name="required"/> disagree.</summary>
    private static List<string> PrdMismatch(
        IReadOnlyList<string> phrases,
        IReadOnlyDictionary<string, IReadOnlyList<string>> mapping,
        IReadOnlyList<string> required)
    {
        var problems = new List<string>();
        var named = new HashSet<string>(StringComparer.Ordinal);
        foreach (var phrase in phrases)
        {
            if (!mapping.TryGetValue(phrase, out var triggers))
            {
                problems.Add($"FR-48's Triggers line names \"{phrase}\", which Fr48TriggerRegistry.PrdPhrases doesn't map: map it to its triggers and add them to Required.");
                continue;
            }

            // Each " or " doubles the actions: "Factor or Passkey added or removed" is four.
            var actions = 1 << Regex.Count(phrase, " or ");
            if (triggers.Distinct(StringComparer.Ordinal).Count() != actions)
            {
                problems.Add($"FR-48's \"{phrase}\" names {actions} triggers, but Fr48TriggerRegistry.PrdPhrases maps it to {triggers.Distinct(StringComparer.Ordinal).Count()}: map one entry per action.");
            }

            foreach (var trigger in triggers)
            {
                named.Add(trigger);
                if (!required.Contains(trigger, StringComparer.Ordinal))
                {
                    problems.Add($"FR-48's \"{phrase}\" maps to {trigger}, which Fr48TriggerRegistry.Required doesn't list: add it to Required.");
                }
            }
        }

        problems.AddRange(required.Distinct(StringComparer.Ordinal).Where(r => !named.Contains(r))
            .Select(r => $"Fr48TriggerRegistry.Required lists {r}, which no phrase on FR-48's Triggers line names: remove it, or fix PrdPhrases."));
        problems.AddRange(required.GroupBy(r => r, StringComparer.Ordinal).Where(g => g.Count() > 1)
            .Select(g => $"Fr48TriggerRegistry.Required lists {g.Key} more than once: remove the copy."));

        return problems;
    }

    private static List<string> MissingOrExtra(IReadOnlyList<string> required, IReadOnlyDictionary<string, Fr48Trigger> registry) =>
    [
        .. required.Where(r => !registry.ContainsKey(r))
            .Select(r => $"FR-48 trigger {r} has no entry: add it to Fr48TriggerRegistry as Covered(\"<test>\") or Pending(\"<story id>\")."),
        .. registry.Keys.Where(k => !required.Contains(k, StringComparer.Ordinal))
            .Select(k => $"Fr48TriggerRegistry lists {k}, which isn't an FR-48 trigger: remove it."),
    ];

    private static List<string> StaleOrUnknown(IReadOnlyDictionary<string, Fr48Trigger> registry, IReadOnlyDictionary<string, string> stories)
    {
        // Story 18.1 needs the walk with nothing pending.
        var releaseGate = stories.Where(s => s.Key.StartsWith($"{ReleaseGateStory}-", StringComparison.Ordinal)).ToList();
        var releaseGateDone = releaseGate.Count == 1 && releaseGate[0].Value == "done";

        var problems = new List<string>();
        foreach (var (trigger, coverage) in registry)
        {
            if (coverage is not Fr48Trigger.PendingOn { Story: var story })
            {
                continue;
            }

            if (releaseGateDone)
            {
                problems.Add($"FR-48 trigger {trigger} is Pending(\"{story}\"), but {releaseGate[0].Key} is done and needs the walk with nothing pending: make it Covered(\"<test>\").");
                continue;
            }

            // The id prefix and its dash: 4-1 never matches 4-11's key.
            var matches = stories.Where(s => s.Key.StartsWith($"{story}-", StringComparison.Ordinal)).ToList();
            if (matches.Count == 0)
            {
                problems.Add($"FR-48 trigger {trigger} is Pending(\"{story}\"), which no story in sprint-status.yaml has: name the story that builds it.");
            }
            else if (matches.Count > 1)
            {
                problems.Add($"FR-48 trigger {trigger} is Pending(\"{story}\"), which matches {matches.Count} stories in sprint-status.yaml: use a unique id.");
            }
            else if (matches[0].Value == "done")
            {
                problems.Add($"FR-48 trigger {trigger} is Pending(\"{story}\"), but {matches[0].Key} is done: add the test proving it ends access through RevokeAccess and make it Covered(\"<test>\").");
            }
        }

        return problems;
    }

    /// <summary>Covered entries whose test doesn't exist, isn't tagged with the entry's trigger, or is skipped.</summary>
    private static List<string> UnknownTests(IReadOnlyDictionary<string, Fr48Trigger> registry, IReadOnlyDictionary<string, TestFacts> tests)
    {
        var problems = new List<string>();
        foreach (var (trigger, coverage) in registry)
        {
            if (coverage is not Fr48Trigger.CoveredBy { Test: var test })
            {
                continue;
            }

            if (!tests.TryGetValue(test, out var facts))
            {
                problems.Add($"FR-48 trigger {trigger} is Covered(\"{test}\"), which isn't a [Fact] or [Theory] Class.Method in the Isolation or Architecture tests.");
            }
            else if (!facts.Fr48Traits.Contains(trigger, StringComparer.Ordinal))
            {
                problems.Add($"FR-48 trigger {trigger} is Covered(\"{test}\"), but that test has no [Trait(\"FR-48\", \"{trigger}\")]: tag it with its trigger.");
            }
            else if (facts.Skipped)
            {
                problems.Add($"FR-48 trigger {trigger} is Covered(\"{test}\"), but that test is skipped: a skipped test covers nothing.");
            }
        }

        return problems;
    }

    /// <summary>What the walk needs of one test: the values of its <c>FR-48</c> traits, and whether it's skipped.</summary>
    private sealed record TestFacts(IReadOnlyList<string> Fr48Traits, bool Skipped);
}
