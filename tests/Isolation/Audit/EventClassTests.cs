using System.Text.RegularExpressions;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Npgsql;
using Gatekeep.Tests.Architecture;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// Story 7.8 and FR-40: each of the 11 Tenant Log classes is proved by a catalogued code, whose
/// flow a test runs and whose code it finds in the Tenant's Log, or is pending on a story that
/// exists in <c>sprint-status.yaml</c> and isn't done. A pending class whose story is done fails.
/// </summary>
public sealed class EventClassTests(PostgresFixture postgres)
{
    private const string Project = "tests/Isolation";
    private const string SprintStatus = "_bmad-output/implementation-artifacts/sprint-status.yaml";

    private static readonly Regex StatusLine = new(@"^  (?<key>[0-9][\w-]*):\s*(?<status>[\w-]+)\s*$", RegexOptions.Multiline | RegexOptions.Compiled);

    /// <summary>
    /// The flow that proves each mapped class: it runs the flow in a fresh database and returns the
    /// database and the Tenant whose Log must hold the class's code. A story that maps a class to a
    /// code adds its proof here, and removes the class's pending story in <see cref="AuditCatalogue"/>.
    /// </summary>
    private static readonly Dictionary<TenantLogClass, Func<PostgresFixture, Task<(string Database, Guid TenantId)>>> Proofs = new()
    {
        [TenantLogClass.SessionRevocation] = ProveSessionRevocationAsync,
    };

    [Fact]
    public void Every_class_is_proved_by_a_catalogued_code_or_pending_on_a_story()
    {
        Assert.Empty(ClassProblems(AuditCatalogue.TenantLogClasses, Catalogue(), Proofs.Keys.Select(k => k.ToString())));
    }

    [Fact]
    public void Every_pending_story_exists_and_isnt_done()
    {
        Assert.Empty(PendingProblems(AuditCatalogue.TenantLogClasses, Statuses(File.ReadAllText(Path.Combine(BuildOutput.RepositoryRoot(), SprintStatus)))));
    }

    [Fact]
    public void The_two_classes_the_story_names_are_pending_on_16_8_and_17_2()
    {
        Assert.Equal("16.8", AuditCatalogue.TenantLogClasses.Single(c => c.Name == nameof(TenantLogClass.EmailChange)).PendingStory);
        Assert.Equal("17.2", AuditCatalogue.TenantLogClasses.Single(c => c.Name == nameof(TenantLogClass.ManagementApiGrant)).PendingStory);
    }

    [Fact]
    public async Task Each_proved_class_has_its_code_in_the_Tenants_Log()
    {
        var catalogue = Catalogue();

        foreach (var (logClass, prove) in Proofs)
        {
            var codes = catalogue.Where(e => e.TenantLogClass == logClass.ToString()).Select(e => e.Code).ToList();
            Assert.NotEmpty(codes);

            var (database, tenantId) = await prove(postgres);
            var written = await PostgresFixture.ScalarAsync<long>(
                postgres.SuperuserConnection(database),
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenantId}' AND type_code IN ({string.Join(", ", codes.Select(c => $"'{c}'"))})");

            Assert.True(written > 0, $"{logClass}'s flow wrote none of {string.Join(", ", codes)} to the Tenant's Log.");
        }
    }

    [Fact]
    public void Pending_class_whose_story_is_done_is_reported()
    {
        LogClass[] classes = [new("EmailChange", "Email changes", "16.8")];

        var problem = Assert.Single(PendingProblems(classes, new Dictionary<string, string> { ["16-8-change-an-email-address-safely"] = "done" }));

        Assert.Equal("Email changes is pending on Story 16.8, which is done: map the class to its code or name the story that will.", problem);
    }

    [Fact]
    public void Pending_class_whose_story_is_missing_is_reported()
    {
        LogClass[] classes = [new("EmailChange", "Email changes", "16.99")];

        var problem = Assert.Single(PendingProblems(classes, new Dictionary<string, string> { ["16-8-change-an-email-address-safely"] = "backlog" }));

        Assert.Equal("Email changes is pending on Story 16.99, which isn't in sprint-status.yaml.", problem);
    }

    [Fact]
    public void Class_with_no_code_and_no_story_is_reported()
    {
        LogClass[] classes = [new("SignIn", "Sign-ins and failures", null)];

        var problem = Assert.Single(ClassProblems(classes, [], []));

        Assert.Equal("Sign-ins and failures has no catalogued code and no pending story.", problem);
    }

    [Fact]
    public void Class_both_mapped_and_pending_or_mapped_with_no_proof_is_reported()
    {
        LogClass[] classes = [new("SignIn", "Sign-ins and failures", "4.9")];
        CatalogueEvent[] events = [new("auth.signin.succeeded", "Authentication", "A User signed in.", "SignIn")];

        var problems = ClassProblems(classes, events, []);

        Assert.Equal(
            new[]
            {
                "Sign-ins and failures is mapped to auth.signin.succeeded and still pending on Story 4.9: remove the pending story.",
                "Sign-ins and failures is mapped to auth.signin.succeeded but no test proves it: add its flow to EventClassTests.Proofs.",
            },
            problems);
    }

    [Fact]
    public void Sprint_status_lines_are_read()
    {
        var statuses = Statuses(
            """
            development_status:
              epic-16: backlog
              16-8-change-an-email-address-safely: backlog
              7-3-verify-chains-and-apply-retention: done
              epic-7-retrospective: optional
            """);

        Assert.Equal("backlog", statuses["16-8-change-an-email-address-safely"]);
        Assert.Equal("done", statuses["7-3-verify-chains-and-apply-retention"]);
        Assert.DoesNotContain("epic-16", statuses.Keys);
    }

    private static IReadOnlyList<CatalogueEvent> Catalogue() => AuditCatalogue.Load(BuildOutput.RepositoryRoot(), Project);

    private static List<string> ClassProblems(
        IEnumerable<LogClass> classes,
        IReadOnlyList<CatalogueEvent> events,
        IEnumerable<string> proved)
    {
        var proofs = proved.ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();

        foreach (var logClass in classes)
        {
            var codes = events.Where(e => e.TenantLogClass == logClass.Name).Select(e => e.Code).ToList();
            var mapped = string.Join(", ", codes);

            if (codes.Count == 0 && logClass.PendingStory is null)
            {
                problems.Add($"{logClass.Title} has no catalogued code and no pending story.");
            }

            if (codes.Count > 0 && logClass.PendingStory is { } story)
            {
                problems.Add($"{logClass.Title} is mapped to {mapped} and still pending on Story {story}: remove the pending story.");
            }

            if (codes.Count > 0 && !proofs.Contains(logClass.Name))
            {
                problems.Add($"{logClass.Title} is mapped to {mapped} but no test proves it: add its flow to EventClassTests.Proofs.");
            }
        }

        return problems;
    }

    /// <summary>Each pending story must be a story key in the sprint status, and not <c>done</c>.</summary>
    private static List<string> PendingProblems(IEnumerable<LogClass> classes, IReadOnlyDictionary<string, string> statuses)
    {
        var problems = new List<string>();

        foreach (var logClass in classes)
        {
            if (logClass.PendingStory is not { } story)
            {
                continue;
            }

            var prefix = story.Replace('.', '-') + "-";
            var matches = statuses.Where(s => s.Key.StartsWith(prefix, StringComparison.Ordinal)).ToList();

            if (matches.Count != 1)
            {
                problems.Add($"{logClass.Title} is pending on Story {story}, which isn't in sprint-status.yaml.");
            }
            else if (matches[0].Value == "done")
            {
                problems.Add($"{logClass.Title} is pending on Story {story}, which is done: map the class to its code or name the story that will.");
            }
        }

        return problems;
    }

    /// <summary>Story keys, such as <c>16-8-change-an-email-address-safely</c>, and their status. Epics and retrospectives aren't stories.</summary>
    private static Dictionary<string, string> Statuses(string yaml) =>
        StatusLine.Matches(yaml.ReplaceLineEndings("\n"))
            .Where(m => Regex.IsMatch(m.Groups["key"].Value, @"\A\d+-\d+-"))
            .ToDictionary(m => m.Groups["key"].Value, m => m.Groups["status"].Value, StringComparer.Ordinal);

    /// <summary>Story 2.7: a Tenant-scope <c>RevokeAccessAsync</c> as <c>gk_hosted</c> writes <c>sessions.access.revoked</c>.</summary>
    private static async Task<(string Database, Guid TenantId)> ProveSessionRevocationAsync(PostgresFixture postgres)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenantId = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(tenantId));

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, CancellationToken.None);
        var sessions = SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System);

        await sessions.RevokeAccessAsync(
            scope.CreateCommandContext(),
            new RevocationScope.Tenant(),
            exceptSessionId: null,
            RevocationReason.AdminRevoke,
            Actor.System,
            CancellationToken.None);
        await scope.CommitAsync(CancellationToken.None);

        return (database, tenantId);
    }
}
