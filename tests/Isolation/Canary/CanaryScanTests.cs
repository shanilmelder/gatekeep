using System.Net;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Canary;

public sealed class CanaryScanTests(PostgresFixture postgres)
{
    private const string LogSource = "console log";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");
    private static readonly Guid PlantedEvent = Guid.Parse("01900000-0000-7000-8000-0000000000f1");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> CanaryKinds => [.. CanaryScanner.Canaries.Select(c => c.Kind)];

    [Fact]
    public async Task Canaries_sent_as_designed_are_found_nowhere()
    {
        var database = await TenantDatabaseAsync();
        await AppendThroughTheAppenderAsync(database);

        var captured = new CapturedConsole();
        using (var logging = CapturedLogging.Create(captured))
        {
            var logger = logging.GetRequiredService<ILoggerFactory>().CreateLogger("Canary");
            foreach (var canary in CanaryScanner.Canaries)
            {
                SendThroughTheSink(logger, canary);
            }
        }

        Assert.NotEmpty(captured.Text);
        var auditSources = await AuditSourcesAsync(database);
        Assert.Equal(
            CanaryScanner.AuditTables.Order(),
            auditSources.Select(s => s.Name.Split('.')[0]).Distinct().Order());

        var findings = CanaryScanner.Scan(
            CanaryScanner.Canaries,
            auditSources.Append(new CanarySource(LogSource, captured.Text)));

        CanaryScanner.ThrowIfFound(findings);
    }

    [Theory]
    [MemberData(nameof(CanaryKinds))]
    public void Canary_written_straight_to_the_output_fails_and_names_the_source(string kind)
    {
        var canary = CanaryScanner.Canaries.Single(c => c.Kind == kind);
        var captured = new CapturedConsole();

        captured.Plant(canary.InShape);

        var failure = Assert.Throws<CanaryFoundException>(() => CanaryScanner.ThrowIfFound(
            CanaryScanner.Scan(CanaryScanner.Canaries, [new CanarySource(LogSource, captured.Text)])));

        Assert.Equal(new CanaryFinding(kind, LogSource).ToString(), failure.Message);
        Assert.DoesNotContain(canary.Value, failure.ToString());
    }

    [Theory]
    [InlineData("audit_detail", "audit_detail.user_agent (text)")]
    [InlineData("deployment_audit_detail", "deployment_audit_detail.user_agent (text)")]
    public async Task Canary_planted_in_detail_fails_and_names_the_table_and_column_kind(string table, string source)
    {
        var canary = CanaryScanner.Canaries.Single(c => c.Kind == "private-key");
        var database = await TenantDatabaseAsync();
        await PlantInDetailAsync(database, table, canary.InShape);

        var sources = await AuditSourcesAsync(database);

        var failure = Assert.Throws<CanaryFoundException>(
            () => CanaryScanner.ThrowIfFound(CanaryScanner.Scan(CanaryScanner.Canaries, sources)));

        Assert.Equal(new CanaryFinding(canary.Kind, source).ToString(), failure.Message);
        Assert.DoesNotContain(canary.Value, failure.ToString());
    }

    [Fact]
    public void New_canary_or_source_needs_only_a_new_entry()
    {
        Canary[] canaries = [.. CanaryScanner.Canaries, new("later-story", "cnry-later", "cnry-later")];
        CanarySource[] sources = [new("later-table", "row with cnry-later"), new("clean-table", "row")];

        var finding = Assert.Single(CanaryScanner.Scan(canaries, sources));

        Assert.Equal(new CanaryFinding("later-story", "later-table"), finding);
    }

    [Fact]
    public void Scanner_reads_every_audit_table_in_the_registry()
    {
        var registered = TableRegistry.Tables.Select(t => t.Name).Where(n => n.Contains("audit", StringComparison.Ordinal));

        Assert.Equal(registered.Order(), CanaryScanner.AuditTables.Order());
    }

    [Fact]
    public void Console_capture_sees_what_the_sink_receives()
    {
        var captured = new CapturedConsole();
        using (var logging = CapturedLogging.Create(captured))
        {
            logging.GetRequiredService<ILoggerFactory>().CreateLogger("Canary").LogInformation("Started {Host}", "gatekeep");
        }

        Assert.Contains("Started gatekeep", captured.Text);
    }

    /// <summary>Every path a value could take to a log, none of which may print it.</summary>
    private static void SendThroughTheSink(ILogger logger, Canary canary)
    {
        logger.LogInformation("{Password}", canary.Value);
        logger.LogInformation("{S}", new Secret<string>(canary.Value));
        logger.LogInformation("{Detail}", canary.InShape);
        logger.LogError(new InvalidOperationException(canary.InShape), "Failed");

        using (logger.BeginScope(canary.Value))
        {
            logger.LogInformation("Inside a scope");
        }
    }

    /// <summary>A secret reaches a detail only through its printed form, which is the mask.</summary>
    private async Task AppendThroughTheAppenderAsync(string database)
    {
        var appender = AuditContract.CreateAppender();
        await using var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));

        foreach (var canary in CanaryScanner.Canaries)
        {
            var detail = new AuditDetail(
                IPAddress.Parse("192.0.2.1"), $"Agent {new Secret<string>(canary.Value)}", "person@example.test");
            var auditEvent = new AuditEvent(new AuditTypeCode("a.b.c"), Actor.System);

            await using (var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation))
            {
                await appender.AppendAsync(scope.CreateCommandContext(), auditEvent, detail, Cancellation);
                await scope.CommitAsync(Cancellation);
            }

            await using (var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation))
            {
                await appender.AppendAsync(scope.CreateCommandContext(), auditEvent, detail, Cancellation);
                await scope.CommitAsync(Cancellation);
            }
        }
    }

    /// <summary>Bypasses the appender, as a bug would.</summary>
    private async Task PlantInDetailAsync(string database, string table, string value)
    {
        var (insertEvent, insertDetail) = table == "audit_detail"
            ? ($"INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{TenantA}', '{PlantedEvent}', 'a.b.c', 'system')",
                $"INSERT INTO audit_detail (tenant_id, event_id, user_agent) VALUES ('{TenantA}', '{PlantedEvent}', @value)")
            : ($"INSERT INTO deployment_audit_event (id, type_code, actor_kind) VALUES ('{PlantedEvent}', 'a.b.c', 'system')",
                $"INSERT INTO deployment_audit_detail (event_id, user_agent) VALUES ('{PlantedEvent}', @value)");

        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), insertEvent);

        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(insertDetail, connection);
        command.Parameters.AddWithValue("value", value);
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    private async Task<string> TenantDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA));
        return database;
    }

    private Task<IReadOnlyList<CanarySource>> AuditSourcesAsync(string database) =>
        CanaryScanner.AuditSourcesAsync(postgres.SuperuserConnection(database), Cancellation);
}
