using System.Net;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Canary;

/// <summary>
/// Story 7.8: every registered canary flow, run normally and forced to fail with Trace logging
/// on, leaves none of its canaries in any table, log, output stream or response (NFR-3, T-42).
/// </summary>
[Collection(Gatekeep.Tests.Isolation.Custody.OpenBaoCollection.Name)]
public sealed class CanaryFlowTests(PostgresFixture postgres, OffServer.ObjectLockFixture bucket, Gatekeep.Tests.Isolation.Custody.OpenBaoFixture bao) : IDisposable
{
    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000007b8");

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-canary-").FullName;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string, bool> Runs =>
        [.. CanaryFlows.All.SelectMany(f => new[] { (f.Name, false), (f.Name, true) })];

    [Theory]
    [MemberData(nameof(Runs))]
    public async Task Flow_leaves_no_canary_anywhere(string flow, bool failing)
    {
        var run = new FlowRun();
        using (var context = new CanaryFlowContext(postgres, _directory, bucket, bao))
        {
            await CanaryFlows.All.Single(f => f.Name == flow).RunAsync(context, run, failing);
        }

        Assert.NotEmpty(run.Canaries);
        Assert.Contains(run.Outputs, o => o.Text.Length > 0);

        var sources = run.Outputs.ToList();
        if (run.Database is { } database)
        {
            var tables = await DatabaseSourcesAsync(database);
            Assert.NotEmpty(tables);
            sources.AddRange(tables);
        }

        CanaryScanner.ThrowIfFound(CanaryScanner.Scan([.. run.Canaries, .. CanaryScanner.Canaries], sources));
    }

    [Fact]
    public void Flow_names_are_unique()
    {
        Assert.Equal(CanaryFlows.All.Count, CanaryFlows.All.Select(f => f.Name).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Raw_canary_in_a_flow_output_fails_and_names_the_source()
    {
        var run = new FlowRun();
        var canary = run.Plant("password-file");
        run.Capture("migrate stderr", $"Migration failed: {canary.Value}");
        run.Capture("migrate stdout", "No migrations to apply.");

        var failure = Assert.Throws<CanaryFoundException>(() => CanaryScanner.ThrowIfFound(CanaryScanner.Scan(run.Canaries, run.Outputs)));

        Assert.Equal(new CanaryFinding("password-file", "migrate stderr").ToString(), failure.Message);
        Assert.DoesNotContain(canary.Value, failure.ToString());
    }

    [Fact]
    public async Task Raw_canary_in_any_table_fails_and_names_the_table_and_column_kind()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var run = new FlowRun();
        var canary = run.Plant("job-credential");
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"CREATE TABLE canary_plant (note text); INSERT INTO canary_plant VALUES ('kept {canary.Value} raw')");

        var sources = await DatabaseSourcesAsync(database);

        var failure = Assert.Throws<CanaryFoundException>(() => CanaryScanner.ThrowIfFound(CanaryScanner.Scan(run.Canaries, sources)));
        Assert.Equal(new CanaryFinding("job-credential", "canary_plant.note (text)").ToString(), failure.Message);
        Assert.DoesNotContain(canary.Value, failure.ToString());
    }

    [Fact]
    public async Task Database_scan_reads_every_registered_table()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var tables = await CanaryScanner.TablesAsync(postgres.SuperuserConnection(database), Cancellation);

        Assert.Empty(TableRegistry.Tables.Select(t => t.Name).Except(tables));
        Assert.Empty(CanaryScanner.AuditTables.Except(tables));
    }

    [Theory]
    [InlineData("Bearer {0}", "Bearer [scrubbed]")]
    [InlineData("agent/1.0 Authorization: Bearer {0}", "agent/1.0 Authorization: [scrubbed]")]
    [InlineData("agent/1.0 (+https://example.test/?access_token={0}&x=1)", "agent/1.0 (+https://example.test/?access_token=[scrubbed]&x=1)")]
    [InlineData("Mozilla/5.0 (X11; Linux x86_64)", "Mozilla/5.0 (X11; Linux x86_64)")]
    public async Task User_Agent_is_stored_with_its_credential_shapes_masked(string userAgent, string stored)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA));
        var canary = new FlowRun().Plant("bearer-user-agent");
        var detail = new AuditDetail(IPAddress.Parse("192.0.2.9"), string.Format(null, userAgent, canary.Value), null);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        foreach (var tenantId in new Guid?[] { TenantA, null })
        {
            await using CommandScope scope = tenantId is { } id
                ? await TenantScope.BeginAsync(source, id, Cancellation)
                : await DeploymentScope.BeginAsync(source, Cancellation);
            await AuditContract.CreateAppender().AppendAsync(
                scope.CreateCommandContext(), new AuditEvent(new AuditTypeCode("tests.canary.appended"), Actor.Anonymous), detail, Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(stored, await PostgresFixture.ScalarAsync<string>(postgres.SuperuserConnection(database), "SELECT user_agent FROM audit_detail"));
        Assert.Equal(
            stored,
            await PostgresFixture.ScalarAsync<string>(postgres.SuperuserConnection(database), "SELECT user_agent FROM deployment_audit_detail"));
    }

    [Fact]
    public void Kernel_shapes_are_the_scrubbers_shapes()
    {
        const string text = "Password=hunter2-hunter2; Bearer abcdefghijklmnopqrst eyJa.eyJb.c";

        Assert.Equal(CredentialShapes.MaskShapes(text), Gatekeep.Adapters.Logging.Scrubber.Scrub(text, []));
        Assert.Equal(CredentialShapes.Mask, Gatekeep.Adapters.Logging.Scrubber.Mask);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private Task<IReadOnlyList<CanarySource>> DatabaseSourcesAsync(string database) =>
        CanaryScanner.DatabaseSourcesAsync(postgres.SuperuserConnection(database), Cancellation);
}
