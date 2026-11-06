using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Tests.Isolation.Audit;
using Gatekeep.Tests.Isolation.Hosting;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Jobs;

/// <summary>
/// Runs the real <c>Host.Worker</c> in its own process, from its own output folder. Ambient
/// <c>ConnectionStrings</c>, <c>Database</c>, <c>Custody</c> and <c>Gatekeep</c> settings are
/// cleared, and the secrets directory is an empty folder, so nothing outside the test leaks in.
/// </summary>
public sealed class WorkerStartupTests(PostgresFixture postgres) : IDisposable
{
    private const string Canary = "canary-connection-value-91d2";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static readonly Guid TenantId = Guid.Parse("01900000-0000-7000-8000-0000000002a1");

    private const string SealLoopStarted = "Audit seal loop started.";

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-worker-").FullName;
    private readonly FakeOpenBaoSocket _openBao = new();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Worker_with_missing_connection_settings_refuses_naming_only_the_settings()
    {
        using var process = HostProcess.Start(
            "Worker",
            Custody()
                .Append($"--ConnectionStrings:Dispatch=Host=localhost;Username=gk_dispatch;Password={Canary}")
                .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var text = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("refuses to start", text);
        Assert.Contains("ConnectionStrings:Worker", text);
        Assert.Contains("ConnectionStrings:Sealer", text);
        Assert.Contains("ConnectionStrings:Retention", text);
        Assert.DoesNotContain("ConnectionStrings:Dispatch", text);
        Assert.DoesNotContain(Canary, text);

        // The harness gives the alert channel and bucket valid settings (Story 1.30), so only the
        // connections are named; HostStartupTests refuses each of those settings in turn.
        Assert.DoesNotContain("Alerts:", text);
        Assert.DoesNotContain("Records:", text);
    }

    [Fact]
    public async Task Worker_with_an_unsafe_bucket_setting_refuses_beside_its_missing_connections()
    {
        using var process = HostProcess.Start(
            "Worker",
            Custody()
                .Append($"--ConnectionStrings:Dispatch=Host=localhost;Username=gk_dispatch;Password={Canary}")
                .Append("--Records:Endpoint=http://objects.invalid")
                .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var text = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("ConnectionStrings:Worker", text);
        Assert.Contains("Records:Endpoint", text);
        Assert.DoesNotContain("Alerts:", text);
        Assert.DoesNotContain(Canary, text);
    }

    [Fact]
    public async Task Configured_worker_enqueues_the_purge_and_runs_it_to_done()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        using var process = HostProcess.Start("Worker", Configured(database));

        var deadline = DateTimeOffset.UtcNow + Timeout;
        var done = 0L;
        while (done == 0 && !process.HasExited && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), Cancellation);
            done = await PostgresFixture.ScalarAsync<long>(
                postgres.SuperuserConnection(database),
                "SELECT count(*) FROM job WHERE type = 'operations.job.purge' AND deployment_wide AND status = 'done'");
        }

        Assert.False(process.HasExited, "Host.Worker stopped instead of running.");
        Assert.Equal(1L, done);
    }

    [Fact]
    public async Task Configured_worker_enqueues_the_key_backfill_and_runs_it_to_done()
    {
        // No Tenant yet, so the hourly backfill (Story 2.3) runs with custody and finds nothing to do.
        var database = await postgres.NewMigratedDatabaseAsync();

        using var process = HostProcess.Start("Worker", Configured(database));

        var deadline = DateTimeOffset.UtcNow + Timeout;
        var done = 0L;
        while (done == 0 && !process.HasExited && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), Cancellation);
            done = await PostgresFixture.ScalarAsync<long>(
                postgres.SuperuserConnection(database),
                "SELECT count(*) FROM job WHERE type = 'keys.tenant_keys.backfill' AND deployment_wide AND status = 'done'");
        }

        Assert.False(process.HasExited, "Host.Worker stopped instead of running.");
        Assert.Equal(1L, done);
    }

    [Fact]
    public async Task Configured_worker_enqueues_the_key_rotation_and_orphan_sweep_and_runs_both_to_done()
    {
        // Story 2.4: no Tenant yet, so the rotation finds nothing; the sweep lists an empty mount
        // (OpenBao answers 404) and deletes nothing.
        _openBao.Respond = path => path.Contains("/auth/", StringComparison.Ordinal)
            ? (200, """{"auth":{"client_token":"fake-token","lease_duration":900}}""")
            : (404, """{"errors":[]}""");
        var database = await postgres.NewMigratedDatabaseAsync();

        using var process = HostProcess.Start("Worker", Configured(database));

        const string Done =
            "SELECT count(DISTINCT type) FROM job WHERE type IN ('keys.signing_keys.rotate', 'keys.transit_keys.sweep') AND deployment_wide AND status = 'done'";
        var deadline = DateTimeOffset.UtcNow + Timeout;
        var done = 0L;
        while (done < 2 && !process.HasExited && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), Cancellation);
            done = await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), Done);
        }

        Assert.False(process.HasExited, "Host.Worker stopped instead of running.");
        Assert.Equal(2L, done);
    }

    [Fact]
    public async Task Configured_worker_hands_its_key_custody_to_the_job_runner()
    {
        // No production job type carries a credential yet, so the runner says at start
        // whether it has custody. Without it a credential job would fail with custody_failed.
        var database = await postgres.NewMigratedDatabaseAsync();

        using var process = HostProcess.Start("Worker", Configured(database));

        var deadline = DateTimeOffset.UtcNow + Timeout;
        while (!process.Output.Contains("Job runner started", StringComparison.Ordinal)
            && !process.HasExited
            && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), Cancellation);
        }

        Assert.Contains("Job runner started with key custody.", process.Output);
        Assert.DoesNotContain("without key custody", process.Output);
    }

    [Fact]
    public async Task Configured_worker_seals_an_appended_event_within_5_seconds()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantId));

        using var process = HostProcess.Start("Worker", Configured(database));

        // Startup isn't part of the 5 seconds: the clock starts once the seal loop says it has begun.
        var started = DateTimeOffset.UtcNow + Timeout;
        while (!process.Output.Contains(SealLoopStarted, StringComparison.Ordinal)
            && !process.HasExited
            && DateTimeOffset.UtcNow < started)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100), Cancellation);
        }

        Assert.False(process.HasExited, "Host.Worker stopped instead of running.");
        Assert.Contains(SealLoopStarted, process.Output);

        await using (var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database)))
        await using (var scope = await TenantScope.BeginAsync(source, TenantId, Cancellation))
        {
            await AuditContract.CreateAppender().AppendAsync(
                scope.CreateCommandContext(),
                new AuditEvent(new AuditTypeCode("tenancy.settings.updated"), Actor.System, AuditTargetKind.Tenant, TenantId),
                detail: null,
                Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        var rows = new List<SealedRow>();
        while (rows.Count == 0 && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100), Cancellation);
            rows = await ChainCheck.ReadAsync(postgres.SuperuserConnection(database), TenantId);
        }

        var row = Assert.Single(rows);
        ChainCheck.AssertLinked(rows);
        Assert.Equal(1, row.Envelope.Epoch);
        Assert.Equal(1, row.Envelope.Seq);
    }

    [Fact]
    public async Task Configured_worker_sweeps_one_retention_job_into_each_Tenant_and_cuts_as_gk_retention()
    {
        var chains = await AuditChains.CreateAsync(postgres, AuditChains.TenantA, AuditChains.TenantB);
        await chains.SealedChainAsync(AuditChains.TenantA, 3, 1, 2);
        await chains.SealedChainAsync(AuditChains.TenantB, 1);

        using var process = HostProcess.Start("Worker", Configured(chains.Name));

        const string ApplyJobs = "FROM job WHERE type = 'audit.retention.apply' AND status = 'done'";
        var deadline = DateTimeOffset.UtcNow + Timeout;
        while (await chains.ScalarAsync<long>($"SELECT count(DISTINCT tenant_id) {ApplyJobs}") < 2
            && !process.HasExited
            && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), Cancellation);
        }

        Assert.False(process.HasExited, "Host.Worker stopped instead of running.");
        Assert.Equal(
            $"{AuditChains.TenantA}|1,{AuditChains.TenantB}|1",
            await chains.ScalarAsync<string>(
                $"SELECT string_agg(tenant_id || '|' || n, ',' ORDER BY tenant_id) FROM (SELECT tenant_id, count(*) AS n FROM job WHERE type = 'audit.retention.apply' GROUP BY tenant_id) j"));
        Assert.Equal(
            "done",
            await chains.ScalarAsync<string>("SELECT status FROM job WHERE type = 'audit.retention.sweep'"));

        // Only gk_retention can delete an event or write a checkpoint, so the cut shows the role it ran as.
        Assert.Equal(1, await chains.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{AuditEvents.RetentionCheckpoint.Code.Value}'"));
        Assert.DoesNotContain(1L, await chains.SeqsAsync(AuditChains.TenantA));
        Assert.DoesNotContain(2L, await chains.SeqsAsync(AuditChains.TenantA));
    }

    [Fact]
    public async Task Configured_worker_runs_the_scheduled_Deployment_retention_to_done_and_writes_a_checkpoint()
    {
        var chains = await AuditChains.CreateAsync(postgres);
        await chains.SealedChainAsync(tenantId: null, 3, 1, 2);

        using var process = HostProcess.Start("Worker", Configured(chains.Name));

        var deadline = DateTimeOffset.UtcNow + Timeout;
        while (await chains.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'audit.retention.deployment' AND status = 'done'") == 0
            && !process.HasExited
            && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), Cancellation);
        }

        Assert.False(process.HasExited, "Host.Worker stopped instead of running.");
        Assert.Equal(1L, await chains.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'audit.retention.deployment' AND status = 'done'"));
        Assert.Equal(
            "1|2",
            await chains.ScalarAsync<string>(
                $"SELECT checkpoint_epoch || '|' || checkpoint_seq FROM deployment_audit_event WHERE type_code = '{AuditEvents.RetentionCheckpoint.Code.Value}'"));
        Assert.DoesNotContain(1L, await chains.SeqsAsync(null));
        Assert.DoesNotContain(2L, await chains.SeqsAsync(null));
    }

    public void Dispose()
    {
        _openBao.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private IEnumerable<string> Configured(string database)
    {
        string Setting(string name, string role) => $"--ConnectionStrings:{name}={postgres.RoleConnection(role, database)}";

        return Custody()
            .Append(Setting("Dispatch", TableRegistry.Dispatch))
            .Append(Setting("Worker", TableRegistry.Worker))
            .Append(Setting("Sealer", TableRegistry.Sealer))
            .Append(Setting("Retention", TableRegistry.Retention))
            .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}");
    }

    private IEnumerable<string> Custody()
    {
        var roleId = Path.Combine(_directory, "role-id-" + Guid.NewGuid().ToString("N"));
        var secretId = Path.Combine(_directory, "secret-id-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(roleId, Guid.NewGuid().ToString());
        File.WriteAllText(secretId, Guid.NewGuid().ToString());

        return
        [
            $"--Custody:SocketPath={_openBao.Path}",
            $"--Custody:RoleIdFile={roleId}",
            $"--Custody:SecretIdFile={secretId}",
        ];
    }
}
