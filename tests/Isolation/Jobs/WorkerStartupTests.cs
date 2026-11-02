using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Tests.Isolation.Hosting;
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
