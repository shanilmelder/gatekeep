using System.Diagnostics;
using Gatekeep.Adapters.Postgres.Schema;
using Xunit;

namespace Gatekeep.Tests.Isolation.Jobs;

/// <summary>Runs the real <c>Host.Worker</c> in its own process, from its own output folder.</summary>
public sealed class WorkerStartupTests(PostgresFixture postgres)
{
    private const string Canary = "canary-connection-value-91d2";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Worker_with_missing_connection_settings_refuses_naming_only_the_settings()
    {
        using var process = Start($"--ConnectionStrings:Dispatch=Host=localhost;Username=gk_dispatch;Password={Canary}");
        var output = process.StandardOutput.ReadToEndAsync(Cancellation);
        var error = process.StandardError.ReadToEndAsync(Cancellation);

        try
        {
            await process.WaitForExitAsync(Cancellation).WaitAsync(Timeout, Cancellation);
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        var text = await output + await error;

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
        string Setting(string name, string role) => $"--ConnectionStrings:{name}={postgres.RoleConnection(role, database)}";

        using var process = Start(
            Setting("Dispatch", TableRegistry.Dispatch),
            Setting("Worker", TableRegistry.Worker),
            Setting("Sealer", TableRegistry.Sealer),
            Setting("Retention", TableRegistry.Retention));
        _ = process.StandardOutput.ReadToEndAsync(Cancellation);
        _ = process.StandardError.ReadToEndAsync(Cancellation);

        try
        {
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
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    private static Process Start(params string[] arguments)
    {
        var worker = BuildOutput.AssemblyPath("Gatekeep.Host.Worker", "Gatekeep.Host.Worker");
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(worker)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(worker);
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var key in start.Environment.Keys.Where(k => k.StartsWith("ConnectionStrings", StringComparison.OrdinalIgnoreCase)).ToList())
        {
            start.Environment.Remove(key);
        }

        return Process.Start(start)!;
    }
}
