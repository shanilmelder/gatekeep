using System.Text.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

/// <summary>
/// The static seal on its own containers: it unseals from the credential file after a
/// restart with no one entering anything, and with the file absent the server doesn't start.
/// </summary>
public sealed class SealTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(60);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Server_without_a_key_file_fails_to_start()
    {
        await using var container = OpenBaoFixture.Build(generateKey: false).Build();
        await container.StartAsync(Cancellation);

        var exitCode = await ExitCodeAsync(container);
        var (stdout, stderr) = await container.GetLogsAsync(ct: Cancellation);

        Assert.NotEqual(0, exitCode);
        Assert.Contains("seal \"static\"", stdout + stderr);
        Assert.DoesNotContain("OpenBao server started", stdout + stderr);
    }

    [Fact]
    public async Task Restart_unseals_from_the_key_file_and_stops_when_the_file_is_gone()
    {
        // A volume, not a tmpfs, so the key survives the restart as the key volume would.
        await using var keyVolume = new VolumeBuilder().WithName("gatekeep-keys-" + Guid.NewGuid().ToString("N")).Build();
        await keyVolume.CreateAsync(Cancellation);
        await using var container = OpenBaoFixture.Build(generateKey: true, keyVolume)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilMessageIsLogged("OpenBao server started"))
            .Build();
        await container.StartAsync(Cancellation);

        var init = await container.ExecAsync(
            ["bao", "operator", "init", "-recovery-shares=1", "-recovery-threshold=1", "-format=json", $"-address={OpenBaoFixture.Socket}"],
            Cancellation);
        Assert.Equal(0, init.ExitCode);
        await UntilUnsealedAsync(container);

        await container.StopAsync(Cancellation);
        await container.StartAsync(Cancellation);
        await UntilUnsealedAsync(container);

        var removed = await container.ExecAsync(["rm", OpenBaoFixture.KeyFile], Cancellation);
        Assert.Equal(0, removed.ExitCode);
        await container.StopAsync(Cancellation);
        var since = DateTime.UtcNow;

        // The wait strategy sees the container exit, which is the outcome under test.
        await Assert.ThrowsAsync<ContainerNotRunningException>(() => container.StartAsync(Cancellation));

        Assert.NotEqual(0, await ExitCodeAsync(container));
        var (stdout, stderr) = await container.GetLogsAsync(since, ct: Cancellation);
        Assert.Contains("error reading file", stdout + stderr);
        Assert.DoesNotContain("OpenBao server started", stdout + stderr);
    }

    private static async Task UntilUnsealedAsync(IContainer container)
    {
        var until = DateTime.UtcNow + Deadline;
        while (DateTime.UtcNow < until)
        {
            var status = await container.ExecAsync(["bao", "status", "-format=json", $"-address={OpenBaoFixture.Socket}"], Cancellation);
            if (status.Stdout.Length > 0)
            {
                using var json = JsonDocument.Parse(status.Stdout);
                if (!json.RootElement.GetProperty("sealed").GetBoolean())
                {
                    Assert.Equal("raft", json.RootElement.GetProperty("storage_type").GetString());
                    return;
                }
            }

            await Task.Delay(500, Cancellation);
        }

        Assert.Fail("OpenBao didn't unseal.");
    }

    private static async Task<long> ExitCodeAsync(IContainer container)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        deadline.CancelAfter(Deadline);
        return await container.GetExitCodeAsync(deadline.Token);
    }
}
