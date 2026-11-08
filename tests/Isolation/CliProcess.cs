using System.Diagnostics;

namespace Gatekeep.Tests.Isolation;

/// <summary>What one Cli run wrote to each stream, and its exit code.</summary>
internal sealed record CliResult(int ExitCode, string StandardOutput, string StandardError);

/// <summary>Runs the real <c>gatekeep</c> Cli in its own process, from its own output folder.</summary>
internal static class CliProcess
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(1);

    /// <summary>The variables the <c>cli</c> Compose service sets, cleared so nothing outside the test leaks in.</summary>
    private static readonly string[] AmbientVariables =
    [
        "GATEKEEP_MIGRATE_CONNECTION_FILE",
        "GATEKEEP_MIGRATE_PASSWORD_FILE",
        "GATEKEEP_CLI_CONNECTION_FILE",
        "GATEKEEP_CLI_PASSWORD_FILE",
        "GATEKEEP_CUSTODY_SOCKET",
        "GATEKEEP_CUSTODY_ROLE_ID_FILE",
        "GATEKEEP_CUSTODY_SECRET_ID_FILE",
        "GATEKEEP_ALERT_URL",
        "GATEKEEP_ALERT_TOKEN_FILE",
        "GATEKEEP_ALERT_DEPLOYMENT",
        "GATEKEEP_RECORDS_ENDPOINT",
        "GATEKEEP_RECORDS_REGION",
        "GATEKEEP_RECORDS_BUCKET",
        "GATEKEEP_RECORDS_ACCESS_KEY_ID_FILE",
        "GATEKEEP_RECORDS_SECRET_ACCESS_KEY_FILE",
        "GATEKEEP_AUDIT_LOG_FILE",
        "GATEKEEP_AUDIT_SHIP_STATE_DIR",
    ];

    public static Task<(int ExitCode, string Output)> RunAsync(params string[] arguments) =>
        RunWithEnvironmentAsync(new Dictionary<string, string>(), arguments);

    public static async Task<(int ExitCode, string Output)> RunWithEnvironmentAsync(
        IReadOnlyDictionary<string, string> environment,
        params string[] arguments)
    {
        var result = await RunCapturedAsync(environment, arguments);
        return (result.ExitCode, result.StandardOutput + result.StandardError);
    }

    /// <summary>Like <see cref="RunWithEnvironmentAsync"/>, with standard output and error kept apart.</summary>
    public static Task<CliResult> RunCapturedAsync(
        IReadOnlyDictionary<string, string> environment,
        params string[] arguments) =>
        Start(environment, uid: null, arguments).CompletedAsync();

    /// <summary>
    /// Starts the Cli without waiting, as root or, through <c>setpriv</c>, as <paramref name="uid"/>
    /// with the same group and no others, as the <c>cli</c> service runs it. <c>setpriv</c> execs
    /// the Cli, so the process ID is the Cli's, and a signal sent to it reaches the Cli.
    /// </summary>
    public static RunningCli Start(IReadOnlyDictionary<string, string> environment, int? uid, params string[] arguments)
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        var dotnet = string.IsNullOrEmpty(host) ? "dotnet" : host;
        var start = new ProcessStartInfo(uid is null ? dotnet : "setpriv")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        if (uid is { } id)
        {
            start.ArgumentList.Add($"--reuid={id}");
            start.ArgumentList.Add($"--regid={id}");
            start.ArgumentList.Add("--clear-groups");
            start.ArgumentList.Add(dotnet);
            start.Environment["HOME"] = Path.GetTempPath();
        }

        foreach (var name in AmbientVariables)
        {
            start.Environment.Remove(name);
        }

        foreach (var (name, value) in environment)
        {
            start.Environment[name] = value;
        }

        start.ArgumentList.Add(BuildOutput.AssemblyPath("Gatekeep.Cli", "gatekeep"));
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        return new RunningCli(Process.Start(start)!, CommandTimeout);
    }
}

/// <summary>One Cli process, its streams read as it runs.</summary>
internal sealed class RunningCli
{
    private readonly Process _process;
    private readonly CancellationTokenSource _timeout;
    private readonly Task<string> _standardOutput;
    private readonly Task<string> _standardError;

    public RunningCli(Process process, TimeSpan timeout)
    {
        _process = process;
        _timeout = new CancellationTokenSource(timeout);
        _standardOutput = process.StandardOutput.ReadToEndAsync(_timeout.Token);
        _standardError = process.StandardError.ReadToEndAsync(_timeout.Token);
    }

    public int Id => _process.Id;

    public async Task<CliResult> CompletedAsync()
    {
        try
        {
            await _process.WaitForExitAsync(_timeout.Token);
            return new CliResult(_process.ExitCode, await _standardOutput, await _standardError);
        }
        catch (OperationCanceledException)
        {
            _process.Kill(entireProcessTree: true);
            throw;
        }
        finally
        {
            _process.Dispose();
            _timeout.Dispose();
        }
    }
}
