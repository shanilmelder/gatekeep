using System.Diagnostics;

namespace Gatekeep.Tests.Isolation;

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
    ];

    public static Task<(int ExitCode, string Output)> RunAsync(params string[] arguments) =>
        RunWithEnvironmentAsync(new Dictionary<string, string>(), arguments);

    public static async Task<(int ExitCode, string Output)> RunWithEnvironmentAsync(
        IReadOnlyDictionary<string, string> environment,
        params string[] arguments)
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        var start = new ProcessStartInfo(string.IsNullOrEmpty(host) ? "dotnet" : host)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

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

        using var process = Process.Start(start)!;
        using var timeout = new CancellationTokenSource(CommandTimeout);

        try
        {
            var standardOutput = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var standardError = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);

            return (process.ExitCode, await standardOutput + await standardError);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
    }
}
