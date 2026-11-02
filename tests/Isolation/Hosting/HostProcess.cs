using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>Runs a real host in its own process, from its own output folder, and reads its output.</summary>
internal sealed class HostProcess : IDisposable
{
    private static readonly string[] ClearedEnvironment = ["ConnectionStrings", "Database__", "Custody__", "Gatekeep__", "ASPNETCORE_", "DOTNET_URLS"];

    private readonly Process _process;
    private readonly StringBuilder _output = new();
    private readonly StringBuilder _standardOutput = new();
    private readonly StringBuilder _standardError = new();
    private readonly Task _reading;

    private HostProcess(Process process)
    {
        _process = process;
        _reading = Task.WhenAll(Pump(process.StandardOutput, _standardOutput), Pump(process.StandardError, _standardError));
    }

    public bool HasExited => _process.HasExited;

    public int ExitCode => _process.ExitCode;

    /// <summary>
    /// Starts <paramref name="host"/> (<c>Hosted</c>, <c>Admin</c> or <c>Worker</c>). The secrets
    /// directory points at an empty folder unless an argument sets it, so a developer's own
    /// <c>/run/secrets</c> can't leak in.
    /// </summary>
    public static HostProcess Start(string host, params IEnumerable<string> arguments)
    {
        var project = $"Gatekeep.Host.{host}";
        var assembly = BuildOutput.AssemblyPath(project, project);
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(assembly)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(assembly);

        var list = arguments.ToList();
        if (!list.Any(a => a.StartsWith("--Gatekeep:SecretsDirectory=", StringComparison.Ordinal)))
        {
            list.Add($"--Gatekeep:SecretsDirectory={EmptyDirectory.Value}");
        }

        foreach (var argument in list)
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var key in start.Environment.Keys
            .Where(k => ClearedEnvironment.Any(p => k.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            .ToList())
        {
            start.Environment.Remove(key);
        }

        return new HostProcess(Process.Start(start)!);
    }

    /// <summary>Waits for the process to exit and returns everything it wrote.</summary>
    public async Task<string> WaitForExitAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            await _process.WaitForExitAsync(cancellationToken).WaitAsync(timeout, cancellationToken);
        }
        catch (TimeoutException)
        {
            Kill();
            throw;
        }

        await _reading;
        return Output;
    }

    public string Output
    {
        get
        {
            lock (_output)
            {
                return _output.ToString();
            }
        }
    }

    /// <summary>What the host wrote to standard output alone.</summary>
    public string StandardOutput
    {
        get
        {
            lock (_output)
            {
                return _standardOutput.ToString();
            }
        }
    }

    /// <summary>What the host wrote to standard error alone, where an unhandled exception goes.</summary>
    public string StandardError
    {
        get
        {
            lock (_output)
            {
                return _standardError.ToString();
            }
        }
    }

    /// <summary>Stops a running host and waits until everything it wrote has been read.</summary>
    public async Task StopAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        Kill();

        await _process.WaitForExitAsync(cancellationToken).WaitAsync(timeout, cancellationToken);
        await _reading.WaitAsync(timeout, cancellationToken);
    }

    /// <summary>GETs <paramref name="path"/> on <paramref name="port"/>, retrying until the host listens.</summary>
    public async Task<(HttpStatusCode Status, string Body)> GetAsync(int port, string path, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            if (_process.HasExited)
            {
                throw new InvalidOperationException($"The host exited with {_process.ExitCode}: {Output}");
            }

            try
            {
                using var response = await http.GetAsync(new Uri($"http://127.0.0.1:{port}{path}"), cancellationToken);
                return (response.StatusCode, await response.Content.ReadAsStringAsync(cancellationToken));
            }
            catch (HttpRequestException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken);
            }
        }
    }

    public void Dispose()
    {
        Kill();

        _process.Dispose();
    }

    /// <summary>Kills the host if it's running. It may exit between the check and the kill, which is fine.</summary>
    private void Kill()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }

    /// <summary>A port free right now. Another process could take it first, which is rare enough here.</summary>
    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private async Task Pump(StreamReader reader, StringBuilder stream)
    {
        var buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer)) > 0)
        {
            lock (_output)
            {
                _output.Append(buffer, 0, read);
                stream.Append(buffer, 0, read);
            }
        }
    }

    private static readonly Lazy<string> EmptyDirectory = new(() => Directory.CreateTempSubdirectory("gatekeep-no-secrets-").FullName);
}
