using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>Runs a real host in its own process, from its own output folder, and reads its output.</summary>
internal sealed class HostProcess : IDisposable
{
    /// <summary>The Admin origin a started Host.Admin has unless a test names another.</summary>
    public const string AdminOrigin = "https://admin.gatekeep-admin.test";

    /// <summary>The Tenant zone a started Host.Admin has unless a test names another (Story 1.27).</summary>
    public const string TenantZone = "gatekeep.test";

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

        // Host.Admin needs its browser origin (Story 1.21). A test that names one, even empty, keeps its own.
        if (host == "Admin" && !list.Any(a => a.StartsWith("--Gatekeep:PublicOrigin=", StringComparison.Ordinal)))
        {
            list.Add($"--Gatekeep:PublicOrigin={AdminOrigin}");
        }

        // And its Tenant zone (Story 1.27), outside which its own origin sits. A test may name another.
        if (host == "Admin" && !list.Any(a => a.StartsWith("--Gatekeep:TenantZone=", StringComparison.Ordinal)))
        {
            list.Add($"--Gatekeep:TenantZone={TenantZone}");
        }

        // And to be told who forwards to it: no proxy, unless a test names a network, or empty.
        if (host == "Admin" && !list.Any(a => a.StartsWith("--Gatekeep:ForwardedBy=", StringComparison.Ordinal)))
        {
            list.Add("--Gatekeep:ForwardedBy=none");
        }

        // Host.Worker needs the alert channel and the bucket (Story 1.30): valid settings, unless a
        // test names one, even empty. Nothing is sent to them at startup.
        if (host == "Worker")
        {
            foreach (var (name, value) in OffServerDefaults.Value)
            {
                if (!list.Any(a => a.StartsWith($"--{name}=", StringComparison.Ordinal)))
                {
                    list.Add($"--{name}={value}");
                }
            }
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

    /// <summary>
    /// A port free right now on every address, as the hosts' public <c>[::]</c> listener needs: a
    /// loopback-only probe can return a port an outgoing connection (such as to Postgres) holds on
    /// another address. Another process could still take it first, which is rare enough here.
    /// </summary>
    public static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.IPv6Any, 0);
        listener.Server.DualMode = true;
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

    /// <summary>
    /// Valid alert and bucket settings for Host.Worker (Story 1.30), under <c>.invalid</c> names that
    /// never resolve, with secret files of random values made once for the run.
    /// </summary>
    public static readonly Lazy<IReadOnlyList<(string Name, string Value)>> OffServerDefaults = new(() =>
    {
        var directory = Directory.CreateTempSubdirectory("gatekeep-offserver-").FullName;
        string Secret(string name)
        {
            var path = Path.Combine(directory, name);
            File.WriteAllText(path, Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)) + "\n");
            return path;
        }

        return
        [
            ("Alerts:Url", "https://alerts.invalid/gatekeep"),
            ("Alerts:TokenFile", Secret("alert-token")),
            ("Alerts:Deployment", "admin.gatekeep-admin.test"),
            ("Records:Endpoint", "https://objects.invalid"),
            ("Records:Region", "us-east-1"),
            ("Records:Bucket", "gatekeep-records"),
            ("Records:AccessKeyIdFile", Secret("access-key-id")),
            ("Records:SecretAccessKeyFile", Secret("secret-access-key")),
        ];
    });
}
