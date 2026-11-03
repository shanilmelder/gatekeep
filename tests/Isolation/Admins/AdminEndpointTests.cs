using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;
using Gatekeep.Tests.Isolation.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21: every endpoint the real <c>Host.Admin</c> maps under <c>/api/v1/deployment</c> carries
/// the request checks' marker. The host's own entry point runs in its own load context with real
/// settings, and its endpoints are read from its started routing, as requests would reach them.
/// </summary>
public sealed class AdminEndpointTests : IDisposable
{
    private const string Prefix = "/api/v1/deployment";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-admin-endpoints-").FullName;

    [Fact]
    public async Task Every_deployment_route_of_the_running_host_has_the_request_checks_marker()
    {
        var endpoints = await RunningEndpointsAsync();

        var deployment = endpoints
            .Where(e => e.RoutePattern.RawText?.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) == true)
            .ToList();

        Assert.Equal(
            [
                "/api/v1/deployment/bootstrap",
                "/api/v1/deployment/capabilities",
                "/api/v1/deployment/credentials/registration",
                "/api/v1/deployment/credentials/registration/complete",
                "/api/v1/deployment/session",
                "/api/v1/deployment/session",
            ],
            deployment.Select(e => e.RoutePattern.RawText!).Order(StringComparer.Ordinal));
        foreach (var endpoint in deployment)
        {
            Assert.True(
                endpoint.Metadata.Any(m => m.GetType().Name == "DeploymentApiEndpoint"),
                $"{endpoint.DisplayName} has no request checks marker.");
        }

        // The unknown-path fallback is the only other API route, and it answers 404 alone.
        Assert.Contains(endpoints, e => e.RoutePattern.RawText == "/api/{**path}");
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private async Task<IReadOnlyList<RouteEndpoint>> RunningEndpointsAsync()
    {
        var assemblyPath = BuildOutput.AssemblyPath("Gatekeep.Host.Admin", "Gatekeep.Host.Admin");
        var context = new HostLoadContext(assemblyPath);
        var assembly = context.LoadFromAssemblyPath(assemblyPath);

        using var socket = new FakeOpenBaoSocket();
        var publicPort = HostProcess.FreePort().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var secrets = Directory.CreateDirectory(Path.Combine(_directory, "secrets")).FullName;
        string[] arguments =
        [
            $"--Gatekeep:SecretsDirectory={secrets}",
            $"--ConnectionStrings:Admin=Host=127.0.0.1;Port=9;Database=gatekeep;Username=gk_admin;Password={Guid.NewGuid():N}",
            $"--Custody:SocketPath={socket.Path}",
            $"--Custody:RoleIdFile={SecretFile("role-id")}",
            $"--Custody:SecretIdFile={SecretFile("secret-id")}",
            $"--Gatekeep:HealthPort={HostProcess.FreePort()}",
            $"--Gatekeep:PublicPort={publicPort}",
            $"--Gatekeep:PublicOrigin={HostProcess.AdminOrigin}",
            "--Gatekeep:ForwardedBy=none",
        ];

        var built = new TaskCompletionSource<IHost>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var listening = DiagnosticListener.AllListeners.Subscribe(new Observer<DiagnosticListener>(listener =>
        {
            if (listener.Name == "Microsoft.Extensions.Hosting")
            {
                listener.Subscribe(new Observer<KeyValuePair<string, object?>>(e =>
                {
                    // Other tests build hosts too: only this one has its public port.
                    if (e.Key == "HostBuilt" && e.Value is IHost host
                        && host.Services.GetService<Microsoft.Extensions.Configuration.IConfiguration>()?["Gatekeep:PublicPort"] == publicPort)
                    {
                        built.TrySetResult(host);
                    }
                }));
            }
        }));

        var exitCode = Environment.ExitCode;
        var entry = Task.Run(() => assembly.EntryPoint!.Invoke(null, [arguments]) as Task ?? Task.CompletedTask);
        try
        {
            var host = await built.Task.WaitAsync(Timeout);
            var lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();
            var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using (lifetime.ApplicationStarted.Register(() => started.TrySetResult()))
            {
                await started.Task.WaitAsync(Timeout);
            }

            var endpoints = host.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();
            lifetime.StopApplication();
            await entry.WaitAsync(Timeout);
            return endpoints;
        }
        finally
        {
            Environment.ExitCode = exitCode;
        }
    }

    private string SecretFile(string name)
    {
        var path = Path.Combine(_directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }

    /// <summary>The host's own assemblies from its output folder; the shared framework from the default context.</summary>
    private sealed class HostLoadContext(string assemblyPath) : AssemblyLoadContext($"Host.Admin endpoints {Guid.NewGuid():N}")
    {
        private readonly AssemblyDependencyResolver _resolver = new(assemblyPath);

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            // Hosting and routing types must be the test's own, so the host's are read as them.
            if (Default.Assemblies.Any(a => a.GetName().Name == assemblyName.Name && IsFramework(a)))
            {
                return null;
            }

            return _resolver.ResolveAssemblyToPath(assemblyName) is { } path ? LoadFromAssemblyPath(path) : null;
        }

        private static bool IsFramework(Assembly assembly) =>
            assembly.Location.Contains($"{Path.DirectorySeparatorChar}shared{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }

    private sealed class Observer<T>(Action<T> next) : IObserver<T>
    {
        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void OnNext(T value) => next(value);
    }
}
