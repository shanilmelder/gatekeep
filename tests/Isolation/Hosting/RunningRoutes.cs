using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Loader;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>One route a running host answers: its method (<c>*</c> for any) and its pattern as mapped.</summary>
internal sealed record LiveRoute(string Method, string Pattern)
{
    public override string ToString() => $"{Method} {Pattern}";
}

/// <summary>
/// The routes the real hosts serve, read from the running host, never from a copied list (Story
/// 1.21, Story 1.31). Each host's own entry point runs in its own load context with real settings
/// and stand-in secrets, and its endpoints are read from its started routing, as requests would
/// reach them. Host.Hosted adds the OpenIddict endpoint URIs it serves, which are middleware
/// rather than endpoints (AD-8).
/// </summary>
internal static class RunningRoutes
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    // Each host starts once per test run, however many tests read it.
    private static readonly Lazy<Task<IReadOnlyList<RouteEndpoint>>> Admin = new(StartAdminAsync);

    private static readonly Lazy<Task<IReadOnlyList<LiveRoute>>> Hosted = new(StartHostedAsync);

    /// <summary>Host.Admin's endpoints, with their metadata.</summary>
    public static Task<IReadOnlyList<RouteEndpoint>> AdminEndpointsAsync() => Admin.Value;

    /// <summary>Every route of Host.Admin, one per method.</summary>
    public static async Task<IReadOnlyList<LiveRoute>> AdminAsync() => Routes(await AdminEndpointsAsync());

    /// <summary>Every route of Host.Hosted: its endpoints, one per method, and each OpenIddict endpoint URI, for any method.</summary>
    public static Task<IReadOnlyList<LiveRoute>> HostedAsync() => Hosted.Value;

    private static async Task<IReadOnlyList<RouteEndpoint>> StartAdminAsync()
    {
        var (endpoints, _) = await RunAsync(
            "Gatekeep.Host.Admin",
            (directory, socket) =>
            [
                $"--ConnectionStrings:Admin=Host=127.0.0.1;Port=9;Database=gatekeep;Username=gk_admin;Password={Guid.NewGuid():N}",
                $"--Custody:SocketPath={socket}",
                $"--Custody:RoleIdFile={SecretFile(directory, "role-id")}",
                $"--Custody:SecretIdFile={SecretFile(directory, "secret-id")}",
                $"--Gatekeep:PublicOrigin={HostProcess.AdminOrigin}",
                "--Gatekeep:ForwardedBy=none",
                $"--Gatekeep:TenantZone={HostProcess.TenantZone}",
            ],
            static (_, _) => []);
        return endpoints;
    }

    private static async Task<IReadOnlyList<LiveRoute>> StartHostedAsync()
    {
        var (endpoints, protocol) = await RunAsync(
            "Gatekeep.Host.Hosted",
            (directory, socket) =>
            [
                $"--ConnectionStrings:Hosted=Host=127.0.0.1;Port=9;Database=gatekeep;Username=gk_hosted;Password={Guid.NewGuid():N}",
                $"--Custody:SocketPath={socket}",
                $"--Custody:RoleIdFile={SecretFile(directory, "role-id")}",
                $"--Custody:SecretIdFile={SecretFile(directory, "secret-id")}",
            ],
            ProtocolEndpointUris);
        return [.. Routes(endpoints), .. protocol.Select(p => new LiveRoute("*", p))];
    }

    /// <summary>
    /// One route per method of each endpoint; an endpoint with no method metadata, or an empty
    /// method list, answers any (<c>*</c>), so it can never drop out of the drift check.
    /// </summary>
    public static IReadOnlyList<LiveRoute> Routes(IEnumerable<RouteEndpoint> endpoints) =>
    [
        .. endpoints.SelectMany(e => (e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods is { Count: > 0 } methods ? methods : (IReadOnlyList<string>)["*"])
            .Select(m => new LiveRoute(m.ToUpperInvariant(), e.RoutePattern.RawText ?? string.Empty))),
    ];

    /// <summary>
    /// Every endpoint URI OpenIddict's server options hold, whatever the endpoint: each public
    /// <c>*EndpointUris</c> list, read by reflection since the host's OpenIddict types are its own.
    /// A new OpenIddict endpoint therefore appears here without any change to this code.
    /// </summary>
    private static IReadOnlyList<string> ProtocolEndpointUris(IHost host, AssemblyLoadContext context)
    {
        var optionsType = context.Assemblies
            .Single(a => a.GetName().Name == "OpenIddict.Server")
            .GetType("OpenIddict.Server.OpenIddictServerOptions", throwOnError: true)!;
        var monitor = host.Services.GetRequiredService(typeof(Microsoft.Extensions.Options.IOptionsMonitor<>).MakeGenericType(optionsType));
        var options = monitor.GetType().GetProperty("CurrentValue")!.GetValue(monitor)!;

        return
        [
            .. optionsType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.Name.EndsWith("EndpointUris", StringComparison.Ordinal) && typeof(IEnumerable<Uri>).IsAssignableFrom(p.PropertyType))
                .SelectMany(p => (IEnumerable<Uri>)p.GetValue(options)!)
                .Select(u => "/" + (u.IsAbsoluteUri ? u.AbsolutePath : u.OriginalString).TrimStart('/'))
                .Distinct(StringComparer.Ordinal),
        ];
    }

    private static async Task<(IReadOnlyList<RouteEndpoint> Endpoints, IReadOnlyList<string> Extra)> RunAsync(
        string project,
        Func<string, string, IEnumerable<string>> settings,
        Func<IHost, AssemblyLoadContext, IReadOnlyList<string>> inspect)
    {
        var directory = Directory.CreateTempSubdirectory("gatekeep-running-routes-").FullName;
        try
        {
            var assemblyPath = BuildOutput.AssemblyPath(project, project);
            var context = new HostLoadContext(assemblyPath);
            var assembly = context.LoadFromAssemblyPath(assemblyPath);

            using var socket = new FakeOpenBaoSocket();
            var publicPort = HostProcess.FreePort().ToString(CultureInfo.InvariantCulture);
            var secrets = Directory.CreateDirectory(Path.Combine(directory, "secrets")).FullName;
            string[] arguments =
            [
                $"--Gatekeep:SecretsDirectory={secrets}",
                $"--Gatekeep:HealthPort={HostProcess.FreePort()}",
                $"--Gatekeep:PublicPort={publicPort}",
                .. settings(directory, socket.Path),
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
            IHostApplicationLifetime? lifetime = null;
            try
            {
                // An entry point that fails before the host is built reports its own error, not a timeout.
                if (await Task.WhenAny(built.Task, entry).WaitAsync(Timeout) == entry)
                {
                    await RethrowAsync(entry);
                    throw new InvalidOperationException($"{project} exited before its host was built.");
                }

                var host = await built.Task;
                lifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();
                var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using (lifetime.ApplicationStarted.Register(() => started.TrySetResult()))
                {
                    if (await Task.WhenAny(started.Task, entry).WaitAsync(Timeout) == entry)
                    {
                        await RethrowAsync(entry);
                        throw new InvalidOperationException($"{project} exited before it started.");
                    }
                }

                var endpoints = host.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();
                var extra = inspect(host, context);
                return (endpoints, extra);
            }
            finally
            {
                // Best effort, so a failure here never hides the one that brought us here.
                try
                {
                    lifetime?.StopApplication();
                    await entry.WaitAsync(Timeout);
                }
                catch (Exception)
                {
                    // Already failing or stopped: the host's own exit adds nothing.
                }

                Environment.ExitCode = exitCode;
            }
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // A host still holding a file leaves only a temp folder behind.
            }
        }
    }

    /// <summary>Awaits the entry point, throwing its own exception rather than the reflection wrapper.</summary>
    private static async Task RethrowAsync(Task entry)
    {
        try
        {
            await entry;
        }
        catch (TargetInvocationException e) when (e.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(e.InnerException);
        }
    }

    private static string SecretFile(string directory, string name)
    {
        var path = Path.Combine(directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }

    /// <summary>The host's own assemblies from its output folder; the shared framework from the default context.</summary>
    private sealed class HostLoadContext(string assemblyPath) : AssemblyLoadContext($"{Path.GetFileNameWithoutExtension(assemblyPath)} routes {Guid.NewGuid():N}")
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
