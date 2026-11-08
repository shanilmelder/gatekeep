using System.Collections;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Xml.Linq;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.31 (FR-8, AD-14, AD-15, SM-2): every job type, rate-limit policy and in-process cache in
/// <c>src</c> is in <see cref="TenantKeyedTypes"/> as Tenant-keyed or Deployment-wide. Job types come
/// from the production job registry; policies are every static <c>RateLimitPolicy</c> field and caches
/// every <c>ConcurrentDictionary&lt;,&gt;</c>, <c>IMemoryCache</c> or <c>MemoryCache</c> field, found by
/// reflection over the built <c>src</c> assemblies. Tests reference no module, so those are read in
/// their own load context from the solution build's output folders, as <c>JobRegistryRuleTests</c> does.
/// </summary>
public sealed class TenantKeyedTypeTests
{
    private const string RateLimitPolicyType = "Gatekeep.Kernel.RateLimiting.RateLimitPolicy";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly Lazy<SourceAssemblies> Source = new(SourceAssemblies.Load);

    [Fact]
    public void Every_src_assembly_is_scanned()
    {
        // Every project file under src, found on disk, is loaded, so nothing is skipped by a missing output.
        var projects = Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.csproj", SearchOption.AllDirectories)
            .Where(p => !p.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(d => d is "bin" or "obj"))
            .Select(SourceAssemblies.ProjectAssemblyName)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Contains("Gatekeep.Kernel", projects);
        Assert.Contains("Gatekeep.Host.Hosted", projects);
        Assert.Equal(projects, Source.Value.Sources.Select(a => a.GetName().Name!).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Every_job_type_is_registered_and_each_Tenant_one_is_Tenant_scoped()
    {
        var jobs = ProductionJobs();
        Assert.NotEmpty(jobs);

        Assert.Empty(Problems("job type", jobs.Keys, TenantKeyedTypes.Jobs, "TenantKeyedTypes.Jobs"));
        Assert.Empty(JobScopeProblems(jobs, TenantKeyedTypes.Jobs));
    }

    [Fact]
    public void A_Tenant_job_that_isnt_Tenant_scoped_in_the_registry_is_reported()
    {
        var problems = JobScopeProblems(
            new Dictionary<string, string> { ["widgets.widget.sweep"] = "DeploymentWide" },
            new Dictionary<string, KeyScope> { ["widgets.widget.sweep"] = KeyScope.Tenant });

        Assert.Equal(["widgets.widget.sweep is registered Tenant but is JobScope.DeploymentWide in the production registry: make it JobScope.Tenant, or register it DeploymentWide with a reason."], problems);
    }

    [Fact]
    public void Every_rate_limit_policy_is_registered()
    {
        var policies = Members(t => t.FullName == RateLimitPolicyType);
        Assert.NotEmpty(policies);

        Assert.Empty(Problems("rate-limit policy", policies, TenantKeyedTypes.RateLimitPolicies, "TenantKeyedTypes.RateLimitPolicies"));
        Assert.Empty(PolicyScopeProblems(TenantKeyedTypes.RateLimitPolicies));
    }

    [Fact]
    public void A_Tenant_rate_limit_policy_is_refused_until_its_key_check_exists()
    {
        Assert.Equal(
            ["rate-limit policy Gatekeep.Widgets.WidgetsContract.SignInPolicy is registered Tenant, which nothing checks yet: the story that adds Tenant counters (Story 2.5) must add its key check here first."],
            PolicyScopeProblems(new Dictionary<string, KeyScope> { ["Gatekeep.Widgets.WidgetsContract.SignInPolicy"] = KeyScope.Tenant }));
    }

    [Fact]
    public void Policies_are_found_in_static_and_instance_fields_and_properties_by_their_own_name()
    {
        var name = typeof(PolicySamples).FullName;
        Assert.Equal(
            [$"{name}.Field", $"{name}.Instance", $"{name}.Property", $"{name}.StaticProperty"],
            MembersOf([typeof(PolicySamples)], t => t == typeof(Version)).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Every_cache_is_registered_and_each_Tenant_one_is_keyed_by_Tenant()
    {
        var caches = Fields(IsCache);
        Assert.NotEmpty(caches);

        Assert.Empty(Problems("cache", caches.Select(Name), TenantKeyedTypes.Caches, "TenantKeyedTypes.Caches"));
        Assert.Empty(CacheKeyProblems(caches, TenantKeyedTypes.Caches));
    }

    [Fact]
    public void An_unregistered_type_and_a_stale_entry_are_reported()
    {
        var problems = Problems(
            "cache",
            ["Gatekeep.Widgets.WidgetCache._byId"],
            new Dictionary<string, KeyScope> { ["Gatekeep.Widgets.Gone._byId"] = KeyScope.Tenant },
            "TenantKeyedTypes.Caches");

        Assert.Equal(
            [
                "cache Gatekeep.Widgets.WidgetCache._byId isn't registered: add it to TenantKeyedTypes.Caches as KeyScope.Tenant or KeyScope.DeploymentWide(\"<reason>\").",
                "TenantKeyedTypes.Caches lists cache Gatekeep.Widgets.Gone._byId, which src no longer has: remove it.",
            ],
            problems);
    }

    [Fact]
    public void A_Tenant_cache_keyed_by_anything_but_a_Tenant_is_reported()
    {
        var problems = CacheKeyProblems(
            [
                typeof(Samples).GetField(nameof(Samples.ByName), BindingFlags.NonPublic | BindingFlags.Static)!,
                typeof(Samples).GetField(nameof(Samples.ByTenant), BindingFlags.NonPublic | BindingFlags.Static)!,
                typeof(Samples).GetField(nameof(Samples.ByTenantKey), BindingFlags.NonPublic | BindingFlags.Static)!,
            ],
            new Dictionary<string, KeyScope>
            {
                [$"{typeof(Samples).FullName}.{nameof(Samples.ByName)}"] = KeyScope.Tenant,
                [$"{typeof(Samples).FullName}.{nameof(Samples.ByTenant)}"] = KeyScope.Tenant,
                [$"{typeof(Samples).FullName}.{nameof(Samples.ByTenantKey)}"] = KeyScope.Tenant,
            });

        Assert.Equal([$"cache {typeof(Samples).FullName}.{nameof(Samples.ByName)} is registered Tenant but is keyed by System.String: key it by the Tenant ID (a Guid, or a key with a TenantId member), or register it DeploymentWide with a reason."], problems);
    }

    [Fact]
    public void Every_Deployment_wide_entry_gives_a_reason()
    {
        var entries = TenantKeyedTypes.Jobs.Concat(TenantKeyedTypes.RateLimitPolicies).Concat(TenantKeyedTypes.Caches);

        Assert.Empty(entries
            .Where(e => e.Value is KeyScope.DeploymentWideScope { Reason: var reason } && string.IsNullOrWhiteSpace(reason))
            .Select(e => e.Key));
    }

    /// <summary>Discovered names missing from the registry, and registry names no longer discovered.</summary>
    private static List<string> Problems(string kind, IEnumerable<string> discovered, IReadOnlyDictionary<string, KeyScope> registry, string registryName)
    {
        var found = discovered.ToHashSet(StringComparer.Ordinal);
        return
        [
            .. found.Where(n => !registry.ContainsKey(n)).Order(StringComparer.Ordinal)
                .Select(n => $"{kind} {n} isn't registered: add it to {registryName} as KeyScope.Tenant or KeyScope.DeploymentWide(\"<reason>\")."),
            .. registry.Keys.Where(n => !found.Contains(n)).Order(StringComparer.Ordinal)
                .Select(n => $"{registryName} lists {kind} {n}, which src no longer has: remove it."),
        ];
    }

    private static List<string> PolicyScopeProblems(IReadOnlyDictionary<string, KeyScope> registry) =>
    [
        .. registry.Where(p => p.Value is KeyScope.TenantKeyed).Select(p => p.Key).Order(StringComparer.Ordinal)
            .Select(n => $"rate-limit policy {n} is registered Tenant, which nothing checks yet: the story that adds Tenant counters (Story 2.5) must add its key check here first."),
    ];

    private static List<string> JobScopeProblems(IReadOnlyDictionary<string, string> jobs, IReadOnlyDictionary<string, KeyScope> registry) =>
    [
        .. jobs.Where(j => registry.TryGetValue(j.Key, out var scope) && scope is KeyScope.TenantKeyed && j.Value != "Tenant")
            .OrderBy(j => j.Key, StringComparer.Ordinal)
            .Select(j => $"{j.Key} is registered Tenant but is JobScope.{j.Value} in the production registry: make it JobScope.Tenant, or register it DeploymentWide with a reason."),
    ];

    private static List<string> CacheKeyProblems(IEnumerable<FieldInfo> caches, IReadOnlyDictionary<string, KeyScope> registry) =>
    [
        .. caches.Where(f => registry.TryGetValue(Name(f), out var scope) && scope is KeyScope.TenantKeyed)
            .Select(f => (Field: f, Key: CacheKey(f.FieldType)))
            .Where(c => c.Key is null || !IsTenantKey(c.Key))
            .OrderBy(c => Name(c.Field), StringComparer.Ordinal)
            .Select(c => $"cache {Name(c.Field)} is registered Tenant but is keyed by {c.Key?.FullName ?? "no key it states"}: key it by the Tenant ID (a Guid, or a key with a TenantId member), or register it DeploymentWide with a reason."),
    ];

    private static readonly string[] CacheTypes =
    [
        "Microsoft.Extensions.Caching.Memory.IMemoryCache",
        "Microsoft.Extensions.Caching.Memory.MemoryCache",
        "Microsoft.Extensions.Caching.Distributed.IDistributedCache",
        "Microsoft.Extensions.Caching.Hybrid.HybridCache",
    ];

    /// <summary>
    /// The key type of a <c>ConcurrentDictionary</c>, or of a type deriving from one; an
    /// <c>IMemoryCache</c>, <c>IDistributedCache</c> or <c>HybridCache</c> takes any key, so it states none.
    /// </summary>
    private static Type? CacheKey(Type type)
    {
        for (var current = type; current is not null; current = current.BaseType)
        {
            if (current.IsGenericType && current.GetGenericTypeDefinition().FullName == "System.Collections.Concurrent.ConcurrentDictionary`2")
            {
                return current.GetGenericArguments()[0];
            }
        }

        return null;
    }

    private static bool IsTenantKey(Type key) =>
        key.FullName == typeof(Guid).FullName
        || key.GetMember("TenantId", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).Length > 0;

    private static bool IsCache(Type type)
    {
        if (CacheKey(type) is not null || type.GetInterfaces().Any(i => CacheTypes.Contains(i.FullName)))
        {
            return true;
        }

        for (var current = type; current is not null; current = current.BaseType)
        {
            if (CacheTypes.Contains(current.FullName))
            {
                return true;
            }
        }

        return false;
    }

    private static string Name(FieldInfo field) => $"{field.DeclaringType!.FullName}.{field.Name}";

    /// <summary>
    /// Every field and property of a matching type in src, static or instance, as
    /// <c>{declaring type}.{name}</c>: an auto-property by its own name, never its backing field, and
    /// never a compiler-generated closure or state machine holding a parameter.
    /// </summary>
    private static List<string> Members(Func<Type, bool> match) =>
        MembersOf(Source.Value.Types.Where(t => !t.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false)), match);

    private static List<string> MembersOf(IEnumerable<Type> types, Func<Type, bool> match)
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;
        var list = types.ToList();
        return
        [
            .. list.SelectMany(t => t.GetFields(All))
                .Where(f => !f.Name.EndsWith(">k__BackingField", StringComparison.Ordinal) && match(f.FieldType))
                .Select(Name),
            .. list.SelectMany(t => t.GetProperties(All))
                .Where(p => p.GetIndexParameters().Length == 0 && match(p.PropertyType))
                .Select(p => $"{p.DeclaringType!.FullName}.{p.Name}"),
        ];
    }

    private static List<FieldInfo> Fields(Func<Type, bool> match) =>
    [
        .. Source.Value.Types
            .SelectMany(t => t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(f => match(f.FieldType)),
    ];

    /// <summary>Each production job type and its <c>JobScope</c>, read from the registry in the src load context.</summary>
    private static Dictionary<string, string> ProductionJobs()
    {
        object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);

        var contract = Source.Value.Sources.Single(a => a.GetName().Name == "Gatekeep.Modules.Operations")
            .GetType("Gatekeep.Modules.Operations.Contracts.OperationsContract", throwOnError: true)!;
        var registry = contract.GetProperty("ProductionRegistry")!.GetValue(null)!;
        return ((IEnumerable)Get(registry, "Definitions")!).Cast<object>()
            .ToDictionary(d => (string)Get(Get(d, "Type")!, "Value")!, d => Get(d, "Scope")!.ToString()!, StringComparer.Ordinal);
    }

    /// <summary>Stand-ins for policy discovery: one of each kind of member.</summary>
    private sealed class PolicySamples
    {
        internal static readonly Version? Field = null;
        internal readonly Version? Instance = null;

        internal Version? Property { get; } = null;

        internal static Version? StaticProperty { get; } = null;
    }

    /// <summary>Stand-ins for the key check.</summary>
    private static class Samples
    {
#pragma warning disable CS0169, CS0414, CS0649 // Read only by reflection.
        internal static System.Collections.Concurrent.ConcurrentDictionary<string, int>? ByName;
        internal static System.Collections.Concurrent.ConcurrentDictionary<Guid, int>? ByTenant;
        internal static System.Collections.Concurrent.ConcurrentDictionary<TenantKey, int>? ByTenantKey;
#pragma warning restore CS0169, CS0414, CS0649

        internal readonly record struct TenantKey(Guid TenantId, string Name);
    }

    /// <summary>
    /// Every <c>src</c> project's assembly, in one load context that resolves each dependency from the
    /// hosts' and Cli's output folders, which hold every package, then the ASP.NET Core shared
    /// framework, which they run on. Kernel and the core framework are shared with this test.
    /// </summary>
    private sealed class SourceAssemblies : AssemblyLoadContext
    {
        private readonly Dictionary<string, string> _paths;

        private SourceAssemblies(Dictionary<string, string> paths)
            : base("src assemblies")
        {
            _paths = paths;
        }

        public IReadOnlyList<Assembly> Sources { get; private set; } = [];

        public IReadOnlyList<Type> Types { get; private set; } = [];

        public static SourceAssemblies Load()
        {
            var output = Path.GetRelativePath(
                Path.Combine(Root, "tests/Architecture"),
                AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            var projects = Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.csproj", SearchOption.AllDirectories)
                .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                .ToList();

            // Deployables first: their folders hold every package. Then each project's own, then the framework.
            var folders = projects
                .OrderBy(p => Path.GetFileName(Path.GetDirectoryName(p)!).StartsWith("Gatekeep.", StringComparison.Ordinal) ? 0 : 1)
                .ThenBy(p => p, StringComparer.Ordinal)
                .Select(p => Path.Combine(Path.GetDirectoryName(p)!, output))
                .Append(AspNetCoreFramework())
                .Where(Directory.Exists);

            var paths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var folder in folders)
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.dll"))
                {
                    paths.TryAdd(Path.GetFileNameWithoutExtension(file), file);
                }
            }

            var context = new SourceAssemblies(paths);
            var assemblies = projects.Select(ProjectAssemblyName)
                .Select(name => paths.ContainsKey(name)
                    ? context.LoadFromAssemblyName(new AssemblyName(name))
                    : throw new InvalidOperationException($"{name}.dll isn't built: build the solution first."))
                .ToList();

            context.Sources = assemblies;
            context.Types = [.. assemblies.SelectMany(a => a.GetTypes())];
            return context;
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            // Kernel and the core framework are this test's own.
            if (assemblyName.Name == "Gatekeep.Kernel"
                || File.Exists(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), $"{assemblyName.Name}.dll")))
            {
                return null;
            }

            return _paths.TryGetValue(assemblyName.Name!, out var path) ? LoadFromAssemblyPath(path) : null;
        }

        /// <summary>The project's assembly name: its <c>AssemblyName</c> property, or its file name.</summary>
        internal static string ProjectAssemblyName(string project) =>
            XDocument.Load(project).Descendants("AssemblyName").FirstOrDefault()?.Value
            ?? Path.GetFileNameWithoutExtension(project);

        /// <summary>The ASP.NET Core shared framework beside the running runtime, at its version or the newest.</summary>
        private static string AspNetCoreFramework()
        {
            var runtime = new DirectoryInfo(RuntimeEnvironment.GetRuntimeDirectory().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            var shared = Path.Combine(runtime.Parent!.Parent!.FullName, "Microsoft.AspNetCore.App");
            if (!Directory.Exists(shared))
            {
                return shared;
            }

            var same = Path.Combine(shared, runtime.Name);
            return Directory.Exists(same)
                ? same
                : Directory.EnumerateDirectories(shared).OrderBy(d => Version.TryParse(Path.GetFileName(d), out var v) ? v : new Version()).Last();
        }
    }
}
