using System.Collections;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.24, NFR-5, AR-14, AR-15, AD-19, AD-20: the route table declares access exhaustively.
/// The committed OpenAPI document, which the build generates from the route table and the drift
/// check holds byte-equal to it, gives every operation one <c>x-gatekeep-access</c>, each named
/// capability is the table's, with its flags, in its own surface's scope, on no setup-allowed
/// operation, and none needs a fresh assertion until Story 1.26 enforces it. Around the document:
/// no Host.Admin source hides an endpoint from it, every API route is mapped in <c>AdminApi.cs</c>,
/// a Tenant scope there opens only on the path Tenant, nothing under <c>src/</c> builds a
/// <c>MachinePrincipal</c>, and no Admins table grants <c>gk_hosted</c> anything. Each rule has
/// a self-check that it catches a violation. Tests reference no module or host: the table and
/// the registry are read by reflection, and sources as text.
/// </summary>
public class CapabilityRuleTests
{
    private const string Document = "docs/api/openapi-v1.json";
    private const string HostDirectory = "src/Gatekeep.Host.Admin";
    private const string Api = "AdminApi.cs";
    private const string Program = "Program.cs";
    private const string DeploymentPrefix = "/api/v1/deployment/";
    private const string TenantPrefix = "/api/v1/tenants/{tenantId}/";
    private const string PathTenantArgument = "AdminRequestChecks.PathTenant(context)";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    /// <summary>The reviewed self-service routes under <c>/api/v1/deployment</c>: every Admin needs them, the Owner or not.</summary>
    private static readonly string[] SelfService =
    [
        "delete /api/v1/deployment/session",
        "get /api/v1/deployment/capabilities",
        "get /api/v1/deployment/session",
        "post /api/v1/deployment/credentials/registration",
        "post /api/v1/deployment/credentials/registration/complete",
    ];

    /// <summary>The reviewed sessionless routes: the bootstrap claim and sign-in's begin and complete.</summary>
    private static readonly string[] Sessionless =
    [
        "post /api/v1/deployment/bootstrap",
        "post /api/v1/deployment/signin",
        "post /api/v1/deployment/signin/complete",
    ];

    private static readonly Regex MachinePrincipalConstruction = new(@"\bnew\s+(?:[\w.]+\.)?MachinePrincipal\s*\(", RegexOptions.Compiled);

    private static readonly Regex ExcludeFromDescription = new(@"\bExcludeFromDescription\b|\bExcludeFromDescriptionAttribute\b|\[\s*ExcludeFromDescription\b", RegexOptions.Compiled);

    /// <summary>
    /// Every <c>.Map…(</c> call, generic ones too (<c>MapHub&lt;T&gt;(</c>), but the fallbacks, which the
    /// next rule places, <c>MapAdminApi</c>, which delegates to <c>AdminApi.cs</c>, and
    /// <c>IPAddress.MapToIPv4</c> and <c>MapToIPv6</c>, which aren't routing.
    /// </summary>
    private static readonly Regex RouteMap = new(
        @"\.\s*Map(?!Fallback|ToIPv[46]\b|AdminApi\b)\w*\s*(?:<[^<>()]*>)?\s*\(",
        RegexOptions.Compiled);

    private static readonly Regex FallbackMap = new(@"\.\s*MapFallback(?:ToFile)?\s*\(", RegexOptions.Compiled);

    private static readonly Regex TenantScopeBegin = new(@"\bTenantScope\s*\.\s*BeginAsync\s*\(", RegexOptions.Compiled);

    /// <summary>
    /// A comment, or a string or char literal, which is kept: a <c>//</c> inside a string, such as
    /// a URL, is no comment and hides no code after it. Raw strings first, then verbatim, regular
    /// and char literals.
    /// </summary>
    private static readonly Regex CommentOrLiteral = new(
        "(?<literal>\"{3,}.*?\"{3,}|@\"(?:[^\"]|\"\")*\"|\"(?:[^\"\\\\\\r\\n]|\\\\.)*\"|'(?:[^'\\\\\\r\\n]|\\\\.)*')|//[^\\r\\n]*|/\\*.*?\\*/",
        RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary><paramref name="source"/> with its comments removed and its literals kept.</summary>
    private static string StripComments(string source) =>
        CommentOrLiteral.Replace(source, m => m.Groups["literal"].Success ? m.Value : string.Empty);

    [Fact]
    public void Every_operation_declares_its_access_and_the_table_agrees()
    {
        var operations = Operations(Load()).ToList();

        Assert.NotEmpty(operations);
        Assert.Empty(AccessProblems(operations, Table()));

        // The Tenant surface exists, so the Tenant rules aren't vacuous.
        Assert.Contains(operations, o => o.Path.StartsWith(TenantPrefix, StringComparison.Ordinal));
    }

    public static TheoryData<string, string, string, string> Violations => new()
    {
        { DeploymentPrefix + "x", "get", """{"x-gatekeep-setup-allowed":false}""", "no x-gatekeep-access" },
        { DeploymentPrefix + "x", "get", """{"x-gatekeep-access":{"kind":"maybe"}}""", "unknown access kind" },
        { DeploymentPrefix + "x", "get", """{"x-gatekeep-access":{"kind":"self"}}""", "isn't on the reviewed self-service list" },
        { DeploymentPrefix + "x", "post", """{"x-gatekeep-access":{"kind":"sessionless"}}""", "isn't on the reviewed sessionless list" },
        { TenantPrefix + "x", "get", """{"x-gatekeep-access":{"kind":"self"}}""", "a Tenant route declares only a Tenant capability" },
        { TenantPrefix + "x", "get", Capability("deployment.tenants.read", "deployment", false, "never"), "a Tenant route declares only a Tenant capability" },
        { DeploymentPrefix + "x", "get", Capability("tenant.configuration.read", "tenant", true, "never"), "a Deployment route declares only a Deployment capability" },
        { TenantPrefix + "x", "get", Capability("tenant.nothing.read", "tenant", true, "never"), "isn't in the capability table" },
        { TenantPrefix + "x", "get", Capability("tenant.configuration.read", "tenant", false, "never"), "machineAllowed" },
        { TenantPrefix + "x", "get", Capability("tenant.configuration.read", "deployment", true, "never"), "scope" },
        { TenantPrefix + "x", "get", Capability("tenant.configuration.read", "tenant", true, "always"), "freshAssertion" },
        { TenantPrefix + "x", "post", Capability("tenant.label.manage", "tenant", false, "whenProdTenant"), "needs a fresh assertion" },
        { TenantPrefix + "x", "get", Capability("tenant.configuration.read", "tenant", true, "never", setupAllowed: true), "setup-allowed" },
        { "/api/v1/other", "get", Capability("deployment.tenants.read", "deployment", false, "never"), "outside the Deployment and Tenant surfaces" },
    };

    [Theory]
    [MemberData(nameof(Violations))]
    public void Access_rule_catches_a_violation(string path, string method, string operation, string expected)
    {
        using var json = JsonDocument.Parse(operation);

        var problems = AccessProblems([(path, method, json.RootElement)], Table());

        Assert.Contains(problems, p => p.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void Access_rule_accepts_a_declared_Tenant_capability()
    {
        using var json = JsonDocument.Parse(Capability("tenant.users.read", "tenant", true, "never"));

        Assert.Empty(AccessProblems([(TenantPrefix + "users", "get", json.RootElement)], Table()));
    }

    [Fact]
    public void Nothing_under_src_builds_a_machine_principal()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .Where(f => MachinePrincipalConstruction.IsMatch(StripComments(File.ReadAllText(f))))
            .Select(f => Path.GetRelativePath(Root, f));

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("var p = new MachinePrincipal(client, tenant);", true)]
    [InlineData("var p = new Contracts.MachinePrincipal (client, tenant);", true)]
    [InlineData("MachinePrincipal p = new(client, tenant);", false)]
    [InlineData("if (principal is MachinePrincipal machine)", false)]
    public void Machine_principal_construction_detection(string source, bool expected)
    {
        Assert.Equal(expected, MachinePrincipalConstruction.IsMatch(source));
    }

    [Fact]
    public void Machine_principal_is_built_by_target_type_nowhere_under_src()
    {
        // `MachinePrincipal p = new(…)` and `(MachinePrincipal)new(…)` escape the regex above, so
        // no src file outside the contract that declares it may name the type next to a `new(`.
        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .Where(f => !f.Replace('\\', '/').EndsWith("Modules/Admins/Contracts/IAdminAuthorization.cs", StringComparison.Ordinal))
            .Select(f => (File: f, Text: StripComments(File.ReadAllText(f))))
            .Where(f => f.Text.Contains("MachinePrincipal", StringComparison.Ordinal) && Regex.IsMatch(f.Text, @"\bnew\s*\("))
            .Where(f => Regex.IsMatch(f.Text, @"MachinePrincipal\s+\w+\s*=\s*new\s*\(|\(\s*MachinePrincipal\s*\)\s*new\s*\("))
            .Select(f => Path.GetRelativePath(Root, f.File));

        Assert.Empty(offenders);
    }

    [Fact]
    public void No_Host_Admin_source_hides_an_endpoint_from_the_document()
    {
        var offenders = HostSources()
            .Where(f => ExcludeFromDescription.IsMatch(StripComments(File.ReadAllText(f.Path))))
            .Select(f => f.Name);

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData("app.MapGet(\"/x\", Handler).ExcludeFromDescription();", true)]
    [InlineData("[ExcludeFromDescription] static Task Handler() => Task.CompletedTask;", true)]
    [InlineData(".WithMetadata(new ExcludeFromDescriptionAttribute())", true)]
    [InlineData("app.MapGet(\"/x\", Handler).WithName(\"X\");", false)]
    public void Exclude_from_description_detection(string source, bool expected)
    {
        Assert.Equal(expected, ExcludeFromDescription.IsMatch(source));
    }

    [Fact]
    public void Every_API_route_is_mapped_in_AdminApi_and_Program_maps_only_the_fallbacks()
    {
        Assert.Empty(MapProblems(HostSources().Select(f => (f.Name, File.ReadAllText(f.Path)))));

        // AdminApi.cs maps the routes, so the rule above isn't vacuous.
        Assert.Matches(RouteMap, File.ReadAllText(Path.Combine(Root, HostDirectory, Api)));
    }

    [Theory]
    [InlineData(Program, "app.MapGet(\"/api/v1/deployment/x\", Handler);")]
    [InlineData(Program, "app.MapGroup(\"/api/v1/tenants/{tenantId}\");")]
    [InlineData("SignInApi.cs", "app.MapPost(\"/api/v1/deployment/y\", Handler);")]
    [InlineData("SignInApi.cs", "app.MapFallback(\"/api/{**path}\", Handler);")]
    [InlineData(Api, "app.MapFallback(\"/api/{**path}\", Handler);")]
    [InlineData(Program, "app.MapControllers();")]
    [InlineData(Program, "app.MapHub<ChatHub>(\"/api/hub\");")]
    [InlineData(Program, "app.MapWhen(c => true, b => b.Run(H));")]
    [InlineData(Program, "app.Map(\"/api/branch\", b => b.Run(H));")]
    [InlineData(Program, "app.MapRazorPages();")]
    [InlineData(Program, "app\n  .MapPut(\"/api/x\", H);")]
    // A // inside a string is no comment: the call after it is still code.
    [InlineData(Program, "var u = \"http://example.test\"; app.MapGet(\"/api/x\", H);")]
    [InlineData(Program, "var u = @\"http://example.test\"; app.MapGet(\"/api/x\", H);")]
    [InlineData(Program, "var c = '/'; var d = '/'; app.MapGet(\"/api/x\", H);")]
    public void Map_rule_catches_a_route_mapped_elsewhere(string file, string source)
    {
        Assert.NotEmpty(MapProblems([(file, source)]));
    }

    [Fact]
    public void Map_rule_accepts_the_fallbacks_in_Program()
    {
        Assert.Empty(MapProblems([(Program, "app.MapFallback(\"/api/{**path}\", NotFound);\napp.MapFallbackToFile(\"index.html\");"), (Api, "app.MapGet(\"/api/v1/deployment/x\", H);")]));

        // Not routing: delegating to AdminApi.cs, an address mapping, and a commented-out call.
        Assert.Empty(MapProblems([
            (Program, "app.MapAdminApi();\n// app.MapGet(\"/api/x\", H);\n/* app.MapPost(\"/api/y\", H); */"),
            ("AdminRequestChecks.cs", "return address.MapToIPv4().ToString(); var v6 = a.MapToIPv6();"),
        ]));
    }

    [Theory]
    [InlineData("var u = \"http://x\"; await TenantScope.BeginAsync(source, tenantId, ct);", 1)]
    [InlineData("// await TenantScope.BeginAsync(source, tenantId, ct);", 0)]
    [InlineData("/* a \"quoted // word\" */ await TenantScope.BeginAsync(source, tenantId, ct);", 1)]
    [InlineData("var c = '\"'; await TenantScope.BeginAsync(source, tenantId, ct);", 1)]
    public void Comment_stripper_keeps_code_after_a_string_or_char_literal(string source, int expected)
    {
        Assert.Equal(expected, TenantScopeProblems("Handler.cs", source).Count);
    }

    [Fact]
    public void Host_Admin_opens_a_Tenant_scope_only_on_the_path_Tenant()
    {
        Assert.Empty(HostSources().SelectMany(f => TenantScopeProblems(f.Name, File.ReadAllText(f.Path))));
    }

    [Theory]
    [InlineData("await TenantScope.BeginAsync(source, AdminRequestChecks.PathTenant(context), ct);", 0)]
    [InlineData("await TenantScope.BeginAsync(\n  source,\n  AdminRequestChecks.PathTenant(context),\n  ct);", 0)]
    [InlineData("await TenantScope.BeginAsync(source, tenantId, ct);", 1)]
    [InlineData("await TenantScope.BeginAsync(source, session.TenantId, ct);", 1)]
    [InlineData("await TenantScope.BeginAsync(source, Guid.Parse(request.Headers[\"X-Tenant\"]!), ct);", 1)]
    [InlineData("await TenantScope.BeginAsync(source, AdminRequestChecks.PathTenant(other), ct);", 1)]
    [InlineData("await TenantScope.BeginAsync(source, AdminRequestChecks.PathTenant(context), ct); await TenantScope.BeginAsync(s, t, ct);", 1)]
    [InlineData("await TenantScope.BeginAsync(source", 1)]
    public void Tenant_scope_rule_catches_another_Tenant(string source, int expected)
    {
        Assert.Equal(expected, TenantScopeProblems("Handler.cs", source).Count);
    }

    [Fact]
    public void No_Admins_table_grants_the_hosted_role_anything()
    {
        var registry = Registry();
        var tables = ((IEnumerable)registry.GetField("Tables")!.GetValue(null)!).Cast<object>().ToList();

        // Today's Admins tables, tenant_role included, are all checked.
        Assert.Contains(tables, t => (string)Get(t, "Name")! == "tenant_role" && (string)Get(t, "Owner")! == "Admins");
        Assert.Empty(HostedGrants(tables));
    }

    [Fact]
    public void Hosted_grant_rule_catches_a_grant_on_an_Admins_table()
    {
        var registry = Registry();
        var entryType = registry.Assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableEntry", throwOnError: true)!;
        var tableClass = registry.Assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableClass", throwOnError: true)!;
        var constructor = entryType.GetConstructors().Single();
        var grants = new Dictionary<string, IReadOnlyList<string>> { ["gk_hosted"] = ["SELECT"] };
        var entry = constructor.Invoke(["tenant_role", Enum.Parse(tableClass, "Control"), "Admins", grants, null, null, false]);

        Assert.Equal(["tenant_role"], HostedGrants([entry]));
    }

    /// <summary>Every way the document's operations break the access rules. Empty when none does.</summary>
    private static List<string> AccessProblems(
        IEnumerable<(string Path, string Method, JsonElement Operation)> operations,
        IReadOnlyDictionary<string, (string Scope, bool MachineAllowed, string FreshAssertion)> table)
    {
        var problems = new List<string>();
        foreach (var (path, method, operation) in operations)
        {
            var name = $"{method} {path}";
            var deployment = path.StartsWith(DeploymentPrefix, StringComparison.Ordinal);
            var tenant = path.StartsWith(TenantPrefix, StringComparison.Ordinal);
            if (!deployment && !tenant)
            {
                problems.Add($"{name} is outside the Deployment and Tenant surfaces.");
            }

            if (!operation.TryGetProperty("x-gatekeep-access", out var access) || access.ValueKind != JsonValueKind.Object)
            {
                problems.Add($"{name} has no x-gatekeep-access.");
                continue;
            }

            var setupAllowed = operation.TryGetProperty("x-gatekeep-setup-allowed", out var setup) && setup.ValueKind == JsonValueKind.True;
            var kind = access.TryGetProperty("kind", out var k) ? k.GetString() : null;
            switch (kind)
            {
                case "self":
                    if (tenant)
                    {
                        problems.Add($"{name}: a Tenant route declares only a Tenant capability, never self-service.");
                    }
                    else if (!SelfService.Contains(name))
                    {
                        problems.Add($"{name} declares self-service but isn't on the reviewed self-service list.");
                    }

                    break;

                case "sessionless":
                    if (tenant)
                    {
                        problems.Add($"{name}: a Tenant route declares only a Tenant capability, never sessionless.");
                    }
                    else if (!Sessionless.Contains(name))
                    {
                        problems.Add($"{name} declares sessionless but isn't on the reviewed sessionless list.");
                    }

                    break;

                case "capability":
                    var capability = access.GetProperty("capability").GetString()!;
                    var scope = access.GetProperty("scope").GetString();
                    var machineAllowed = access.GetProperty("machineAllowed").GetBoolean();
                    var fresh = access.GetProperty("freshAssertion").GetString();
                    if (!table.TryGetValue(capability, out var row))
                    {
                        problems.Add($"{name}: {capability} isn't in the capability table.");
                        break;
                    }

                    if (scope != row.Scope)
                    {
                        problems.Add($"{name}: {capability} has scope {scope}, but the table says {row.Scope}.");
                    }

                    if (machineAllowed != row.MachineAllowed)
                    {
                        problems.Add($"{name}: {capability} has machineAllowed {machineAllowed}, but the table says {row.MachineAllowed}.");
                    }

                    if (fresh != row.FreshAssertion)
                    {
                        problems.Add($"{name}: {capability} has freshAssertion {fresh}, but the table says {row.FreshAssertion}.");
                    }

                    if (tenant && row.Scope != "tenant")
                    {
                        problems.Add($"{name}: a Tenant route declares only a Tenant capability, not {capability}.");
                    }

                    if (deployment && row.Scope != "deployment")
                    {
                        problems.Add($"{name}: a Deployment route declares only a Deployment capability, not {capability}.");
                    }

                    if (setupAllowed)
                    {
                        problems.Add($"{name} is setup-allowed but declares {capability}: a restricted Session holds none.");
                    }

                    // Lifted by Story 1.26, which enforces fresh assertions.
                    if (row.FreshAssertion != "never")
                    {
                        problems.Add($"{name}: {capability} needs a fresh assertion, which no route may declare before Story 1.26.");
                    }

                    break;

                default:
                    problems.Add($"{name} has an unknown access kind {kind}.");
                    break;
            }
        }

        return problems;
    }

    /// <summary>Every API route mapped outside <c>AdminApi.cs</c>, and every fallback outside <c>Program.cs</c>.</summary>
    private static List<string> MapProblems(IEnumerable<(string Name, string Source)> sources)
    {
        var problems = new List<string>();
        foreach (var (name, source) in sources)
        {
            var code = StripComments(source);
            if (name != Api && RouteMap.IsMatch(code))
            {
                problems.Add($"{name} maps a route: every API Map call is in {Api}.");
            }

            if (name != Program && FallbackMap.IsMatch(code))
            {
                problems.Add($"{name} maps a fallback: only {Program} does.");
            }
        }

        return problems;
    }

    /// <summary>Every <c>TenantScope.BeginAsync</c> call in <paramref name="source"/> whose Tenant isn't the path Tenant.</summary>
    private static List<string> TenantScopeProblems(string name, string source)
    {
        var code = StripComments(source);
        var problems = new List<string>();
        foreach (Match call in TenantScopeBegin.Matches(code))
        {
            var arguments = Arguments(code, call.Index + call.Length);
            if (arguments is null || arguments.Count < 2 || arguments[1] != PathTenantArgument)
            {
                problems.Add($"{name}: a Tenant scope opens on something other than {PathTenantArgument}.");
            }
        }

        return problems;
    }

    /// <summary>A call's top-level arguments, trimmed, from just after its opening parenthesis. Null when it never closes.</summary>
    private static List<string>? Arguments(string source, int start)
    {
        var arguments = new List<string>();
        var depth = 1;
        var from = start;
        for (var i = start; i < source.Length; i++)
        {
            switch (source[i])
            {
                case '(' or '[' or '{':
                    depth++;
                    break;
                case ',' when depth == 1:
                    arguments.Add(Regex.Replace(source[from..i], @"\s+", string.Empty));
                    from = i + 1;
                    break;
                case ')' or ']' or '}':
                    if (--depth == 0)
                    {
                        arguments.Add(Regex.Replace(source[from..i], @"\s+", string.Empty));
                        return arguments;
                    }

                    break;
            }
        }

        return null;
    }

    private static List<string> HostedGrants(IEnumerable<object> tables) =>
        [.. tables
            .Where(t => (string)Get(t, "Owner")! == "Admins")
            .Where(t => Roles(Get(t, "Grants")).Concat(Roles(Get(t, "ColumnGrants"))).Contains("gk_hosted"))
            .Select(t => (string)Get(t, "Name")!)];

    private static IEnumerable<string> Roles(object? grants) =>
        grants is null ? [] : ((IEnumerable)grants).Cast<object>().Select(g => (string)Get(g, "Key")!);

    private static string Capability(string name, string scope, bool machineAllowed, string freshAssertion, bool setupAllowed = false) =>
        JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["x-gatekeep-setup-allowed"] = setupAllowed,
            ["x-gatekeep-access"] = new Dictionary<string, object>
            {
                ["kind"] = "capability",
                ["capability"] = name,
                ["scope"] = scope,
                ["machineAllowed"] = machineAllowed,
                ["freshAssertion"] = freshAssertion,
            },
        });

    /// <summary>The capability table, by name, read by reflection from the Admins build output, in the document's spelling.</summary>
    private static Dictionary<string, (string Scope, bool MachineAllowed, string FreshAssertion)> Table()
    {
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Modules/Admins", Output(), "Gatekeep.Modules.Admins.dll"));
        var table = assembly.GetType("Gatekeep.Modules.Admins.Contracts.AdminCapabilities", throwOnError: true)!;
        var all = ((IEnumerable)table.GetField("All")!.GetValue(null)!).Cast<object>().ToList();

        Assert.NotEmpty(all);
        return all.ToDictionary(
            c => (string)Get(c, "Name")!,
            c => (
                Get(c, "Scope")!.ToString()!.ToLowerInvariant(),
                (bool)Get(c, "MachineAllowed")!,
                JsonNamingPolicy.CamelCase.ConvertName(Get(c, "FreshAssertion")!.ToString()!)));
    }

    private static Type Registry()
    {
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Adapters/Postgres", Output(), "Gatekeep.Adapters.Postgres.dll"));
        return assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableRegistry", throwOnError: true)!;
    }

    /// <summary>The build output folder, relative to a project: the same as this test's.</summary>
    private static string Output() =>
        Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

    private static JsonDocument Load() => JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

    private static IEnumerable<(string Path, string Method, JsonElement Operation)> Operations(JsonDocument document) =>
        document.RootElement.GetProperty("paths").EnumerateObject()
            .SelectMany(p => p.Value.EnumerateObject().Select(o => (p.Name, o.Name, o.Value)));

    private static IEnumerable<(string Name, string Path)> HostSources() =>
        SourceFiles(Path.Combine(Root, HostDirectory))
            .Select(f => (Path.GetRelativePath(Path.Combine(Root, HostDirectory), f).Replace('\\', '/'), f));

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Directory.EnumerateFiles(directory, "*.cs").Concat(nested);
    }

    private static object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);
}
