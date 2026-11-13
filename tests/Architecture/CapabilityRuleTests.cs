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
/// operation; and its fresh assertion (Story 1.26) is what the table says, enforced by the checks
/// for <c>Always</c> and by a reviewed handler for a <c>When…</c> predicate, with its 403 problem,
/// and a self-service route's names a self-service action. Around the document:
/// no Host.Admin source hides an endpoint from it, every API route is mapped in <c>AdminApi.cs</c>,
/// a Tenant scope there opens only on the path Tenant (but for Story 7.4's one named refusal
/// writer), nothing under <c>src/</c> builds a
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

    /// <summary>
    /// The one reviewed Tenant scope on another Tenant than the path's (Story 7.4, AD-9): the
    /// refusal writer, which only appends <c>admin.cross_tenant.rejected</c> to the Log of the Tenant
    /// a refused request named, as no path Tenant was authorized. Its one call, on the
    /// <c>gk_admin</c> source, in its own file; anywhere else, or a second call, is a problem.
    /// </summary>
    private static readonly (string File, string Argument) RefusalWriterExemption = ("CrossTenantRejection.cs", "rejectedTenant");

    private const string RefusalWriterSource = "services.Source";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    /// <summary>The reviewed self-service routes under <c>/api/v1/deployment</c>: every Admin needs them, the Owner or not.</summary>
    private static readonly string[] SelfService =
    [
        "delete /api/v1/deployment/credentials/{credentialId}",
        "delete /api/v1/deployment/session",
        "get /api/v1/deployment/capabilities",
        "get /api/v1/deployment/credentials",
        "get /api/v1/deployment/my-tenants",
        "get /api/v1/deployment/session",
        "post /api/v1/deployment/assertions",
        "post /api/v1/deployment/assertions/complete",
        "post /api/v1/deployment/credentials/recovery-code",
        "post /api/v1/deployment/credentials/recovery-code/confirm",
        "post /api/v1/deployment/credentials/registration",
        "post /api/v1/deployment/credentials/registration/complete",
    ];

    /// <summary>
    /// The reviewed routes whose handler, not the request checks, uses up their fresh assertion
    /// (Story 1.26): registration begin, whose need depends on the Session being full. A route
    /// declaring a <c>When…</c> capability joins this list with the story that maps it: Story 1.28's
    /// label change, whose handler decides <c>WhenProdTenant</c> on the locked label, and Story 3.2's
    /// Application settings save, whose handler decides it on the locked label and callbacks.
    /// </summary>
    private static readonly string[] HandlerEnforced =
    [
        "post /api/v1/deployment/credentials/registration",
        "put /api/v1/tenants/{tenantId}/applications/{applicationId}/settings",
        "put /api/v1/tenants/{tenantId}/label",
    ];

    /// <summary>The reviewed sessionless routes: the bootstrap claim and sign-in's begin and complete.</summary>
    private static readonly string[] Sessionless =
    [
        "post /api/v1/deployment/bootstrap",
        "post /api/v1/deployment/signin",
        "post /api/v1/deployment/signin/complete",
        "post /api/v1/deployment/signin/enrolment",
        "post /api/v1/deployment/signin/recovery-code",
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

        // Story 1.26: the fresh-assertion requirement is the table's, enforced where it must be.
        { DeploymentPrefix + "tenants/{x}", "delete", Capability("deployment.tenants.delete", "deployment", false, "always"), "needs a fresh assertion enforced by the checks" },
        { DeploymentPrefix + "tenants/{x}", "delete", Capability("deployment.tenants.delete", "deployment", false, "always", enforcedBy: "handler"), "must be enforced by the checks" },
        { DeploymentPrefix + "tenants/{x}", "delete", Capability("deployment.tenants.delete", "deployment", false, "always", enforcedBy: "checks", action: "deployment.admins.manage"), "names action deployment.admins.manage" },
        { DeploymentPrefix + "tenants/{x}", "delete", Capability("deployment.tenants.delete", "deployment", false, "always", enforcedBy: "checks", problem403: false), "lists no 403 problem" },
        { TenantPrefix + "label", "put", Capability("tenant.label.manage", "tenant", false, "whenProdTenant", enforcedBy: "checks"), "must be enforced by the handler" },
        { TenantPrefix + "environment", "put", Capability("tenant.label.manage", "tenant", false, "whenProdTenant", enforcedBy: "handler"), "isn't on the reviewed handler-enforced list" },
        { TenantPrefix + "x", "get", Capability("tenant.configuration.read", "tenant", true, "never", enforcedBy: "checks"), "needs no fresh assertion" },
        { DeploymentPrefix + "credentials/{credentialId}", "delete", Declared("self", "self.credentials.rename"), "isn't a self-service fresh-assertion action" },
        { DeploymentPrefix + "credentials/{credentialId}", "delete", Declared("self", "deployment.tenants.delete"), "isn't a self-service fresh-assertion action" },
        { DeploymentPrefix + "credentials/{credentialId}", "delete", Declared("self", "self.credentials.remove", "handler"), "isn't on the reviewed handler-enforced list" },
        { DeploymentPrefix + "credentials/{credentialId}", "delete", Declared("self", "self.credentials.remove", setupAllowed: true), "setup-allowed" },
        { DeploymentPrefix + "credentials/{credentialId}", "delete", Declared("self", "self.credentials.remove", problem403: false), "lists no 403 problem" },
        { DeploymentPrefix + "signin", "post", Declared("sessionless", "self.credentials.add"), "is sessionless" },
    };

    [Fact]
    public void Fresh_assertion_rule_accepts_each_enforcement_where_it_belongs()
    {
        var operations = new (string Path, string Method, string Json)[]
        {
            (DeploymentPrefix + "credentials/{credentialId}", "delete", Declared("self", "self.credentials.remove")),
            (DeploymentPrefix + "credentials/registration", "post", Declared("self", "self.credentials.add", "handler", setupAllowed: true)),
        };

        var problems = operations.SelectMany(o =>
        {
            using var json = JsonDocument.Parse(o.Json);
            return AccessProblems([(o.Path, o.Method, json.RootElement.Clone())], Table());
        });

        Assert.Empty(problems);
    }

    [Fact]
    public void Fresh_assertion_rule_holds_the_routes_this_story_declares()
    {
        var operations = Operations(Load()).ToDictionary(o => $"{o.Method} {o.Path}", o => o.Operation);

        Assert.Equal("checks", Fresh(operations["delete /api/v1/deployment/credentials/{credentialId}"])!.EnforcedBy);
        Assert.Equal("credentialId", Fresh(operations["delete /api/v1/deployment/credentials/{credentialId}"])!.Target);
        Assert.Equal("handler", Fresh(operations["post /api/v1/deployment/credentials/registration"])!.EnforcedBy);

        // Story 1.28: the label change's handler decides WhenProdTenant, bound to the path Tenant alone.
        Assert.Equal("handler", Fresh(operations["put /api/v1/tenants/{tenantId}/label"])!.EnforcedBy);
        Assert.Null(Fresh(operations["put /api/v1/tenants/{tenantId}/label"])!.Target);
        Assert.Equal("tenant.label.manage", Fresh(operations["put /api/v1/tenants/{tenantId}/label"])!.Action);
        // Story 3.2: the settings save's handler decides WhenProdTenant, bound to the Application it changes.
        const string Settings = "put /api/v1/tenants/{tenantId}/applications/{applicationId}/settings";
        Assert.Equal("handler", Fresh(operations[Settings])!.EnforcedBy);
        Assert.Equal("applicationId", Fresh(operations[Settings])!.Target);
        Assert.Equal("tenant.application_callbacks.manage", Fresh(operations[Settings])!.Action);
        Assert.Equal(HandlerEnforced.Order(), operations.Where(o => Fresh(o.Value)?.EnforcedBy == "handler").Select(o => o.Key).Order());

        // Story 1.29: the first production Always routes, a deletion's start and retry, are
        // checks-enforced and bound to the Tenant they act on.
        foreach (var route in DeletionRoutes)
        {
            var fresh = Fresh(operations[route])!;
            Assert.Equal("checks", fresh.EnforcedBy);
            Assert.Equal("deployment.tenants.delete", fresh.Action);
            Assert.Equal("targetTenantId", fresh.Target);
        }

        Assert.Equal(
            DeletionRoutes.Order(StringComparer.Ordinal),
            operations.Where(o => Fresh(o.Value)?.Action == "deployment.tenants.delete").Select(o => o.Key).Order(StringComparer.Ordinal));

        // Story 3.3: every client secret write is checks-enforced (Always) and bound to the Application it acts on.
        foreach (var route in ClientSecretRoutes)
        {
            var fresh = Fresh(operations[route])!;
            Assert.Equal("checks", fresh.EnforcedBy);
            Assert.Equal("tenant.client_secrets.manage", fresh.Action);
            Assert.Equal("applicationId", fresh.Target);
        }

        Assert.Equal(
            ClientSecretRoutes.Order(StringComparer.Ordinal),
            operations.Where(o => Fresh(o.Value)?.Action == "tenant.client_secrets.manage").Select(o => o.Key).Order(StringComparer.Ordinal));

        // Story 3.4: the tokens save is tenant.applications.manage, open to machine principals, with no fresh assertion.
        const string Tokens = "put /api/v1/tenants/{tenantId}/applications/{applicationId}/tokens";
        Assert.Null(Fresh(operations[Tokens]));
        var access = operations[Tokens].GetProperty("x-gatekeep-access");
        Assert.Equal("capability", access.GetProperty("kind").GetString());
        Assert.Equal("tenant.applications.manage", access.GetProperty("capability").GetString());
        Assert.True(access.GetProperty("machineAllowed").GetBoolean());
        Assert.Equal("never", access.GetProperty("freshAssertion").GetString());
    }

    private static readonly string[] ClientSecretRoutes =
    [
        "post /api/v1/tenants/{tenantId}/applications/{applicationId}/secrets",
        "post /api/v1/tenants/{tenantId}/applications/{applicationId}/secrets/{secretId}/revoke",
    ];

    private static readonly string[] DeletionRoutes =
    [
        "post /api/v1/deployment/tenants/{targetTenantId}/deletion",
        "post /api/v1/deployment/tenants/{targetTenantId}/deletion/retry",
    ];

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
    public void The_refusal_writer_is_the_one_exemption_and_is_used()
    {
        var (file, argument) = RefusalWriterExemption;
        var source = File.ReadAllText(Path.Combine(Root, HostDirectory, file));

        // The exempt call exists, exactly once, so the exemption isn't stale.
        Assert.Single(TenantScopeBegin.Matches(StripComments(source)));
        Assert.Empty(TenantScopeProblems(file, source));
    }

    [Theory]
    [InlineData("CrossTenantRejection.cs", "await TenantScope.BeginAsync(services.Source, rejectedTenant, ct);", 0)]
    [InlineData("CrossTenantRejection.cs", "await TenantScope.BeginAsync(services.Source, rejectedTenant, ct); await TenantScope.BeginAsync(services.Source, rejectedTenant, ct);", 1)]
    [InlineData("CrossTenantRejection.cs", "await TenantScope.BeginAsync(services.Source, tenantId, ct);", 1)]
    [InlineData("CrossTenantRejection.cs", "await TenantScope.BeginAsync(other.Source, rejectedTenant, ct);", 1)]
    [InlineData("TenantLabelApi.cs", "await TenantScope.BeginAsync(services.Source, rejectedTenant, ct);", 1)]
    [InlineData("Nested/CrossTenantRejection.cs", "await TenantScope.BeginAsync(services.Source, rejectedTenant, ct);", 1)]
    public void Refusal_writer_exemption_covers_its_one_call_only(string file, string source, int expected)
    {
        Assert.Equal(expected, TenantScopeProblems(file, source).Count);
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
        var tableUse = registry.Assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableUse", throwOnError: true)!;
        var constructor = entryType.GetConstructors().Single();
        var grants = new Dictionary<string, IReadOnlyList<string>> { ["gk_hosted"] = ["SELECT"] };
        var entry = constructor.Invoke(["tenant_role", Enum.Parse(tableClass, "Control"), "Admins", Enum.Parse(tableUse, "Configuration"), grants, null, null, false]);

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

                    // Story 1.26: the table's flag decides the requirement, and who enforces it.
                    var expected = row.FreshAssertion switch
                    {
                        "never" => null,
                        "always" => "checks",
                        _ => "handler",
                    };
                    problems.AddRange(FreshProblems(name, operation, expected, capability, setupAllowed));
                    break;

                default:
                    problems.Add($"{name} has an unknown access kind {kind}.");
                    break;
            }

            if (kind == "self" && Fresh(operation) is { } self)
            {
                if (!SelfActions().Contains(self.Action))
                {
                    problems.Add($"{name}: {self.Action} isn't a self-service fresh-assertion action.");
                }
                else
                {
                    problems.AddRange(FreshProblems(name, operation, self.EnforcedBy, self.Action, setupAllowed));
                }
            }

            if (kind == "sessionless" && Fresh(operation) is not null)
            {
                problems.Add($"{name} is sessionless, so it can't need a fresh assertion.");
            }
        }

        return problems;
    }

    /// <summary>
    /// Story 1.26: an operation's <c>x-gatekeep-fresh-assertion</c> against what it must be. A null
    /// <paramref name="enforcedBy"/> means none. Checks-enforced is never setup-allowed, a
    /// handler-enforced route is on the reviewed list, and every one lists the 403 problem.
    /// </summary>
    private static List<string> FreshProblems(string name, JsonElement operation, string? enforcedBy, string action, bool setupAllowed)
    {
        var problems = new List<string>();
        var fresh = Fresh(operation);
        if (enforcedBy is null)
        {
            if (fresh is not null)
            {
                problems.Add($"{name}: {action} needs no fresh assertion, but the route declares one.");
            }

            return problems;
        }

        if (fresh is null)
        {
            problems.Add($"{name}: {action} needs a fresh assertion enforced by the {enforcedBy}, but the route declares none.");
            return problems;
        }

        if (fresh.Action != action)
        {
            problems.Add($"{name}: its fresh assertion names action {fresh.Action}, not {action}.");
        }

        if (fresh.EnforcedBy != enforcedBy)
        {
            problems.Add($"{name}: {action}'s fresh assertion must be enforced by the {enforcedBy}, not the {fresh.EnforcedBy}.");
        }

        if (fresh.EnforcedBy == "handler" && !HandlerEnforced.Contains(name))
        {
            problems.Add($"{name}: its handler enforces its fresh assertion, but it isn't on the reviewed handler-enforced list.");
        }

        if (fresh.EnforcedBy == "checks" && setupAllowed)
        {
            problems.Add($"{name} is setup-allowed, so a checks-enforced fresh assertion could never be met.");
        }

        if (!(operation.TryGetProperty("responses", out var responses)
            && responses.TryGetProperty("403", out var refused)
            && refused.TryGetProperty("content", out var content)
            && content.TryGetProperty("application/problem+json", out _)))
        {
            problems.Add($"{name} needs a fresh assertion but lists no 403 problem for fresh_assertion_required.");
        }

        return problems;
    }

    private sealed record FreshDeclaration(string Action, string? Target, string EnforcedBy);

    private static FreshDeclaration? Fresh(JsonElement operation) =>
        operation.TryGetProperty("x-gatekeep-fresh-assertion", out var fresh) && fresh.ValueKind == JsonValueKind.Object
            ? new FreshDeclaration(
                fresh.TryGetProperty("action", out var a) ? a.GetString() ?? string.Empty : string.Empty,
                fresh.TryGetProperty("target", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null,
                fresh.TryGetProperty("enforcedBy", out var e) ? e.GetString() ?? string.Empty : string.Empty)
            : null;

    /// <summary>The self-service fresh-assertion actions, read by reflection from the Admins build output.</summary>
    private static IReadOnlyList<string> SelfActions()
    {
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Modules/Admins", Output(), "Gatekeep.Modules.Admins.dll"));
        var actions = assembly.GetType("Gatekeep.Modules.Admins.Contracts.AdminFreshAssertions", throwOnError: true)!;
        return [.. ((IEnumerable)actions.GetField("SelfActions")!.GetValue(null)!).Cast<string>()];
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

    /// <summary>
    /// Every <c>TenantScope.BeginAsync</c> call in <paramref name="source"/> whose Tenant isn't the
    /// path Tenant, but for <see cref="RefusalWriterExemption"/>'s one call in its own file.
    /// </summary>
    private static List<string> TenantScopeProblems(string name, string source)
    {
        var code = StripComments(source);
        var problems = new List<string>();
        var exempted = 0;
        foreach (Match call in TenantScopeBegin.Matches(code))
        {
            var arguments = Arguments(code, call.Index + call.Length);
            if (name == RefusalWriterExemption.File && arguments is { Count: >= 2 }
                && arguments[0] == RefusalWriterSource && arguments[1] == RefusalWriterExemption.Argument && exempted++ == 0)
            {
                continue;
            }

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

    private static string Capability(
        string name,
        string scope,
        bool machineAllowed,
        string freshAssertion,
        bool setupAllowed = false,
        string? enforcedBy = null,
        string? action = null,
        bool problem403 = true) =>
        JsonSerializer.Serialize(Operation(
            new Dictionary<string, object>
            {
                ["kind"] = "capability",
                ["capability"] = name,
                ["scope"] = scope,
                ["machineAllowed"] = machineAllowed,
                ["freshAssertion"] = freshAssertion,
            },
            setupAllowed,
            enforcedBy is null ? null : (action ?? name, enforcedBy),
            problem403));

    /// <summary>A self-service or sessionless operation, with a fresh assertion when <paramref name="action"/> is given.</summary>
    private static string Declared(string kind, string? action = null, string enforcedBy = "checks", bool setupAllowed = false, bool problem403 = true) =>
        JsonSerializer.Serialize(Operation(
            new Dictionary<string, object> { ["kind"] = kind },
            setupAllowed,
            action is null ? null : (action, enforcedBy),
            problem403));

    private static Dictionary<string, object> Operation(
        Dictionary<string, object> access,
        bool setupAllowed,
        (string Action, string EnforcedBy)? fresh,
        bool problem403)
    {
        var operation = new Dictionary<string, object>
        {
            ["x-gatekeep-setup-allowed"] = setupAllowed,
            ["x-gatekeep-access"] = access,
        };
        if (fresh is { } f)
        {
            operation["x-gatekeep-fresh-assertion"] = new Dictionary<string, object?> { ["action"] = f.Action, ["target"] = null, ["enforcedBy"] = f.EnforcedBy };
        }

        if (problem403)
        {
            operation["responses"] = new Dictionary<string, object>
            {
                ["403"] = new Dictionary<string, object>
                {
                    ["content"] = new Dictionary<string, object> { ["application/problem+json"] = new Dictionary<string, object>() },
                },
            };
        }

        return operation;
    }

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
