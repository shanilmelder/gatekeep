using System.Collections;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 1.21: <c>admin</c> and <c>admin_session</c> in the AD-3 registry with exactly their grants
/// and no delete; the committed OpenAPI document naming the Session cookie, the CSRF header and the
/// problem responses on every Admin API operation; and the request checks covering every mapped
/// <c>/api/v1/deployment</c> endpoint. Tests reference no adapter or host, so the registry is read
/// by reflection and the host's source as text.
/// </summary>
public class AdminApiRuleTests
{
    private const string Document = "docs/api/openapi-v1.json";
    private const string Api = "src/Gatekeep.Host.Admin/AdminApi.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] StateChanging = ["post", "put", "patch", "delete"];

    [Theory]
    [InlineData("admin", new[] { "gk_admin INSERT", "gk_admin SELECT", "gk_cli SELECT" }, new[] { "gk_admin UPDATE setup_completed_at,webauthn_handle" })]
    [InlineData(
        "admin_session",
        new[] { "gk_admin INSERT", "gk_admin SELECT" },
        new[] { "gk_admin UPDATE end_reason,ended_at,idle_expires_at,kind,registration_challenge_expires_at,registration_challenge_sha256" })]
    [InlineData("admin_credential", new[] { "gk_admin INSERT", "gk_admin SELECT" }, new[] { "gk_admin UPDATE last_used_at,sign_count" })]
    // Story 1.23: the one Admins table with DELETE, and no UPDATE: taking a challenge deletes it.
    [InlineData("admin_signin_challenge", new[] { "gk_admin DELETE", "gk_admin INSERT", "gk_admin SELECT" }, new string[0], true)]
    // Story 1.24: read-only to gk_admin. Story 1.27 adds INSERT, Story 8.4 UPDATE and DELETE.
    [InlineData("tenant_role", new[] { "gk_admin SELECT" }, new string[0])]
    public void Registry_lists_the_Admins_tables_with_exactly_their_grants(string table, string[] grants, string[] columns, bool unlogged = false)
    {
        var entry = Entry(table);

        Assert.Equal("Control", Get(entry, "Class")!.ToString());
        Assert.Equal("Admins", Get(entry, "Owner"));
        Assert.Equal(unlogged, (bool)Get(entry, "Unlogged")!);

        var tableGrants = ((IEnumerable)Get(entry, "Grants")!)
            .Cast<object>()
            .SelectMany(g => ((IEnumerable<string>)Get(g, "Value")!).Select(p => $"{Get(g, "Key")} {p}"))
            .Order(StringComparer.Ordinal);
        Assert.Equal(grants, tableGrants);

        var columnGrants = ((IEnumerable?)Get(entry, "ColumnGrants") ?? Array.Empty<object>())
            .Cast<object>()
            .SelectMany(g => ((IEnumerable)Get(g, "Value")!).Cast<object>().Select(c =>
                $"{Get(g, "Key")} {Get(c, "Privilege")} {string.Join(",", ((IEnumerable<string>)Get(c, "Columns")!).Order(StringComparer.Ordinal))}"))
            .Order(StringComparer.Ordinal);
        Assert.Equal(columns, columnGrants);
    }

    [Fact]
    public void Document_names_the_session_cookie_and_the_CSRF_header()
    {
        using var document = Load();
        var schemes = document.RootElement.GetProperty("components").GetProperty("securitySchemes");

        var session = schemes.GetProperty("adminSession");
        Assert.Equal("apiKey", session.GetProperty("type").GetString());
        Assert.Equal("cookie", session.GetProperty("in").GetString());
        Assert.Equal("__Host-gk-admin", session.GetProperty("name").GetString());

        var csrf = schemes.GetProperty("csrf");
        Assert.Equal("apiKey", csrf.GetProperty("type").GetString());
        Assert.Equal("header", csrf.GetProperty("in").GetString());
        Assert.Equal("X-Gatekeep-CSRF", csrf.GetProperty("name").GetString());

        Assert.Equal(
            ["code", "traceId"],
            document.RootElement.GetProperty("components").GetProperty("schemas").GetProperty("ApiProblem")
                .GetProperty("properties").EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public void Every_operation_states_its_auth_and_only_the_claim_and_sign_in_have_none()
    {
        using var document = Load();
        var operations = Operations(document).ToList();

        foreach (var sessionless in Sessionless)
        {
            Assert.Contains(operations, o => o.Path == sessionless && o.Method == "post");
        }

        // The Tenant surface (Story 1.24) is covered too: it always needs a Session.
        Assert.Contains(operations, o => o.Path == TenantCapabilities && o.Method == "get");

        foreach (var (path, method, operation) in operations)
        {
            var schemes = operation.GetProperty("security").EnumerateArray()
                .SelectMany(r => r.EnumerateObject().Select(s => s.Name))
                .Order(StringComparer.Ordinal)
                .ToList();

            if (Sessionless.Contains(path))
            {
                Assert.Empty(schemes);
                continue;
            }

            Assert.Equal(
                StateChanging.Contains(method) ? ["adminSession", "csrf"] : ["adminSession"],
                schemes);
            Assert.True(operation.GetProperty("responses").TryGetProperty("401", out _), $"{method} {path} has no 401.");
        }
    }

    [Fact]
    public void Problem_responses_use_the_problem_schema()
    {
        using var document = Load();

        var refusals = Operations(document)
            .SelectMany(o => o.Operation.GetProperty("responses").EnumerateObject())
            .Where(r => r.Value.TryGetProperty("content", out _))
            .Where(r => r.Name.StartsWith('4'))
            .ToList();

        // 403 carries a problem only on capability operations: access_denied (Story 1.24).
        Assert.Equal(["400", "403", "429"], refusals.Select(r => r.Name).Distinct().Order(StringComparer.Ordinal));
        foreach (var refusal in refusals)
        {
            Assert.Equal(
                "#/components/schemas/ApiProblem",
                refusal.Value.GetProperty("content").GetProperty("application/problem+json").GetProperty("schema").GetProperty("$ref").GetString());
        }
    }

    [Fact]
    public void Every_deployment_endpoint_is_behind_the_request_checks()
    {
        var source = File.ReadAllText(Path.Combine(Root, Api));
        var maps = Regex.Matches(source, @"\.Map(?:Get|Post|Put|Patch|Delete)\(\s*""(?<route>[^""]+)""(?<rest>.*?);", RegexOptions.Singleline);

        Assert.NotEmpty(maps);
        foreach (Match map in maps)
        {
            var route = map.Groups["route"].Value;
            var rest = map.Groups["rest"].Value;

            // One access declaration each (Story 1.24): a capability, self-service, or sessionless.
            var declarations = new[] { "new RequiresCapability(", "SelfService.Instance", "BootstrapClaimEndpoint.Instance", "SignInEndpoint.Instance" }
                .Sum(d => Regex.Matches(rest, Regex.Escape(d)).Count);
            Assert.True(declarations == 1, $"{route} declares {declarations} access kinds, not one.");

            if (route.StartsWith("/api/v1/tenants/{tenantId}/", StringComparison.Ordinal))
            {
                // The Tenant surface: a Tenant capability only, never self-service or sessionless.
                Assert.Contains("TenantApiEndpoint.Instance", rest);
                Assert.DoesNotContain("DeploymentApiEndpoint.Instance", rest);
                Assert.Matches(@"new RequiresCapability\(AdminCapabilities\.Tenant[A-Za-z]+\)", rest);
                continue;
            }

            Assert.StartsWith("/api/v1/deployment/", route);
            Assert.Contains("DeploymentApiEndpoint.Instance", rest);
            Assert.DoesNotContain("TenantApiEndpoint.Instance", rest);
            Assert.DoesNotMatch(@"new RequiresCapability\(AdminCapabilities\.Tenant", rest);
        }

        // Self-service is the reviewed list: every Admin needs these, the Owner or not (Story 1.24).
        // Any other Deployment route declares a Deployment capability, which only the Owner holds.
        Assert.Equal(
            [
                "/api/v1/deployment/capabilities",
                "/api/v1/deployment/credentials/registration",
                "/api/v1/deployment/credentials/registration/complete",
                "/api/v1/deployment/session",
                "/api/v1/deployment/session",
            ],
            maps.Where(m => m.Groups["rest"].Value.Contains("SelfService.Instance")).Select(m => m.Groups["route"].Value).Order(StringComparer.Ordinal));

        // No setup-allowed route declares a capability: a restricted Session holds none.
        Assert.DoesNotContain(
            maps,
            m => m.Groups["rest"].Value.Contains("SetupAllowed.Instance") && m.Groups["rest"].Value.Contains("new RequiresCapability("));

        // Setup-allowed is the reviewed short list: GET of the Session endpoint, and credential
        // registration's begin and complete (Story 1.22). Sign-out (DELETE) is deliberately not
        // setup-allowed: it would strand the only Owner.
        Assert.Equal(
            ["/api/v1/deployment/credentials/registration", "/api/v1/deployment/credentials/registration/complete", "/api/v1/deployment/session"],
            maps.Where(m => m.Groups["rest"].Value.Contains("SetupAllowed.Instance")).Select(m => m.Groups["route"].Value).Order(StringComparer.Ordinal));

        // Sessionless is the reviewed short list too: the claim (Story 1.21) and sign-in's begin and
        // complete (Story 1.23). None of them is setup-allowed: no Session reaches them.
        Assert.Equal(
            Sessionless.Order(StringComparer.Ordinal),
            maps.Where(m => m.Groups["rest"].Value.Contains("BootstrapClaimEndpoint.Instance") || m.Groups["rest"].Value.Contains("SignInEndpoint.Instance"))
                .Select(m => m.Groups["route"].Value)
                .Order(StringComparer.Ordinal));
        Assert.DoesNotContain(
            maps,
            m => m.Groups["rest"].Value.Contains("SignInEndpoint.Instance") && m.Groups["rest"].Value.Contains("SetupAllowed.Instance"));
    }

    /// <summary>The operations with no Session: they need the exact Admin Origin only.</summary>
    private static readonly string[] Sessionless =
        ["/api/v1/deployment/bootstrap", "/api/v1/deployment/signin", "/api/v1/deployment/signin/complete"];

    private const string TenantCapabilities = "/api/v1/tenants/{tenantId}/capabilities";

    private static JsonDocument Load() => JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));

    private static IEnumerable<(string Path, string Method, JsonElement Operation)> Operations(JsonDocument document) =>
        document.RootElement.GetProperty("paths").EnumerateObject()
            .SelectMany(p => p.Value.EnumerateObject().Select(o => (p.Name, o.Name, o.Value)));

    private static object Entry(string table)
    {
        var output = Path.GetRelativePath(
            Path.Combine(Root, "tests/Architecture"),
            AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var assembly = Assembly.LoadFrom(Path.Combine(Root, "src/Adapters/Postgres", output, "Gatekeep.Adapters.Postgres.dll"));
        var registry = assembly.GetType("Gatekeep.Adapters.Postgres.Schema.TableRegistry", throwOnError: true)!;
        var tables = (IEnumerable)registry.GetField("Tables")!.GetValue(null)!;

        return Assert.Single(tables.Cast<object>(), t => (string)Get(t, "Name")! == table);
    }

    private static object? Get(object target, string name) => target.GetType().GetProperty(name)!.GetValue(target);
}
