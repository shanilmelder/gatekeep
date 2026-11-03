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
    [InlineData("admin", new[] { "gk_admin INSERT", "gk_admin SELECT", "gk_cli SELECT" }, new[] { "gk_admin UPDATE setup_completed_at" })]
    [InlineData(
        "admin_session",
        new[] { "gk_admin INSERT", "gk_admin SELECT" },
        new[] { "gk_admin UPDATE end_reason,ended_at,idle_expires_at" })]
    public void Registry_lists_the_Admins_tables_with_exactly_their_grants(string table, string[] grants, string[] columns)
    {
        var entry = Entry(table);

        Assert.Equal("Control", Get(entry, "Class")!.ToString());
        Assert.Equal("Admins", Get(entry, "Owner"));
        Assert.False((bool)Get(entry, "Unlogged")!);

        var tableGrants = ((IEnumerable)Get(entry, "Grants")!)
            .Cast<object>()
            .SelectMany(g => ((IEnumerable<string>)Get(g, "Value")!).Select(p => $"{Get(g, "Key")} {p}"))
            .Order(StringComparer.Ordinal);
        Assert.Equal(grants, tableGrants);

        var columnGrants = ((IEnumerable)Get(entry, "ColumnGrants")!)
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
    public void Every_operation_states_its_auth_and_the_claim_alone_has_none()
    {
        using var document = Load();
        var operations = Operations(document).ToList();

        Assert.Contains(operations, o => o.Path == "/api/v1/deployment/bootstrap" && o.Method == "post");
        foreach (var (path, method, operation) in operations)
        {
            var schemes = operation.GetProperty("security").EnumerateArray()
                .SelectMany(r => r.EnumerateObject().Select(s => s.Name))
                .Order(StringComparer.Ordinal)
                .ToList();

            if (path == "/api/v1/deployment/bootstrap")
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

        Assert.Equal(["400", "429"], refusals.Select(r => r.Name).Order(StringComparer.Ordinal));
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
            Assert.StartsWith("/api/v1/deployment/", map.Groups["route"].Value);
            Assert.Contains("DeploymentApiEndpoint.Instance", map.Groups["rest"].Value);
        }

        // Setup-allowed is the reviewed short list: GET of the Session endpoint only, until Story 1.22.
        // Sign-out (DELETE) is deliberately not setup-allowed: it would strand the only Owner.
        Assert.Equal(
            ["/api/v1/deployment/session"],
            maps.Where(m => m.Groups["rest"].Value.Contains("SetupAllowed.Instance")).Select(m => m.Groups["route"].Value));
    }

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
