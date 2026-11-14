using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 7.4, FR-40: no route, on any surface, can change or delete a Log. The committed OpenAPI
/// document, which the build generates from the route table and the drift check holds byte-equal
/// to it, has a Log path only under <c>/api/v1/tenants/{tenantId}/logs</c> and, from Story 7.5,
/// <c>/api/v1/tenants/{tenantId}/logs/{eventId}</c>, from Story 7.7 under <c>/api/v1/deployment/logs</c>
/// and <c>/api/v1/deployment/logs/{eventId}</c>, and only <c>GET</c> there; and no source under
/// <c>src/</c> maps a Log route with any other method.
/// <c>AdminEndpointTests</c> holds the live route table equal to the document, so that is the
/// running host's route set too. The database triggers keep the rows immutable underneath.
/// Each rule has a self-check that it catches a violation.
/// </summary>
public class LogRouteRuleTests
{
    private const string Document = "docs/api/openapi-v1.json";

    private const string TenantLogs = "/api/v1/tenants/{tenantId}/logs";

    private const string TenantLogEvent = TenantLogs + "/{eventId}";

    private const string DeploymentLogs = "/api/v1/deployment/logs";

    private const string DeploymentLogEvent = DeploymentLogs + "/{eventId}";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    private static readonly string[] SkippedDirectories = ["bin", "obj"];

    /// <summary>A path segment, or a route literal's, that names a Log: <c>logs</c>, <c>log</c> or <c>audit</c>.</summary>
    private static readonly Regex LogSegment = new(@"(?:^|/)(?i:logs?|audit[\w-]*)(?:/|$|\?)", RegexOptions.Compiled);

    /// <summary>Every <c>Map…("pattern"</c> call, its method and its route literal.</summary>
    private static readonly Regex RouteMap = new(
        @"\.\s*Map(?<method>Get|Post|Put|Patch|Delete|Methods|Group|Fallback|\w*)\s*\(\s*@?""(?<pattern>[^""]*)""",
        RegexOptions.Compiled);

    [Fact]
    public void The_Log_routes_are_GET_only_and_no_Log_path_has_another_method()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, Document)));
        var operations = Operations(document).ToList();

        Assert.Contains(operations, o => o.Path == TenantLogs && o.Method == "get");
        Assert.Equal(["get"], operations.Where(o => o.Path == TenantLogEvent).Select(o => o.Method));
        Assert.Equal(["get"], operations.Where(o => o.Path == DeploymentLogs).Select(o => o.Method));
        Assert.Equal(["get"], operations.Where(o => o.Path == DeploymentLogEvent).Select(o => o.Method));
        Assert.Empty(DocumentProblems(operations));
    }

    [Theory]
    [InlineData(TenantLogs, "post")]
    [InlineData(TenantLogs, "put")]
    [InlineData(TenantLogs, "patch")]
    [InlineData(TenantLogs, "delete")]
    [InlineData(TenantLogEvent, "delete")]
    [InlineData(TenantLogEvent, "put")]
    [InlineData(TenantLogEvent, "patch")]
    [InlineData(TenantLogEvent, "post")]
    [InlineData(DeploymentLogs, "post")]
    [InlineData(DeploymentLogs, "put")]
    [InlineData(DeploymentLogs, "patch")]
    [InlineData(DeploymentLogs, "delete")]
    [InlineData(DeploymentLogEvent, "delete")]
    [InlineData(DeploymentLogEvent, "put")]
    [InlineData(DeploymentLogEvent, "patch")]
    [InlineData(DeploymentLogEvent, "post")]
    [InlineData("/api/v1/deployment/audit/events", "delete")]
    [InlineData("/api/v1/tenants/{tenantId}/Logs", "put")]
    [InlineData("/api/v1/tenants/{tenantId}/log", "patch")]
    public void Document_rule_catches_a_Log_route_that_changes_state(string path, string method)
    {
        Assert.NotEmpty(DocumentProblems([(TenantLogs, "get"), (path, method)]));
    }

    [Fact]
    public void Document_rule_accepts_GET_and_paths_that_merely_contain_the_word()
    {
        Assert.Empty(DocumentProblems([
            (TenantLogs, "get"),
            (TenantLogEvent, "get"),
            (DeploymentLogs, "get"),
            (DeploymentLogEvent, "get"),
            ("/api/v1/deployment/catalogue", "post"),
            ("/api/v1/tenants/{tenantId}/login-settings", "put"),
            ("/api/v1/tenants/{tenantId}/blogs", "delete"),
        ]));
    }

    [Fact]
    public void No_source_maps_a_Log_route_with_a_method_other_than_GET()
    {
        var offenders = SourceFiles(Path.Combine(Root, "src"))
            .SelectMany(f => MapProblems(Path.GetRelativePath(Root, f).Replace('\\', '/'), File.ReadAllText(f)));

        Assert.Empty(offenders);

        // The rule reads the real route, so it isn't vacuous.
        var api = File.ReadAllText(Path.Combine(Root, "src/Gatekeep.Host.Admin/AdminApi.cs"));
        Assert.Contains(RouteMap.Matches(api), m => m.Groups["pattern"].Value == TenantLogs && m.Groups["method"].Value == "Get");
        Assert.Contains(RouteMap.Matches(api), m => m.Groups["pattern"].Value == TenantLogEvent && m.Groups["method"].Value == "Get");
        Assert.Contains(RouteMap.Matches(api), m => m.Groups["pattern"].Value == DeploymentLogs && m.Groups["method"].Value == "Get");
        Assert.Contains(RouteMap.Matches(api), m => m.Groups["pattern"].Value == DeploymentLogEvent && m.Groups["method"].Value == "Get");
    }

    [Theory]
    [InlineData("app.MapPost(\"/api/v1/tenants/{tenantId}/logs\", H);")]
    [InlineData("app.MapDelete(\"/api/v1/tenants/{tenantId}/logs/{eventId}\", H);")]
    [InlineData("app.MapPut(@\"/api/v1/deployment/logs\", H);")]
    [InlineData("app.MapDelete(\"/api/v1/deployment/logs/{eventId}\", H);")]
    [InlineData("app.MapMethods(\"/api/v1/tenants/{tenantId}/logs\", [\"PATCH\"], H);")]
    [InlineData("app.MapGroup(\"/api/v1/tenants/{tenantId}/logs\").MapGet(\"\", H);")]
    [InlineData("app.Map(\"/api/v1/audit\", H);")]
    public void Map_rule_catches_a_Log_route_that_isnt_a_plain_GET(string source)
    {
        Assert.NotEmpty(MapProblems("AdminApi.cs", source));
    }

    [Fact]
    public void Map_rule_accepts_a_GET_and_other_routes()
    {
        Assert.Empty(MapProblems(
            "AdminApi.cs",
            "app.MapGet(\"/api/v1/tenants/{tenantId}/logs\", H); app.MapPut(\"/api/v1/tenants/{tenantId}/label\", H); app.MapPost(\"/api/v1/deployment/signin\", H);"));
    }

    /// <summary>Each Log operation in the document whose method isn't GET.</summary>
    private static List<string> DocumentProblems(IEnumerable<(string Path, string Method)> operations) =>
        [.. operations
            .Where(o => LogSegment.IsMatch(o.Path) && o.Method != "get")
            .Select(o => $"{o.Method.ToUpperInvariant()} {o.Path} would change a Log: Logs are read-only.")];

    /// <summary>Each <c>Map…</c> call in <paramref name="source"/> on a Log route that isn't <c>MapGet</c>.</summary>
    private static List<string> MapProblems(string name, string source) =>
        [.. RouteMap.Matches(source)
            .Where(m => LogSegment.IsMatch(m.Groups["pattern"].Value) && m.Groups["method"].Value != "Get")
            .Select(m => $"{name}: Map{m.Groups["method"].Value}(\"{m.Groups["pattern"].Value}\") would change a Log: map Log routes with MapGet only.")];

    private static IEnumerable<(string Path, string Method)> Operations(JsonDocument document) =>
        document.RootElement.GetProperty("paths").EnumerateObject()
            .SelectMany(p => p.Value.EnumerateObject()
                .Where(o => o.Name is "get" or "put" or "post" or "delete" or "options" or "head" or "patch" or "trace")
                .Select(o => (p.Name, o.Name)));

    private static IEnumerable<string> SourceFiles(string directory)
    {
        var nested = Directory.EnumerateDirectories(directory)
            .Where(d => !SkippedDirectories.Contains(Path.GetFileName(d)))
            .SelectMany(SourceFiles);

        return Directory.EnumerateFiles(directory, "*.cs").Concat(nested);
    }
}
