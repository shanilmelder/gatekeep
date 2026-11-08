using Gatekeep.Tests.Isolation.Hosting;
using Microsoft.AspNetCore.Routing.Patterns;
using Xunit;

namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>
/// Story 1.31 (FR-8, AD-25, AR-13): <see cref="RouteRegistry"/> lists exactly the routes the running
/// hosts serve, read from each host as it starts (<see cref="RunningRoutes"/>), never from a copied
/// list. A live route with no entry fails, naming its method and pattern; an entry no live route
/// matches fails, naming the entry. Each entry's case kind fits its pattern, so a
/// <see cref="CaseKind.NotTenantBound"/> entry can never hide a Tenant route.
/// </summary>
public sealed class RouteRegistryTests
{
    [Fact]
    public async Task Every_live_Host_Admin_route_has_exactly_one_registry_entry()
    {
        var live = await RunningRoutes.AdminAsync();

        Assert.NotEmpty(live);
        Assert.Empty(Drift("Host.Admin", live, RouteRegistry.Admin));
    }

    [Fact]
    public async Task Every_live_Host_Hosted_route_has_exactly_one_registry_entry_and_none_is_under_api()
    {
        var live = await RunningRoutes.HostedAsync();

        Assert.Contains(live, r => r.Pattern == "/connect/token");
        Assert.Empty(Drift("Host.Hosted", live, RouteRegistry.Hosted));

        // AR-13, AD-2: no Admin or Management API route is registered on the public host.
        Assert.DoesNotContain(live, r => r.Pattern.TrimStart('/').StartsWith("api", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The request checks' own marker, not the parameter name, decides what is Tenant-bound: every
    /// live Host.Admin endpoint carrying <c>TenantApiEndpoint</c> is a <see cref="CaseKind.TenantPath"/>
    /// entry, and every such entry's endpoint carries it. The types come from the host's load
    /// context, so they are matched by name.
    /// </summary>
    [Fact]
    public async Task Tenant_marked_Admin_endpoints_are_exactly_the_TenantPath_entries()
    {
        var endpoints = await RunningRoutes.AdminEndpointsAsync();
        var marked = RunningRoutes.Routes(endpoints.Where(e => e.Metadata.Any(m => m.GetType().Name == "TenantApiEndpoint")))
            .Select(r => r.ToString())
            .ToHashSet(StringComparer.Ordinal);

        Assert.NotEmpty(marked);
        Assert.Empty(MarkerProblems(marked, RouteRegistry.Admin));
    }

    [Fact]
    public void A_Tenant_marked_endpoint_listed_otherwise_and_an_unmarked_TenantPath_entry_are_reported()
    {
        RouteCase[] registry =
        [
            new("GET", "/api/v1/tenants/{tenant}/widgets", CaseKind.NotTenantBound, Reason: "a reason"),
            new("GET", "/api/v1/tenants/{tenantId}/label", CaseKind.TenantPath),
        ];

        Assert.Equal(
            [
                "GET /api/v1/tenants/{tenant}/widgets carries TenantApiEndpoint but is NotTenantBound: give it the TenantPath case.",
                "GET /api/v1/tenants/{tenantId}/label is TenantPath but its endpoint doesn't carry TenantApiEndpoint.",
            ],
            MarkerProblems(new HashSet<string>(StringComparer.Ordinal) { "GET /api/v1/tenants/{tenant}/widgets" }, registry));
    }

    [Theory]
    [InlineData("GET /.well-known/{tenantId}/jwks HostResolved")]
    [InlineData("GET /.well-known/{targetTenantId}/jwks HostResolved")]
    [InlineData("GET /api/v1/tenants/{tenantId}/label TenantPath")]
    [InlineData("POST /api/v1/deployment/tenants/{targetTenantId}/deletion TargetTenant")]
    public void A_Hosted_entry_that_names_a_Tenant_or_takes_an_Admin_case_is_reported(string entry)
    {
        var parts = entry.Split(' ');

        var problems = KindProblems([new RouteCase(parts[0], parts[1], Enum.Parse<CaseKind>(parts[2]))], hosted: true);

        Assert.True(problems.Count == 1, string.Join(" | ", problems));
        Assert.StartsWith($"{parts[0]} {parts[1]} ", problems[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Every_entry_s_case_fits_its_pattern()
    {
        Assert.Empty(KindProblems(RouteRegistry.Admin, hosted: false));
        Assert.Empty(KindProblems(RouteRegistry.Hosted, hosted: true));
    }

    [Fact]
    public void An_unregistered_route_and_a_stale_entry_are_reported_by_name()
    {
        LiveRoute[] live = [new("GET", "/api/v1/tenants/{tenantId}/label"), new("GET", "/api/v1/tenants/{tenantId}/widgets")];
        RouteCase[] registry =
        [
            new("GET", "/api/v1/tenants/{tenantId}/label", CaseKind.TenantPath),
            new("DELETE", "/api/v1/tenants/{tenantId}/gone", CaseKind.TenantPath),
        ];

        Assert.Equal(
            [
                "Host.Admin serves GET /api/v1/tenants/{tenantId}/widgets, which has no entry: add it to RouteRegistry with its cross-Tenant case (TenantPath, TargetTenant, HostResolved, or NotTenantBound with a reason).",
                "RouteRegistry lists DELETE /api/v1/tenants/{tenantId}/gone, which Host.Admin no longer serves: remove the entry.",
            ],
            Drift("Host.Admin", live, registry));
    }

    [Fact]
    public void A_duplicate_entry_is_reported()
    {
        LiveRoute[] live = [new("GET", "/api/v1/deployment/session")];
        RouteCase[] registry =
        [
            new("GET", "/api/v1/deployment/session", CaseKind.NotTenantBound, Reason: "self-service"),
            new("GET", "/api/v1/deployment/session", CaseKind.NotTenantBound, Reason: "self-service"),
        ];

        Assert.Equal(["RouteRegistry lists GET /api/v1/deployment/session 2 times: keep one entry."], Drift("Host.Admin", live, registry));
    }

    public static TheoryData<string, string> MisfitCases => new()
    {
        { "NotTenantBound route naming tenantId", "GET /api/v1/tenants/{tenantId}/widgets NotTenantBound" },
        { "NotTenantBound route naming targetTenantId", "POST /api/v1/deployment/tenants/{targetTenantId}/widgets NotTenantBound" },
        { "NotTenantBound route with no reason", "GET /api/v1/deployment/widgets NotTenantBound-noreason" },
        { "TenantPath route without tenantId", "GET /api/v1/deployment/widgets TenantPath" },
        { "TargetTenant route without targetTenantId", "GET /api/v1/tenants/{tenantId}/widgets TargetTenant" },
        { "HostResolved route on Host.Admin", "GET /.well-known/jwks HostResolved" },
    };

    [Theory]
    [MemberData(nameof(MisfitCases))]
    public void A_case_that_doesnt_fit_its_pattern_is_reported(string name, string entry)
    {
        var parts = entry.Split(' ');
        var noReason = parts[2].EndsWith("-noreason", StringComparison.Ordinal);
        var kind = Enum.Parse<CaseKind>(parts[2].Replace("-noreason", string.Empty, StringComparison.Ordinal));
        var reason = kind == CaseKind.NotTenantBound && !noReason ? "a reason" : null;

        var problems = KindProblems([new RouteCase(parts[0], parts[1], kind, Reason: reason)], hosted: false);

        Assert.True(problems.Count == 1, $"{name}: {string.Join(" | ", problems)}");
        Assert.Contains($"{parts[0]} {parts[1]}", problems[0], StringComparison.Ordinal);
    }

    /// <summary>Live routes with no entry, entries matching no live route, and entries listed twice.</summary>
    internal static List<string> Drift(string host, IEnumerable<LiveRoute> live, IEnumerable<RouteCase> registry)
    {
        var served = live.Select(r => $"{r.Method} {r.Pattern}").ToHashSet(StringComparer.Ordinal);
        var listed = registry.Select(e => e.ToString()).ToList();
        var known = listed.ToHashSet(StringComparer.Ordinal);

        return
        [
            .. served.Where(r => !known.Contains(r)).Order(StringComparer.Ordinal)
                .Select(r => $"{host} serves {r}, which has no entry: add it to RouteRegistry with its cross-Tenant case (TenantPath, TargetTenant, HostResolved, or NotTenantBound with a reason)."),
            .. known.Where(e => !served.Contains(e)).Order(StringComparer.Ordinal)
                .Select(e => $"RouteRegistry lists {e}, which {host} no longer serves: remove the entry."),
            .. listed.GroupBy(e => e, StringComparer.Ordinal).Where(g => g.Count() > 1).OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => $"RouteRegistry lists {g.Key} {g.Count()} times: keep one entry."),
        ];
    }

    /// <summary>Marked endpoints listed as anything but TenantPath, and TenantPath entries whose endpoint isn't marked.</summary>
    internal static List<string> MarkerProblems(IReadOnlySet<string> marked, IEnumerable<RouteCase> registry) =>
    [
        .. registry.Where(e => marked.Contains(e.ToString()) && e.Kind != CaseKind.TenantPath)
            .Select(e => $"{e} carries TenantApiEndpoint but is {e.Kind}: give it the TenantPath case."),
        .. registry.Where(e => e.Kind == CaseKind.TenantPath && !marked.Contains(e.ToString()))
            .Select(e => $"{e} is TenantPath but its endpoint doesn't carry TenantApiEndpoint."),
    ];

    /// <summary>Every entry whose case kind doesn't fit its pattern or host.</summary>
    internal static List<string> KindProblems(IEnumerable<RouteCase> registry, bool hosted)
    {
        var problems = new List<string>();
        foreach (var entry in registry)
        {
            var parameters = RoutePatternFactory.Parse(entry.Pattern).Parameters.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var tenant = parameters.Contains("tenantId");
            var target = parameters.Contains("targetTenantId");
            var problem = entry.Kind switch
            {
                CaseKind.NotTenantBound when tenant || target => "is NotTenantBound but names a Tenant in its path: give it the TenantPath or TargetTenant case",
                CaseKind.NotTenantBound when string.IsNullOrWhiteSpace(entry.Reason) => "is NotTenantBound with no reason: say in one line why no Tenant names it",
                CaseKind.TenantPath when !tenant || target => "is TenantPath but its path has no {tenantId}",
                CaseKind.TargetTenant when !target || tenant => "is TargetTenant but its path has no {targetTenantId}",
                CaseKind.HostResolved when !hosted => "is HostResolved but isn't a Host.Hosted route",
                CaseKind.HostResolved when tenant || target => "is HostResolved but names a Tenant in its path: Host.Hosted takes its Tenant from the host only (AD-4)",
                CaseKind.TenantPath or CaseKind.TargetTenant when hosted => "is an Admin case on a Host.Hosted route: give it HostResolved",
                _ => null,
            };

            if (problem is not null)
            {
                problems.Add($"{entry} {problem}.");
            }
        }

        return problems;
    }
}
