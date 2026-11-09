using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;

namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>
/// One real Host.Admin on its own migrated database, with two active Tenants, A and B, shared by
/// every Admin case of <see cref="CrossTenantRouteTests"/>. Each case makes its own Admin, so the
/// per-Admin denial audit cap (Story 1.24) never counts one case against another.
/// </summary>
public sealed class CrossTenantAdmin(PostgresFixture postgres) : IAsyncLifetime
{
    private AdminHost? _host;

    internal AdminHost Host => _host ?? throw new InvalidOperationException("The Admin host isn't started.");

    public Guid TenantA { get; private set; }

    public Guid TenantB { get; private set; }

    public async ValueTask InitializeAsync()
    {
        _host = await AdminHost.StartAsync(postgres);
        TenantA = await TenantRequests.InsertAsync(_host, name: "Tenant A");
        TenantB = await TenantRequests.InsertAsync(_host, name: "Tenant B");
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }
    }
}

/// <summary>
/// Story 1.31 (FR-8, AD-4, AD-9, AD-19, AD-25, SM-2): the cross-Tenant case of every
/// <see cref="RouteRegistry"/> entry, driven from the registry, so a new entry runs its case with no
/// new test code. An Admin route naming Tenant B, called by an Admin who holds Owner in Tenant A
/// only and isn't the Deployment Owner, is refused with 403 <c>access_denied</c> and writes exactly
/// one <c>admin.access.denied</c> and nothing else, and B is unchanged. A <see cref="CaseKind.TargetTenant"/>
/// route is refused by Deployment Owner gating, so the same Admin gets the identical refusal for its
/// own Tenant A: those cases prove the Owner gate, and their event names no target Tenant (AD-19:
/// only <c>{tenantId}</c> names a path Tenant; the Tenant's own Log is Story 7.4). A Hosted route
/// asked on B's host answers with B's issuer and keys only, and the token endpoint refuses.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class CrossTenantRouteTests(PostgresFixture postgres, OpenBaoFixture bao, CrossTenantAdmin admin)
    : IClassFixture<CrossTenantAdmin>
{
    private const string HostA = "acme.cross-tenant.test";
    private const string HostB = "beta.cross-tenant.test";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string, string> AdminCases() => Cases(RouteRegistry.Admin, CaseKind.TenantPath, CaseKind.TargetTenant);

    public static TheoryData<string, string> HostedCases() => Cases(RouteRegistry.Hosted, CaseKind.HostResolved);

    [Fact]
    public void The_registry_has_Admin_and_Hosted_cases_to_run()
    {
        // The theories below run these; an empty set would pass them vacuously.
        Assert.NotEmpty(AdminCases());
        Assert.NotEmpty(HostedCases());
    }

    [Theory]
    [MemberData(nameof(AdminCases))]
    public async Task Admin_route_naming_Tenant_B_is_refused_and_audited_for_an_Owner_of_Tenant_A_only(string method, string pattern)
    {
        var entry = RouteRegistry.Admin.Single(e => e.Method == method && e.Pattern == pattern);
        var host = admin.Host;
        var (cookie, csrf, adminId) = await TenantRequests.RoleSessionAsync(host, admin.TenantA, "owner");
        Assert.False(await host.ScalarAsync<bool>($"SELECT deployment_owner FROM admin WHERE id = '{adminId}'"));
        var tenantB = PublicId.Format(PublicIdType.Tenant, admin.TenantB);
        var before = await StateOfBAsync(adminId);

        var path = PathFor(entry, tenantB);
        var stateChanging = method is not ("GET" or "HEAD");
        using var response = await host.SendAsync(
            new HttpMethod(method),
            path,
            cookie,
            stateChanging ? csrf : null,
            stateChanging ? AdminHost.Origin : null,
            entry.Body,
            headers: [(TenantRequests.Header, tenantB)]);

        Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{entry} at Tenant B answered {(int)response.StatusCode}.");
        Assert.Equal("access_denied", await TenantRequests.CodeAsync(response));

        // Exactly one event from this Admin: the refusal, on the Deployment chain.
        Assert.Equal(
            "1 admin.access.denied",
            await host.ScalarAsync<string>(
                $"SELECT count(*) || ' ' || coalesce(min(type_code), '') FROM deployment_audit_event WHERE actor_id = '{adminId}'"));
        var target = await host.ScalarAsync<string>(
            $"SELECT coalesce(target_kind || ' ' || target_id, 'none') FROM deployment_audit_event WHERE actor_id = '{adminId}'");
        Assert.Equal(
            entry.Kind == CaseKind.TenantPath
                ? $"tenant {admin.TenantB}"

                // A Deployment route's Tenant is never a path Tenant (AD-19), so its refusal targets none.
                : "none",
            target);

        // A Tenant-path refusal also goes on Tenant B's own Log, once, with this Admin as Actor (Story
        // 7.4, AD-9); a Deployment route has no path Tenant, so B's Log holds none from it.
        Assert.Equal(
            entry.Kind == CaseKind.TenantPath ? 1L : 0L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{admin.TenantB}' AND type_code = 'admin.cross_tenant.rejected' AND actor_id = '{adminId}'"));

        // Nothing else reached Tenant B or its Log.
        Assert.Equal(before, await StateOfBAsync(adminId));

        if (entry.Kind == CaseKind.TargetTenant)
        {
            // Deployment Owner gating refuses it, whatever the target: the same refusal for the
            // Admin's own Tenant A, so these cases prove the Owner gate, not a Tenant check.
            var tenantA = PublicId.Format(PublicIdType.Tenant, admin.TenantA);
            using var own = await host.SendAsync(
                new HttpMethod(method),
                PathFor(entry, tenantA),
                cookie,
                stateChanging ? csrf : null,
                stateChanging ? AdminHost.Origin : null,
                entry.Body,
                headers: [(TenantRequests.Header, tenantA)]);
            Assert.True(own.StatusCode == HttpStatusCode.Forbidden, $"{entry} at Tenant A answered {(int)own.StatusCode}.");
            Assert.Equal("access_denied", await TenantRequests.CodeAsync(own));
            Assert.Equal(
                2L,
                await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE actor_id = '{adminId}' AND type_code = 'admin.access.denied' AND target_id IS NULL"));
        }
    }

    [Theory]
    [MemberData(nameof(HostedCases))]
    public async Task Hosted_route_on_Tenant_B_s_host_carries_only_Tenant_B(string method, string pattern)
    {
        var entry = RouteRegistry.Hosted.Single(e => e.Method == method && e.Pattern == pattern);
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        var b = await database.AddTenantAsync(HostB);
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(bao, b.TenantId));
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        switch (entry.Pattern)
        {
            case ProtocolContract.ConfigurationPath:
            {
                using var response = await host.Http.GetAsync(new Uri($"http://{HostB}{entry.Pattern}"), Cancellation);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                using var document = JsonDocument.Parse(body);
                Assert.Equal(b.Issuer, document.RootElement.GetProperty("issuer").GetString());
                Assert.Equal($"{b.Issuer}.well-known/jwks", document.RootElement.GetProperty("jwks_uri").GetString());
                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                break;
            }

            case ProtocolContract.JsonWebKeySetPath:
            {
                using var response = await host.Http.GetAsync(new Uri($"http://{HostB}{entry.Pattern}"), Cancellation);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                using var document = JsonDocument.Parse(body);
                var kids = document.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()!).Order(StringComparer.Ordinal).ToList();
                Assert.Equal(await database.KeyIdsAsync(b.TenantId, "signing"), kids);
                Assert.Empty(kids.Intersect(await database.KeyIdsAsync(a.TenantId, "signing")));
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                break;
            }

            case ProtocolContract.TokenPath:
            {
                // Tenant A's real machine client, presented at B's host by Basic and by post: refused
                // with invalid_client, nothing issued, and the rejection logged in B's Log only, naming
                // nothing of A (Story 2.5).
                var client = await database.CreateClientAsync(a.TenantId);
                var eventsA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'");
                foreach (var how in new[] { "basic", "post" })
                {
                    using var refused = await ClientCredentialsTests.TokenAsync(host, HostB, client.ClientId, client.Secret, how);
                    Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
                    Assert.Equal("invalid_client", refused.Error);
                }

                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
                Assert.Equal(2L, await database.ScalarAsync<long>(
                    $"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}' AND type_code = 'protocol.client.cross_tenant_rejected' AND actor_kind = 'anonymous' AND target_id IS NULL"));
                Assert.Equal(eventsA, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'"));
                break;
            }

            case ProtocolContract.AuthorizePath:
            {
                // Tenant A's real web client, at B's host (Story 2.9): B doesn't know it, so the request gets
                // the static page, never a redirect to A's client, and naming nothing of A. Nothing begins.
                var client = await database.CreateWebClientAsync(a.TenantId, [CodeFlowSetup.Callback]);
                var user = await database.AddUserAsync(a.TenantId);
                using var response = await CodeFlow.AuthorizeAsync(host, HostB, client.ClientId, CodeFlowSetup.Callback, Pkce.New(), user, state: "cross-tenant");
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                Assert.Null(response.Headers.Location);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                Assert.Contains("Something went wrong", body, StringComparison.Ordinal);
                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(client.ClientId, body, StringComparison.Ordinal);
                Assert.DoesNotContain("cross-tenant", body, StringComparison.Ordinal);
                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
                break;
            }

            default:
                Assert.Fail($"{entry} is HostResolved but has no case here: add one to {nameof(Hosted_route_on_Tenant_B_s_host_carries_only_Tenant_B)}.");
                break;
        }
    }

    private static TheoryData<string, string> Cases(IEnumerable<RouteCase> registry, params CaseKind[] kinds)
    {
        var data = new TheoryData<string, string>();
        foreach (var entry in registry.Where(e => kinds.Contains(e.Kind)))
        {
            data.Add(entry.Method, entry.Pattern);
        }

        return data;
    }

    /// <summary>The entry's pattern with Tenant B in its Tenant parameter and its other values filled in.</summary>
    private static string PathFor(RouteCase entry, string tenant)
    {
        var path = entry.Pattern.Replace("{tenantId}", tenant, StringComparison.Ordinal)
            .Replace("{targetTenantId}", tenant, StringComparison.Ordinal);
        foreach (var (name, value) in entry.RouteValues ?? new Dictionary<string, string>())
        {
            path = path.Replace($"{{{name}}}", Uri.EscapeDataString(value), StringComparison.Ordinal);
        }

        Assert.DoesNotContain("{", path, StringComparison.Ordinal);
        return path;
    }

    /// <summary>
    /// Everything of Tenant B's a leaked call could change, as one value to compare before and after:
    /// its row, settings, roles, Operations, jobs, keys, own Log and the Deployment events naming it.
    /// Each piece is coalesced, so a missing row reads as a value and never makes the whole NULL. The
    /// caller's own refusal, asserted on its own, is left out of the Deployment events and, as its
    /// <c>admin.cross_tenant.rejected</c> (Story 7.4), of B's Log.
    /// </summary>
    private Task<string> StateOfBAsync(Guid caller) =>
        admin.Host.ScalarAsync<string>(
            $"""
            SELECT 'tenant ' || coalesce((SELECT name || '/' || status || '/' || label FROM tenant WHERE id = '{admin.TenantB}'), 'none')
                   || ' settings ' || coalesce((SELECT row_to_json(s)::text FROM tenant_settings AS s WHERE tenant_id = '{admin.TenantB}'), 'none')
                   || ' roles ' || coalesce((SELECT count(*) FROM tenant_role WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' operations ' || coalesce((SELECT count(*) FROM operation WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' steps ' || coalesce((SELECT count(*) FROM operation_step WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' jobs ' || coalesce((SELECT count(*) FROM job WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' keys ' || coalesce((SELECT count(*) FROM signing_key WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' events ' || coalesce((SELECT count(*) FROM audit_event WHERE tenant_id = '{admin.TenantB}' AND NOT (type_code = 'admin.cross_tenant.rejected' AND actor_id IS NOT DISTINCT FROM '{caller}'::uuid)), 0)
                   || ' deployment events ' || coalesce((SELECT count(*) FROM deployment_audit_event WHERE target_id = '{admin.TenantB}' AND coalesce(actor_id::text, '') <> '{caller}'), 0)
            """);
}
