using System.Net;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.28 (FR-9, AD-4, AD-19): every Admin-Session state-changing request on the Tenant
/// surface carries <c>X-Gatekeep-Tenant</c>, the Tenant the page shows. The request checks compare
/// it, as a string, with the <c>{tenantId}</c> path segment, after the capability decision and
/// before any grant is used: missing, sent twice or different is 409 <c>tenant_mismatch</c>, with
/// nothing run, nothing audited and neither value logged. A capability refusal, a bad CSRF token
/// and a bad Origin still come first. Reads never need it, and it never selects a Tenant.
/// </summary>
public sealed class TenantMismatchTests(PostgresFixture postgres)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_missing_different_or_repeated_page_Tenant_is_409_and_nothing_runs()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "prod");
        var b = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, a, b);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], a);
        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");

        foreach (var header in new[] { Id(b), NoHeader, Id(a).ToUpperInvariant(), $"{Id(a)}, {Id(a)}", "" })
        {
            using var response = await SetLabelAsync(host, cookie, csrf, a, "staging", header);
            Assert.True(response.StatusCode == HttpStatusCode.Conflict, $"Header '{header}' answered {(int)response.StatusCode}.");
            Assert.Equal("tenant_mismatch", await CodeAsync(response));
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        }

        // Sent as two header lines, too.
        using (var twice = await host.SendAsync(
            HttpMethod.Put, LabelPath(a), cookie, csrf, AdminHost.Origin, """{"label":"staging"}""", [(Header, Id(a)), (Header, Id(a))]))
        {
            Assert.Equal(HttpStatusCode.Conflict, twice.StatusCode);
            Assert.Equal("tenant_mismatch", await CodeAsync(twice));
        }

        // Nothing changed, nothing was audited, and the grant held for A is still unused.
        Assert.Equal("prod", await StoredLabelAsync(host, a));
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id IN ('{a}', '{b}')"));
        Assert.Equal(1L, await GrantsAsync(host));

        using (var matched = await SetLabelAsync(host, cookie, csrf, a, "staging"))
        {
            Assert.Equal("staging", await LabelOfAsync(matched));
        }

        Assert.Equal(0L, await GrantsAsync(host));
        Assert.All(authenticators, x => x.Dispose());
    }

    [Fact]
    public async Task A_capability_refusal_and_the_CSRF_check_come_before_the_mismatch()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var mine = await InsertAsync(host);
        var other = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, mine);

        // A role-less path Tenant with a mismatched header: still the audited access_denied.
        using (var denied = await SetLabelAsync(host, cookie, csrf, other, "prod", Id(mine)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(denied));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND target_id = '{other}'"));

        // A wrong CSRF token or Origin with a mismatched header: the bodiless 403.
        foreach (var (token, origin) in new[] { ("wrong", AdminHost.Origin), (csrf, "https://evil.example") })
        {
            using var forbidden = await host.SendAsync(
                HttpMethod.Put, LabelPath(mine), cookie, token, origin, """{"label":"prod"}""", [(Header, Id(other))]);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
            Assert.Empty(await forbidden.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Reads_need_no_page_Tenant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "staging");
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        using (var label = await GetLabelAsync(host, cookie, tenant))
        {
            Assert.Equal("staging", await LabelOfAsync(label));
        }

        using (var capabilities = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{Id(tenant)}/capabilities", cookie))
        {
            Assert.Equal(HttpStatusCode.OK, capabilities.StatusCode);
        }

        // An unknown Operation is the 404 it always was, not a mismatch.
        var operation = PublicId.Format(PublicIdType.Operation, Guid.CreateVersion7());
        using var read = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{Id(tenant)}/operations/{operation}", cookie, headers: [(Header, "ten_other")]);
        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
    }

    [Fact]
    public async Task The_page_Tenant_never_selects_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, b);

        // Owner of B only: a write on A naming A as the page's Tenant is A's, and refused.
        using var response = await SetLabelAsync(host, cookie, csrf, a, "prod", Id(a));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Equal("dev", await StoredLabelAsync(host, a));
        Assert.Equal("dev", await StoredLabelAsync(host, b));
        Assert.All(authenticators, x => x.Dispose());
    }
}
