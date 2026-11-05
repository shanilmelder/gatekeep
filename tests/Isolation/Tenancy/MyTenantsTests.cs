using System.Net;
using System.Text.Json;
using Gatekeep.Tests.Isolation.Admins;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.28 (FR-9, AD-20) on the real Host.Admin and PostgreSQL: <c>GET /api/v1/deployment/my-tenants</c>
/// lists the active Tenants the current Admin holds a Tenant Role in, oldest first, with each one's ID,
/// name, stored host and label, and never the role or a status. It is self-service: the Deployment
/// Owner holding no role, and every other Admin with none, get an empty list. It is read again on
/// every call, so a removed role and a changed label show at once.
/// </summary>
public sealed class MyTenantsTests(PostgresFixture postgres)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Lists_only_the_active_Tenants_the_Admin_holds_a_role_in_oldest_first()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        // Inserted newest first, then made older by the superuser: the order is creation time, not insertion.
        var c = await InsertAsync(host, "staging", name: "Gamma");
        var b = await InsertAsync(host, "dev", status: "creating", name: "Beta");
        var a = await InsertAsync(host, "prod", name: "Alpha");
        var d = await InsertAsync(host, "dev", name: "Delta");
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SET session_replication_role = replica; UPDATE tenant SET created_at = created_at - interval '1 day' WHERE id = '{a}'; SET session_replication_role = DEFAULT");
        Assert.True(await host.ScalarAsync<bool>($"SELECT (SELECT created_at FROM tenant WHERE id = '{a}') < (SELECT created_at FROM tenant WHERE id = '{c}')"));
        var (cookie, _, admin) = await RoleSessionAsync(host, a, "viewer");
        await host.GrantTenantRoleAsync(b, admin, "owner");
        await host.GrantTenantRoleAsync(c, admin, "editor");
        var (_, _, otherSession) = await host.InsertFullSessionAsync();
        await host.GrantTenantRoleAsync(d, await host.AdminOfSessionAsync(otherSession), "owner");

        using var response = await host.SendAsync(HttpMethod.Get, MyTenantsPath, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["tenants"], json.RootElement.EnumerateObject().Select(p => p.Name));
        var tenants = json.RootElement.GetProperty("tenants").EnumerateArray().ToList();
        Assert.Equal(
            [
                $"{Id(a)}|Alpha|{TestTenants.Host(a)}|prod",
                $"{Id(c)}|Gamma|{TestTenants.Host(c)}|staging",
            ],
            tenants.Select(t => $"{t.GetProperty("id").GetString()}|{t.GetProperty("name").GetString()}|{t.GetProperty("host").GetString()}|{t.GetProperty("label").GetString()}"));
        Assert.All(tenants, t => Assert.Equal(["id", "name", "host", "label"], t.EnumerateObject().Select(p => p.Name)));
    }

    [Fact]
    public async Task The_Owner_with_no_role_and_any_other_Admin_with_none_get_an_empty_list()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await InsertAsync(host, "dev");
        var (owner, _, _) = await host.OwnerSessionAsync();
        var (other, _, _) = await host.InsertFullSessionAsync();

        foreach (var cookie in new[] { owner, other })
        {
            using var response = await host.SendAsync(HttpMethod.Get, MyTenantsPath, cookie);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("""{"tenants":[]}""", await response.Content.ReadAsStringAsync(Cancellation));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied'"));
    }

    [Fact]
    public async Task A_restricted_Session_is_403_and_no_Session_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (setup, _, _) = await host.ClaimedAsync();

        using (var restricted = await host.SendAsync(HttpMethod.Get, MyTenantsPath, setup))
        {
            Assert.Equal(HttpStatusCode.Forbidden, restricted.StatusCode);
            Assert.Empty(await restricted.Content.ReadAsByteArrayAsync(Cancellation));
        }

        using var anonymous = await host.SendAsync(HttpMethod.Get, MyTenantsPath);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task A_removed_role_and_a_changed_label_show_on_the_next_read()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "dev");
        var b = await InsertAsync(host, "dev");
        var (cookie, _, admin) = await RoleSessionAsync(host, a, "owner");
        await host.GrantTenantRoleAsync(b, admin, "viewer");
        Assert.Equal([$"{Id(a)} dev", $"{Id(b)} dev"], await ListAsync(host, cookie));

        await host.RevokeTenantRoleAsync(b, admin);
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE tenant SET label = 'prod' WHERE id = '{a}'");

        Assert.Equal([$"{Id(a)} prod"], await ListAsync(host, cookie));
    }

    private static async Task<List<string>> ListAsync(AdminHost host, string cookie)
    {
        using var response = await host.SendAsync(HttpMethod.Get, MyTenantsPath, cookie);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return [.. json.RootElement.GetProperty("tenants").EnumerateArray().Select(t => $"{t.GetProperty("id").GetString()} {t.GetProperty("label").GetString()}")];
    }
}
