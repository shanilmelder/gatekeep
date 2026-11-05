using System.Net;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Tests.Isolation.Admins;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.28 (FR-7, FR-46, AD-5, AD-19) on the real Host.Admin and PostgreSQL, with software
/// authenticators: a Tenant Owner changes a Tenant's label on <c>PUT /api/v1/tenants/{tenantId}/label</c>.
/// Raising it, Dev and Staging, and an unchanged label need no fresh assertion; removing Prod needs
/// one bound to that Session, action and Tenant, begun on the Tenant surface and used once. Only
/// <c>tenant.label</c> changes, and its event goes on the Tenant's own chain. Anyone but the Owner
/// is 403 and audited, a creating Tenant is 409, and every bad body is 400 with nothing used.
/// </summary>
public sealed class TenantLabelTests(PostgresFixture postgres)
{
    private const string LabelChanged = "tenancy.tenant.label_changed";
    private const string ProdRemoved = "tenancy.tenant.prod_label_removed";
    private const string Denied = "type_code = 'admin.access.denied'";

    [Fact]
    public async Task Raising_to_Prod_writes_only_the_label_and_label_changed_and_needs_no_grant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant);

        // Raising a label never asks for a grant; the one this Session held goes with the change.
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
        var before = await host.ScalarAsync<string>($"SELECT name || '|' || status || '|' || issuer || '|' || created_at::text FROM tenant WHERE id = '{tenant}'");

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "prod");

        Assert.Equal("prod", await LabelOfAsync(response));
        Assert.Equal("prod", await StoredLabelAsync(host, tenant));
        Assert.Equal(before, await host.ScalarAsync<string>($"SELECT name || '|' || status || '|' || issuer || '|' || created_at::text FROM tenant WHERE id = '{tenant}'"));
        Assert.Equal(
            $"1 admin {owner} tenant {tenant}",
            await host.ScalarAsync<string>(
                $"SELECT count(*) || ' ' || min(actor_kind) || ' ' || min(actor_id::text) || ' ' || min(target_kind) || ' ' || min(target_id::text) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{LabelChanged}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code LIKE 'tenancy.tenant.%label%'"));
        Assert.Equal(0L, await GrantsAsync(host));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = 'tenancy.tenant.prod_label_removed'"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Theory]
    [InlineData("dev", "staging")]
    [InlineData("staging", "dev")]
    [InlineData("staging", "prod")]
    public async Task Dev_and_Staging_changes_and_raising_need_no_confirmation(string from, string to)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, from);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, to);

        Assert.Equal(to, await LabelOfAsync(response));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, LabelChanged));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, ProdRemoved));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task An_unchanged_label_is_200_with_no_write_event_or_grant_used()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
        var xmin = await host.ScalarAsync<string>($"SELECT xmin::text FROM tenant WHERE id = '{tenant}'");

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "prod");

        Assert.Equal("prod", await LabelOfAsync(response));
        Assert.Equal(xmin, await host.ScalarAsync<string>($"SELECT xmin::text FROM tenant WHERE id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await GrantsAsync(host));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Removing_Prod_without_a_grant_is_403_and_changes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "staging");

        await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal("prod", await StoredLabelAsync(host, tenant));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Removing_Prod_after_a_Tenant_confirmation_writes_prod_label_removed_and_uses_the_grant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
        var verified = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.fresh_assertion.verified'");

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "staging");

        Assert.Equal("staging", await LabelOfAsync(response));
        Assert.Equal("staging", await StoredLabelAsync(host, tenant));
        Assert.Equal(
            $"1 admin {owner} tenant {tenant}",
            await host.ScalarAsync<string>(
                $"SELECT count(*) || ' ' || min(actor_kind) || ' ' || min(actor_id::text) || ' ' || min(target_kind) || ' ' || min(target_id::text) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{ProdRemoved}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, LabelChanged));
        Assert.True(verified >= 1);
        Assert.Equal(verified, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.fresh_assertion.verified'"));
        Assert.Equal(0L, await GrantsAsync(host));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_grant_removes_Prod_once()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);

        using (var removed = await SetLabelAsync(host, cookie, csrf, tenant, "dev"))
        {
            Assert.Equal("dev", await LabelOfAsync(removed));
        }

        using (var raised = await SetLabelAsync(host, cookie, csrf, tenant, "prod"))
        {
            Assert.Equal("prod", await LabelOfAsync(raised));
        }

        using var again = await SetLabelAsync(host, cookie, csrf, tenant, "dev");
        await FreshAssertionTests.AssertProblemAsync(again, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal("prod", await StoredLabelAsync(host, tenant));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, ProdRemoved));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_grant_for_one_Tenant_never_serves_another()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "prod");
        var b = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, a, b);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], a);

        using var other = await SetLabelAsync(host, cookie, csrf, b, "staging");

        await FreshAssertionTests.AssertProblemAsync(other, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal("prod", await StoredLabelAsync(host, b));
        Assert.Equal(1L, await GrantsAsync(host));

        // A's grant is still there for A.
        using var mine = await SetLabelAsync(host, cookie, csrf, a, "staging");
        Assert.Equal("staging", await LabelOfAsync(mine));
        Assert.All(authenticators, x => x.Dispose());
    }

    [Fact]
    public async Task An_expired_grant_is_403()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "UPDATE admin_fresh_assertion SET created_at = created_at - interval '6 minutes', expires_at = expires_at - interval '6 minutes'");

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "dev");

        await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal("prod", await StoredLabelAsync(host, tenant));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Removing_Prod_changes_no_row_but_the_label_and_the_audit_rows()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        await PostgresFixture.ExecuteAsync(host.Superuser, $"INSERT INTO tenant_settings (tenant_id) VALUES ('{tenant}')");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
        var tenantRow = $"SELECT (to_jsonb(t) - 'label')::text FROM tenant t WHERE id = '{tenant}'";
        var before = await SnapshotAsync(host);
        var row = await host.ScalarAsync<string>(tenantRow);

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "dev");

        Assert.Equal("dev", await LabelOfAsync(response));
        Assert.Equal(before, await SnapshotAsync(host));
        Assert.Equal(row, await host.ScalarAsync<string>(tenantRow));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Two_removals_racing_on_one_grant_remove_Prod_once()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);

        var responses = await Task.WhenAll(
            SetLabelAsync(host, cookie, csrf, tenant, "staging"),
            SetLabelAsync(host, cookie, csrf, tenant, "staging"),
            SetLabelAsync(host, cookie, csrf, tenant, "dev"));
        try
        {
            foreach (var response in responses)
            {
                Assert.True(
                    response.StatusCode is HttpStatusCode.OK or HttpStatusCode.Forbidden,
                    $"A racing removal answered {(int)response.StatusCode}.");
                if (response.StatusCode == HttpStatusCode.Forbidden)
                {
                    Assert.Equal("fresh_assertion_required", await CodeAsync(response));
                }
            }
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, ProdRemoved));
        Assert.NotEqual("prod", await StoredLabelAsync(host, tenant));
        Assert.Equal(0L, await GrantsAsync(host));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Theory]
    [InlineData("editor")]
    [InlineData("viewer")]
    public async Task Anyone_but_the_Owner_is_403_audited_and_changes_nothing(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, admin) = await RoleSessionAsync(host, tenant, role);

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "staging");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Equal("dev", await StoredLabelAsync(host, tenant));
        Assert.Equal(
            $"1 {admin} {tenant}",
            await host.ScalarAsync<string>($"SELECT count(*) || ' ' || min(actor_id::text) || ' ' || min(target_id::text) FROM deployment_audit_event WHERE {Denied}"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
    }

    [Fact]
    public async Task No_role_in_the_path_Tenant_is_403_whatever_the_header_says()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var mine = await InsertAsync(host, "dev");
        var other = await InsertAsync(host, "dev");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, mine);

        // The header names the Tenant the Admin owns: it still selects nothing (AD-19).
        foreach (var header in new[] { Id(other), Id(mine) })
        {
            using var response = await SetLabelAsync(host, cookie, csrf, other, "prod", header);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{other}'"));

        // An unknown Tenant and a malformed ID are refused alike.
        var unknown = Id(Guid.CreateVersion7());
        foreach (var path in new[] { unknown, "ten_x", "ten_" + new string('a', 26) })
        {
            using var response = await SetBodyAsync(host, cookie, csrf, LabelPath(path), """{"label":"prod"}""", path);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.Equal("dev", await StoredLabelAsync(host, mine));
        Assert.Equal("dev", await StoredLabelAsync(host, other));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_creating_Tenant_is_409_tenant_not_active_and_keeps_its_label()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev", status: "creating");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        using var response = await SetLabelAsync(host, cookie, csrf, tenant, "prod");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_not_active", await CodeAsync(response));
        Assert.Equal("dev", await StoredLabelAsync(host, tenant));

        // Its label still reads, whatever its status.
        using var read = await GetLabelAsync(host, cookie, tenant);
        Assert.Equal("dev", await LabelOfAsync(read));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Every_bad_body_is_400_tenant_invalid_with_nothing_written_or_used()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);

        foreach (var (body, contentType) in new[]
        {
            ("""{"label":"production"}""", "application/json"),
            ("""{"label":"Dev"}""", "application/json"),
            ("""{}""", "application/json"),
            ("""{"label":null}""", "application/json"),
            ("""{"label":1}""", "application/json"),
            ("""{"label":["dev"]}""", "application/json"),
            ("not json", "application/json"),
            ("", "application/json"),
            ("""{"label":"dev"}""", "text/plain"),
            ($$"""{"label":"dev","pad":"{{new string('p', 4096)}}"}""", "application/json"),
        })
        {
            using var response = await SetBodyAsync(host, cookie, csrf, LabelPath(tenant), body, Id(tenant), contentType);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("tenant_invalid", await CodeAsync(response));
        }

        Assert.Equal("prod", await StoredLabelAsync(host, tenant));
        Assert.Equal(1L, await GrantsAsync(host));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));

        // An unknown extra property is ignored.
        using var extra = await SetBodyAsync(host, cookie, csrf, LabelPath(tenant), """{"label":"prod","region":"eu"}""", Id(tenant));
        Assert.Equal("prod", await LabelOfAsync(extra));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Theory]
    [InlineData("viewer")]
    [InlineData("editor")]
    [InlineData("owner")]
    public async Task Any_role_reads_the_label_with_no_header(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "staging");
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, role);

        using var response = await GetLabelAsync(host, cookie, tenant);

        Assert.Equal("staging", await LabelOfAsync(response));
    }

    [Fact]
    public async Task A_role_less_label_read_is_403_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "staging");
        var (cookie, _, _) = await host.OwnerSessionAsync();

        using var response = await GetLabelAsync(host, cookie, tenant);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task No_Tenant_name_host_label_or_header_reaches_the_log()
    {
        const string Name = "Canary Tenant Zq81x";
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod", name: Name);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        var stray = Id(Guid.CreateVersion7());

        using (var list = await host.SendAsync(HttpMethod.Get, MyTenantsPath, cookie))
        {
            Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        }

        using (var mismatch = await SetLabelAsync(host, cookie, csrf, tenant, "dev", stray))
        {
            Assert.Equal(HttpStatusCode.Conflict, mismatch.StatusCode);
        }

        using (var refused = await SetLabelAsync(host, cookie, csrf, tenant, "staging"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
        using (var removed = await SetLabelAsync(host, cookie, csrf, tenant, "staging"))
        {
            Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        }

        await host.StopAsync();
        Assert.DoesNotContain(Name, host.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(TestTenants.Host(tenant), host.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(stray, host.Output, StringComparison.Ordinal);
        Assert.DoesNotContain("{Code}", host.Output, StringComparison.Ordinal);
        Assert.Contains("tenant_mismatch", host.Output, StringComparison.Ordinal);
        Assert.All(authenticators, a => a.Dispose());
    }

    /// <summary>
    /// Every table's rows, hashed, but the ones a removal is meant to touch: <c>tenant</c> (compared
    /// without its label), the audit chains, and the Session's own slide, grants and counts.
    /// </summary>
    private static async Task<string> SnapshotAsync(AdminHost host)
    {
        var skipped = new HashSet<string>(StringComparer.Ordinal)
        {
            "tenant", "audit_event", "audit_detail", "deployment_audit_event", "deployment_audit_detail",
            "admin_fresh_assertion", "admin_session", "admin_attempt", "migration_history",
        };
        var parts = new List<string>();
        foreach (var table in TableRegistry.Tables.Select(t => t.Name).Where(n => !skipped.Contains(n)).Order(StringComparer.Ordinal))
        {
            parts.Add(table + "=" + await host.ScalarAsync<string>($"SELECT md5(coalesce(string_agg(r::text, '|' ORDER BY r::text), '')) FROM \"{table}\" r"));
        }

        return string.Join("\n", parts);
    }
}
