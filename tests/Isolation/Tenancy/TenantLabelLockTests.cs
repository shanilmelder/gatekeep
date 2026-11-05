using System.Net;
using System.Text;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.28 review: the label change's lock and its grant. The row lock is
/// <c>FOR NO KEY UPDATE</c>, so a foreign-key insert referencing the Tenant and a label read never
/// wait behind it; once the gate has used up a grant, the change commits even if the client goes;
/// a change that needed no grant uses up any this Session holds, so a grant never serves a change
/// it wasn't earned for; and a Tenant begin can't carry a target its action's route never names.
/// </summary>
public sealed class TenantLabelLockTests(PostgresFixture postgres)
{
    private const string ProdRemoved = "tenancy.tenant.prod_label_removed";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_held_label_lock_blocks_no_foreign_key_insert_and_no_label_read()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");
        var (_, _, otherSession) = await host.InsertFullSessionAsync();
        var other = await host.AdminOfSessionAsync(otherSession);

        // A label change's transaction, holding the lock the production code takes.
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, host.Database));
        await using var change = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var state = await TenancyContract.CreateTenants(AuditContract.CreateAppender()).LockLabelAsync(change.CreateCommandContext(), tenant, Cancellation);
        Assert.Equal(TenantLabel.Prod, state!.Label);

        // A foreign-key insert takes FOR KEY SHARE on the Tenant: it must not wait.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SET lock_timeout = '3s'; INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{tenant}', '{other}', 'viewer')");
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM tenant_role WHERE tenant_id = '{tenant}' AND admin_id = '{other}'"));

        // Nor does a label read, which takes no lock.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var request = new HttpRequestMessage(HttpMethod.Get, LabelPath(tenant));
        request.Headers.TryAddWithoutValidation("Cookie", $"{AdminHost.Cookie}={cookie}");
        using var read = await host.Http.SendAsync(request, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
    }

    [Fact]
    public async Task A_client_gone_after_the_gate_never_leaves_the_grant_used_with_Prod_still_set()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        // Four confirmations: eight ceremony calls, under the Session's limit of ten.
        foreach (var delay in new[] { 0, 5, 20, 60 })
        {
            await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE tenant SET label = 'prod' WHERE id = '{tenant}'; DELETE FROM admin_fresh_assertion");
            await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);
            var before = await TenantEventsAsync(host, tenant, ProdRemoved);

            using var abort = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
            abort.CancelAfter(delay);
            using var request = new HttpRequestMessage(HttpMethod.Put, LabelPath(tenant))
            {
                Content = new StringContent("""{"label":"staging"}""", Encoding.UTF8, "application/json"),
            };
            request.Headers.TryAddWithoutValidation("Cookie", $"{AdminHost.Cookie}={cookie}");
            request.Headers.TryAddWithoutValidation(AdminHost.CsrfHeader, csrf);
            request.Headers.TryAddWithoutValidation("Origin", AdminHost.Origin);
            request.Headers.TryAddWithoutValidation(Header, Id(tenant));
            try
            {
                using var response = await host.Http.SendAsync(request, abort.Token);
            }
            catch (OperationCanceledException)
            {
                // The client went away: what the server does now is the point.
            }

            // Settled one way or the other: Prod with the grant still there, or Prod removed.
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (true)
            {
                var label = await StoredLabelAsync(host, tenant);
                var grants = await GrantsAsync(host);
                if (label != "prod" || grants == 1)
                {
                    break;
                }

                Assert.True(DateTime.UtcNow < deadline, $"After an abort at {delay}ms the grant is used up and the Tenant is still Prod.");
                await Task.Delay(200, Cancellation);
            }

            // A removal and its event go together.
            await Task.Delay(500, Cancellation);
            Assert.Equal(await StoredLabelAsync(host, tenant) == "prod" ? 0L : 1L, await TenantEventsAsync(host, tenant, ProdRemoved) - before);
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_change_that_needed_no_grant_uses_up_the_grant_so_a_later_removal_needs_a_new_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);

        // Another Owner removes Prod, as the superuser stands in for them.
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE tenant SET label = 'staging' WHERE id = '{tenant}'");

        // This Session makes a change that needs no grant: the one it holds goes with it.
        using (var change = await SetLabelAsync(host, cookie, csrf, tenant, "dev"))
        {
            Assert.Equal("dev", await LabelOfAsync(change));
        }

        Assert.Equal(0L, await GrantsAsync(host));

        // The other Owner makes it Prod again: this Session's removal needs a new confirmation.
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE tenant SET label = 'prod' WHERE id = '{tenant}'");
        using var removal = await SetLabelAsync(host, cookie, csrf, tenant, "staging");
        await FreshAssertionTests.AssertProblemAsync(removal, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal("prod", await StoredLabelAsync(host, tenant));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, ProdRemoved));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task An_unchanged_label_keeps_the_grant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        await ConfirmAsync(host, cookie, csrf, authenticators[0], tenant);

        using var unchanged = await SetLabelAsync(host, cookie, csrf, tenant, "prod");

        Assert.Equal("prod", await LabelOfAsync(unchanged));
        Assert.Equal(1L, await GrantsAsync(host));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_Tenant_begin_with_a_target_its_action_never_takes_is_400_with_no_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        var (response, _) = await BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":"staging"}""");
        using (response)
        {
            await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.BadRequest, "assertion_refused");
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task The_label_read_names_the_status()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var active = await InsertAsync(host, "dev");
        var creating = await InsertAsync(host, "staging", status: "creating");
        var (cookie, _, admin) = await RoleSessionAsync(host, active, "viewer");
        await host.GrantTenantRoleAsync(creating, admin, "viewer");

        foreach (var (tenant, expected) in new[] { (active, "{\"label\":\"dev\",\"status\":\"active\"}"), (creating, "{\"label\":\"staging\",\"status\":\"creating\"}") })
        {
            using var response = await GetLabelAsync(host, cookie, tenant);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(expected, await response.Content.ReadAsStringAsync(Cancellation));
        }
    }
}
