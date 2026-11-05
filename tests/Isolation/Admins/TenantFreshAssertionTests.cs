using System.Net;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.28 (FR-46, AD-19, AD-20): the Tenant-surface fresh-assertion begin,
/// <c>POST /api/v1/tenants/{tenantId}/assertions</c>, on the real Host.Admin. Any Tenant Role
/// reaches it; it begins only a Tenant capability action whose fresh assertion isn't never, bound
/// to the path Tenant, after deciding that action's capability from the same role read. Everything
/// else is 400 with no challenge stored, a refused capability is 403 and audited against the path
/// Tenant, the Session's limit is shared with the Deployment ceremony, and the Deployment begin
/// still refuses Tenant actions.
/// </summary>
public sealed class TenantFreshAssertionTests(PostgresFixture postgres)
{
    [Theory]
    [InlineData("""{"action":"tenant.configuration.read","target":null}""", "application/json")]
    [InlineData("""{"action":"deployment.tenants.delete","target":null}""", "application/json")]
    [InlineData("""{"action":"self.credentials.add","target":null}""", "application/json")]
    [InlineData("""{"action":"nope","target":null}""", "application/json")]
    [InlineData("""{"target":null}""", "application/json")]
    [InlineData("not json", "application/json")]
    [InlineData("""{"action":"tenant.label.manage","target":null}""", "text/plain")]
    public async Task Anything_but_a_Tenant_fresh_assertion_action_is_400_with_no_challenge(string body, string contentType)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        var (response, _) = await BeginAsync(host, cookie, csrf, tenant, body, contentType: contentType);
        using (response)
        {
            await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.BadRequest, "assertion_refused");
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task An_Editor_beginning_tenant_label_manage_is_403_audited_against_the_Tenant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, admin) = await RoleSessionAsync(host, tenant, "editor");

        var (response, _) = await BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":null}""");
        using (response)
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.Equal(
            $"1 {admin} tenant {tenant}",
            await host.ScalarAsync<string>(
                "SELECT count(*) || ' ' || min(actor_id::text) || ' ' || min(target_kind) || ' ' || min(target_id::text) FROM deployment_audit_event WHERE type_code = 'admin.access.denied'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
    }

    [Fact]
    public async Task A_role_less_path_Tenant_is_403_before_the_handler()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host);

        var (response, _) = await BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":null}""");
        using (response)
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task The_Owners_begin_is_bound_to_the_path_Tenant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        var (response, options) = await BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":null}""");
        using (response)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.Equal("required", options.GetProperty("userVerification").GetString());
            Assert.Equal(0, options.GetProperty("allowCredentials").GetArrayLength());
        }

        // The challenge row carries the binding hash, which names this Tenant.
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM admin_fresh_assertion WHERE binding_hash = sha256(convert_to(E'tenant.label.manage\\n{Id(tenant)}\\n', 'UTF8'))"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task The_eleventh_ceremony_call_in_15_minutes_is_429()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        const string Body = """{"action":"tenant.label.manage","target":null}""";

        // The Owner's setup already made no ceremony calls in this Session: ten pass, the eleventh doesn't.
        for (var i = 0; i < 10; i++)
        {
            var (begin, _) = await BeginAsync(host, cookie, csrf, tenant, Body);
            using (begin)
            {
                Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            }
        }

        var (limited, _) = await BeginAsync(host, cookie, csrf, tenant, Body);
        using (limited)
        {
            await FreshAssertionTests.AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
            Assert.NotNull(limited.Headers.RetryAfter);
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task The_Deployment_begin_still_refuses_a_Tenant_action()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);

        var (response, _) = await host.BeginAssertionAsync(cookie, csrf, "tenant.label.manage");
        using (response)
        {
            await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.BadRequest, "assertion_refused");
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_mismatched_page_Tenant_is_409_with_no_challenge_and_no_count()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var other = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant, other);

        var (response, _) = await BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":null}""", Id(other));
        using (response)
        {
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal("tenant_mismatch", await CodeAsync(response));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.All(authenticators, a => a.Dispose());
    }
}
