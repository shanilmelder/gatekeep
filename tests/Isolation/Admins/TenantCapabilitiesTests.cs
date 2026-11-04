using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Admins.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.24, AD-4, AD-9, AD-19, AD-20, FR-39: capabilities on the real <c>Host.Admin</c> and
/// PostgreSQL. <c>GET /api/v1/tenants/{tenantId}/capabilities</c> takes its Tenant from the path's
/// public ID only and returns the Tenant Role's capabilities there, in the table's order, read on
/// every request. A role in another Tenant, an unknown Tenant, a malformed ID and a Deployment
/// Owner with no role there all get the one 403 <c>access_denied</c> and write one
/// <c>admin.access.denied</c>, targeting the path Tenant when the ID was well-formed. The setup
/// gate and the Session check come first, unaudited. <c>GET /api/v1/deployment/capabilities</c>
/// lists every Deployment capability for the Owner and none for another Admin, and self-service
/// routes answer a non-Owner as they answer the Owner. Unknown API paths stay the 404.
/// </summary>
public sealed class TenantCapabilitiesTests(PostgresFixture postgres)
{
    private const string DeploymentCapabilities = "/api/v1/deployment/capabilities";
    private const string Denied = "type_code = 'admin.access.denied'";

    private static readonly string[] ViewerSet = ["tenant.configuration.read", "tenant.users.read", "tenant.logs.read"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Viewer_reads_exactly_the_Viewer_capabilities_in_table_order()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(tenant, admin, "viewer");

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal(ViewerSet, await CapabilitiesAsync(response));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
    }

    [Theory]
    [InlineData("editor", TenantRole.Editor)]
    [InlineData("owner", TenantRole.Owner)]
    public async Task Editor_and_Owner_read_exactly_their_rows(string role, TenantRole tenantRole)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(tenant, admin, role);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var expected = AdminCapabilities.All.Where(c => c.Scope == CapabilityScope.Tenant && c.Roles.Contains(tenantRole)).Select(c => c.Name).ToList();
        Assert.Equal(expected, await CapabilitiesAsync(response));
        Assert.Equal(tenantRole == TenantRole.Owner ? 26 : 14, expected.Count);
    }

    [Fact]
    public async Task Role_in_another_Tenant_is_refused_and_audited_against_the_path_Tenant_only()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var mine = await host.InsertTenantAsync();
        var other = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(mine, admin, "owner");
        var before = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");

        // No header or query string can name a Tenant: only the path does (AD-4).
        var mineId = PublicId.Format(PublicIdType.Tenant, mine);
        using var response = await host.SendAsync(
            HttpMethod.Get,
            $"{PathFor(other)}?tenantId={mineId}",
            cookie,
            headers: [("X-Gatekeep-Tenant", mineId)]);

        var traceId = await AssertAccessDeniedAsync(response);
        Assert.Equal(before + 1, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        Assert.Equal(
            $"admin {admin} tenant {other}",
            await host.ScalarAsync<string>($"SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE {Denied}"));
        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_detail AS d JOIN deployment_audit_event AS e ON e.id = d.event_id WHERE e.{Denied}"));

        // The capability and trace go only in the log line, under their own placeholders.
        Assert.Contains($"refused with access_denied for tenant.configuration.read, audited True, trace {traceId}", host.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(cookie, host.Output, StringComparison.Ordinal);

        // The Tenant the role is in still answers.
        using var allowed = await host.SendAsync(HttpMethod.Get, PathFor(mine), cookie);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [Fact]
    public async Task Unknown_Tenant_gets_the_same_refusal_and_its_event_targets_the_path_ID()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var known = await host.InsertTenantAsync();
        var unknown = Guid.CreateVersion7();

        using var refusedKnown = await host.SendAsync(HttpMethod.Get, PathFor(known), cookie);
        using var refusedUnknown = await host.SendAsync(HttpMethod.Get, PathFor(unknown), cookie);

        await AssertAccessDeniedAsync(refusedKnown);
        await AssertAccessDeniedAsync(refusedUnknown);
        Assert.Equal(await ShapeAsync(refusedKnown), await ShapeAsync(refusedUnknown));
        Assert.Equal(
            $"tenant {unknown}",
            await host.ScalarAsync<string>($"SELECT target_kind || ' ' || target_id FROM deployment_audit_event WHERE {Denied} AND target_id = '{unknown}'"));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND actor_id = '{admin}'"));
    }

    public static TheoryData<string> MalformedTenantIds()
    {
        var canonical = PublicId.Format(PublicIdType.Tenant, Guid.Parse("01900000-0000-7000-8000-0000000007a8"));
        var body = canonical["ten_".Length..];
        return
        [
            canonical.ToUpperInvariant(),
            "ten_" + body.ToUpperInvariant(),
            canonical + "======",
            canonical[..^1],
            canonical + "a",
            "usr_" + body,
            canonical[..^1] + "b",
            "01900000-0000-7000-8000-0000000007a8",
            "ten_" + new string('a', 26),
        ];
    }

    [Theory]
    [MemberData(nameof(MalformedTenantIds))]
    public async Task Malformed_Tenant_ID_gets_the_same_refusal_and_an_event_with_no_target(string tenantId)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(tenant, admin, "owner");

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));

        using var malformed = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{Uri.EscapeDataString(tenantId)}/capabilities", cookie);

        // This request wrote exactly one event, and it has no target.
        await AssertAccessDeniedAsync(malformed);
        Assert.Equal(
            $"1 admin {admin} t",
            await host.ScalarAsync<string>(
                $"""
                SELECT count(*) || ' ' || min(actor_kind) || ' ' || min(actor_id::text) || ' '
                       || bool_and(target_kind IS NULL AND target_id IS NULL)::text::char
                FROM deployment_audit_event WHERE {Denied}
                """));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));

        using var unknown = await host.SendAsync(HttpMethod.Get, PathFor(Guid.CreateVersion7()), cookie);
        Assert.Equal(await ShapeAsync(unknown), await ShapeAsync(malformed));
    }

    [Fact]
    public async Task Deployment_Owner_gets_nothing_in_a_Tenant_without_a_role_and_only_the_role_with_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, owner) = await host.OwnerSessionAsync();
        var tenant = await host.InsertTenantAsync();

        using (var refused = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie))
        {
            await AssertAccessDeniedAsync(refused);
        }

        Assert.Equal($"tenant {tenant}", await host.ScalarAsync<string>($"SELECT target_kind || ' ' || target_id FROM deployment_audit_event WHERE {Denied}"));

        await host.GrantTenantRoleAsync(tenant, owner, "viewer");
        using var viewer = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);
        Assert.Equal(HttpStatusCode.OK, viewer.StatusCode);
        Assert.Equal(ViewerSet, await CapabilitiesAsync(viewer));
    }

    [Fact]
    public async Task Role_removed_mid_session_counts_on_the_next_request()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(tenant, admin, "editor");

        using (var first = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        await host.RevokeTenantRoleAsync(tenant, admin);

        using var second = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);
        await AssertAccessDeniedAsync(second);
    }

    [Fact]
    public async Task Restricted_Session_is_refused_by_the_setup_gate_first_and_nothing_is_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (setup, _, owner) = await host.ClaimedAsync();
        var tenant = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(tenant, owner, "owner");
        var (oneCredential, _, session) = await host.InsertFullSessionAsync(credentials: 1);
        await host.GrantTenantRoleAsync(tenant, await host.AdminOfSessionAsync(session), "owner");

        foreach (var cookie in new[] { setup, oneCredential })
        {
            using var response = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
    }

    [Fact]
    public async Task No_or_unknown_Session_is_401_and_nothing_is_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var tenant = await host.InsertTenantAsync();

        using (var none = await host.SendAsync(HttpMethod.Get, PathFor(tenant)))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);
            Assert.Empty(await none.Content.ReadAsByteArrayAsync(Cancellation));
        }

        using (var unknown = await host.SendAsync(HttpMethod.Get, PathFor(tenant), AdminHost.Unissued()))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
            Assert.Contains("Max-Age=0", Assert.Single(unknown.Headers.GetValues("Set-Cookie")), StringComparison.Ordinal);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
    }

    [Fact]
    public async Task Deployment_capabilities_are_every_one_for_the_Owner_in_table_order()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();

        using var response = await host.SendAsync(HttpMethod.Get, DeploymentCapabilities, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            [
                "deployment.tenants.read",
                "deployment.tenants.create",
                "deployment.tenants.delete",
                "deployment.admins.read",
                "deployment.admins.manage",
                "deployment.email_provider.manage",
                "deployment.incident_response.run",
                "deployment.log.read",
            ],
            await CapabilitiesAsync(response));
    }

    [Fact]
    public async Task Deployment_capabilities_are_none_for_another_Admin_whatever_their_Tenant_Roles()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (cookie, admin) = await AdminAsync(host);
        await host.GrantTenantRoleAsync(await host.InsertTenantAsync(), admin, "owner");

        using var response = await host.SendAsync(HttpMethod.Get, DeploymentCapabilities, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""{"capabilities":[]}""", await response.Content.ReadAsStringAsync(Cancellation));
    }

    [Fact]
    public async Task Self_service_routes_answer_a_non_Owner_as_they_answer_the_Owner()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (ownerCookie, ownerCsrf, _) = await host.OwnerSessionAsync();
        var (adminCookie, adminCsrf, _) = await host.InsertFullSessionAsync();

        foreach (var (cookie, csrf) in new[] { (ownerCookie, ownerCsrf), (adminCookie, adminCsrf) })
        {
            using (var session = await host.SendAsync(HttpMethod.Get, "/api/v1/deployment/session", cookie))
            {
                Assert.Equal(HttpStatusCode.OK, session.StatusCode);
            }

            // Both already hold two credentials: a third is refused alike, not Owner-gated.
            using (var registration = await host.SendAsync(HttpMethod.Post, AdminHost.RegistrationPath, cookie, csrf, AdminHost.Origin))
            {
                Assert.Equal(HttpStatusCode.Forbidden, registration.StatusCode);
            }

            using (var signOut = await host.SendAsync(HttpMethod.Delete, "/api/v1/deployment/session", cookie, csrf, AdminHost.Origin))
            {
                Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);
            }
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
    }

    [Theory]
    [InlineData("/nope")]
    [InlineData("")]
    [InlineData("/capabilities/more")]
    public async Task Unknown_Tenant_API_path_is_the_404_never_the_bundle(string suffix)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(tenant, admin, "owner");

        foreach (var path in new[] { $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, tenant)}{suffix}", "/api/v1/other", "/api/v2/tenants" })
        {
            using var response = await host.SendAsync(HttpMethod.Get, path, cookie);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
    }

    [Fact]
    public async Task Refusals_past_the_audit_cap_are_still_refused_alike_but_only_logged()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var (otherCookie, other) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        var cap = Gatekeep.Kernel.Limits.SecurityLimits.AdminAccessDeniedAuditAttempts;

        string? first = null;
        for (var i = 0; i < cap; i++)
        {
            using var refused = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);
            await AssertAccessDeniedAsync(refused);
            first ??= await ShapeAsync(refused);
        }

        Assert.Equal((long)cap, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND actor_id = '{admin}'"));

        // Past the cap: the same 403 body, no event, and the log line says it wasn't audited.
        using var over = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);
        var traceId = await AssertAccessDeniedAsync(over);
        Assert.Equal(first, await ShapeAsync(over));
        Assert.Equal((long)cap, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND actor_id = '{admin}'"));
        Assert.Contains($"refused with access_denied for tenant.configuration.read, audited False, trace {traceId}", host.Output, StringComparison.Ordinal);
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt WHERE policy = 'admins.access.denial_audit'"));

        // The cap is per Admin: another Admin's refusal is still audited.
        using (var others = await host.SendAsync(HttpMethod.Get, PathFor(tenant), otherCookie))
        {
            await AssertAccessDeniedAsync(others);
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND actor_id = '{other}'"));
    }

    [Fact]
    public async Task Audit_failure_on_a_refusal_is_503_and_rolls_back_the_slide()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, admin) = await AdminAsync(host);
        var tenant = await host.InsertTenantAsync();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"UPDATE admin_session SET idle_expires_at = idle_expires_at - interval '5 minutes' WHERE admin_id = '{admin}'");
        var idle = await host.ScalarAsync<string>($"SELECT idle_expires_at::text FROM admin_session WHERE admin_id = '{admin}'");

        // Stands in for a fault at the denial's event, after the Session was authenticated and slid.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            """
            CREATE FUNCTION test_fail_access_denied() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN
              IF NEW.type_code = 'admin.access.denied' THEN
                RAISE EXCEPTION 'refused by the test';
              END IF;
              RETURN NEW;
            END
            $body$;
            CREATE TRIGGER test_fail_access_denied BEFORE INSERT ON deployment_audit_event
              FOR EACH ROW EXECUTE FUNCTION test_fail_access_denied();
            """);

        using (var failed = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
            Assert.Empty(await failed.Content.ReadAsByteArrayAsync(Cancellation));
        }

        // Rolled back: no event, no count, and the slide undone with it.
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt WHERE policy = 'admins.access.denial_audit'"));
        Assert.Equal(idle, await host.ScalarAsync<string>($"SELECT idle_expires_at::text FROM admin_session WHERE admin_id = '{admin}'"));

        await PostgresFixture.ExecuteAsync(host.Superuser, "DROP TRIGGER test_fail_access_denied ON deployment_audit_event");
        using var again = await host.SendAsync(HttpMethod.Get, PathFor(tenant), cookie);
        await AssertAccessDeniedAsync(again);
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}"));
        Assert.NotEqual(idle, await host.ScalarAsync<string>($"SELECT idle_expires_at::text FROM admin_session WHERE admin_id = '{admin}'"));
    }

    [Fact]
    public async Task Case_and_trailing_slash_variants_are_checked_alike_or_the_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _) = await AdminAsync(host);
        var tenant = PublicId.Format(PublicIdType.Tenant, await host.InsertTenantAsync());

        foreach (var path in new[]
        {
            $"/API/V1/TENANTS/{tenant}/CAPABILITIES",
            $"/Api/v1/Tenants/{tenant}/Capabilities",
            $"/api/v1/tenants/{tenant}/capabilities/",
            $"/API/V1/TENANTS/{tenant}/CAPABILITIES/",
            $"/api/v1/tenants/{tenant}//capabilities",
        })
        {
            var before = await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}");
            using var response = await host.SendAsync(HttpMethod.Get, path, cookie);

            // The role-less Admin is refused and audited by the same checks, or it's the unknown path.
            Assert.True(
                response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound,
                $"{path} answered {(int)response.StatusCode}.");
            Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
            var after = await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied}");
            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                await AssertAccessDeniedAsync(response);
                Assert.Equal(before + 1, after);
            }
            else
            {
                Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
                Assert.Equal(before, after);
            }
        }
    }

    [Fact]
    public async Task Static_files_never_serve_a_path_under_api()
    {
        var root = Directory.CreateTempSubdirectory("gatekeep-admin-webroot-").FullName;
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "index.html"), "<!doctype html><title>bundle</title>", Cancellation);
            await File.WriteAllTextAsync(Path.Combine(root, "probe.txt"), "served", Cancellation);
            Directory.CreateDirectory(Path.Combine(root, "api", "v1"));
            await File.WriteAllTextAsync(Path.Combine(root, "api", "v1", "probe.txt"), "leaked", Cancellation);
            Directory.CreateDirectory(Path.Combine(root, "API"));
            await File.WriteAllTextAsync(Path.Combine(root, "API", "probe.txt"), "leaked", Cancellation);

            await using var host = await AdminHost.StartAsync(postgres, null, $"--webroot={root}");

            // The web root is this one: a file outside /api is served.
            using (var served = await host.SendAsync(HttpMethod.Get, "/probe.txt"))
            {
                Assert.Equal(HttpStatusCode.OK, served.StatusCode);
                Assert.Equal("served", await served.Content.ReadAsStringAsync(Cancellation));
            }

            foreach (var path in new[] { "/api/v1/probe.txt", "/API/probe.txt", "/Api/v1/probe.txt" })
            {
                using var response = await host.SendAsync(HttpMethod.Get, path);
                Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
                Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>A full Session of an Admin who isn't the Owner, and that Admin.</summary>
    private static async Task<(string Cookie, Guid AdminId)> AdminAsync(AdminHost host)
    {
        var (cookie, _, session) = await host.InsertFullSessionAsync();
        return (cookie, await host.AdminOfSessionAsync(session));
    }

    private static string PathFor(Guid tenant) => $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, tenant)}/capabilities";

    private static async Task<List<string>> CapabilitiesAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["capabilities"], json.RootElement.EnumerateObject().Select(p => p.Name));
        return [.. json.RootElement.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()!)];
    }

    /// <summary>Asserts the one 403 <c>access_denied</c>: a problem body of the code and trace ID only, never cached. Returns the trace ID.</summary>
    private static async Task<string> AssertAccessDeniedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.False(response.Headers.Contains("Set-Cookie"));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["code", "traceId"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("access_denied", json.RootElement.GetProperty("code").GetString());
        var traceId = json.RootElement.GetProperty("traceId").GetString()!;
        return traceId;
    }

    /// <summary>A refusal with its trace ID blanked: two refusals that differ only in it are the same answer.</summary>
    private static async Task<string> ShapeAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var traceId = json.RootElement.GetProperty("traceId").GetString()!;
        return (await AdminHost.SnapshotAsync(response)).Replace(
            Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(traceId)),
            "TRACE",
            StringComparison.Ordinal);
    }
}
