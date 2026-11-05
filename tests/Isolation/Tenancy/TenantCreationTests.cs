using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Operations;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.27 (FR-7, FR-44, AD-5, AD-6, AD-30) on the real Host.Admin and PostgreSQL: creating a
/// Tenant writes it, its host, its creator's Owner role, its creation Operation and its event in one
/// transaction, and answers 202; every bad subdomain is the same 400 <c>subdomain_refused</c>; every
/// bad body, name, label or cursor is 400 <c>tenant_invalid</c>; a non-Owner is 403 and audited;
/// the Operation is read through the Tenant path only and retried through the Deployment one; and
/// no route changes a subdomain.
/// </summary>
public sealed class TenantCreationTests(PostgresFixture postgres)
{
    private const string TenantsPath = "/api/v1/deployment/tenants";
    private const string Denied = "type_code = 'admin.access.denied'";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Owner_creates_a_Tenant_in_one_transaction_and_gets_202()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, owner) = await host.OwnerSessionAsync();

        using var response = await CreateAsync(host, cookie, csrf, "Acme Dev", "acme-dev", "dev");

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var tenant = json.RootElement.GetProperty("tenant");
        var operation = json.RootElement.GetProperty("operation");
        Assert.True(PublicId.TryParse(PublicIdType.Tenant, tenant.GetProperty("id").GetString(), out var tenantId));
        Assert.True(PublicId.TryParse(PublicIdType.Operation, operation.GetProperty("id").GetString(), out var operationId));
        Assert.Equal(
            $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, tenantId)}/operations/{PublicId.Format(PublicIdType.Operation, operationId)}",
            response.Headers.Location?.OriginalString);

        Assert.Equal("Acme Dev", tenant.GetProperty("name").GetString());
        Assert.Equal("acme-dev.gatekeep.test", tenant.GetProperty("host").GetString());
        Assert.Equal("dev", tenant.GetProperty("label").GetString());
        Assert.Equal("creating", tenant.GetProperty("status").GetString());
        Assert.False(tenant.TryGetProperty("subdomain", out _));
        Assert.Equal(PublicId.Format(PublicIdType.Operation, operationId), tenant.GetProperty("creation").GetProperty("operationId").GetString());
        Assert.Equal("running", tenant.GetProperty("creation").GetProperty("status").GetString());

        Assert.Equal("tenancy.tenant.create", operation.GetProperty("type").GetString());
        Assert.Equal("running", operation.GetProperty("status").GetString());
        var steps = operation.GetProperty("steps").EnumerateArray().ToList();
        Assert.Equal(["keys.secret_classes", "keys.signing"], steps.Select(s => s.GetProperty("stage").GetString()));
        Assert.All(steps, s => Assert.False(s.TryGetProperty("id", out _)));

        Assert.Equal(
            "creating|https://acme-dev.gatekeep.test/|acme-dev.gatekeep.test|https://acme-dev.gatekeep.test/|Acme Dev|dev",
            await host.ScalarAsync<string>($"SELECT status || '|' || issuer || '|' || rp_id || '|' || email_link_base || '|' || name || '|' || label FROM tenant WHERE id = '{tenantId}'"));
        Assert.Equal("subdomain", await host.ScalarAsync<string>($"SELECT kind FROM tenant_host WHERE host = 'acme-dev.gatekeep.test' AND tenant_id = '{tenantId}'"));
        Assert.Equal("owner", await host.ScalarAsync<string>($"SELECT role FROM tenant_role WHERE tenant_id = '{tenantId}' AND admin_id = '{owner}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant_role"));
        Assert.Equal($"running|{tenantId}", await host.ScalarAsync<string>($"SELECT status || '|' || tenant_id FROM operation WHERE id = '{operationId}'"));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM operation_step WHERE operation_id = '{operationId}' AND tenant_id = '{tenantId}' AND status = 'pending'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = 'operations.operation.run' AND operation_id = '{operationId}'"));
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'tenancy.tenant.created' AND actor_kind = 'admin' AND actor_id = '{owner}' AND target_kind = 'tenant' AND target_id = '{tenantId}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant_settings"));
    }

    [Fact]
    public async Task Tenant_HTTPS_port_goes_into_the_issuer_only()
    {
        await using var host = await AdminHost.StartAsync(postgres, null, "--Gatekeep:TenantHttpsPort=8443");
        var (cookie, csrf, _) = await host.OwnerSessionAsync();

        using var response = await CreateAsync(host, cookie, csrf, "Acme Dev", "acme-dev", "staging");

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(
            "https://acme-dev.gatekeep.test:8443/|acme-dev.gatekeep.test|https://acme-dev.gatekeep.test:8443/",
            await host.ScalarAsync<string>("SELECT issuer || '|' || rp_id || '|' || email_link_base FROM tenant"));
    }

    [Fact]
    public async Task Every_bad_subdomain_is_the_same_refusal_and_writes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();

        using (var first = await CreateAsync(host, cookie, csrf, "Acme Dev", "acme-dev", "dev"))
        {
            Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        }

        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");
        var shapes = new List<string>();
        foreach (var subdomain in new[]
        {
            "Acme", "ab", "-acme", "acme-", "xn--acme", "ac--me", "a_b", " acme", new string('a', 64),
            "admin", "www", "mta-sts",
            "acme-dev",
        })
        {
            using var response = await CreateAsync(host, cookie, csrf, "Another", subdomain, "dev");
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("subdomain_refused", await CodeAsync(response));
            shapes.Add(await ShapeAsync(response));
        }

        // Malformed, reserved and taken can't be told apart.
        Assert.Single(shapes.Distinct());
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant_host"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant_role"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
    }

    [Fact]
    public async Task Concurrent_creations_of_one_subdomain_make_one_Tenant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();

        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(i => CreateAsync(host, cookie, csrf, $"Racer {i}", "race", "dev")));
        try
        {
            Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Accepted);
            foreach (var refused in responses.Where(r => r.StatusCode != HttpStatusCode.Accepted))
            {
                Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
                Assert.Equal("subdomain_refused", await CodeAsync(refused));
            }
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'tenancy.tenant.created'"));
    }

    [Fact]
    public async Task Bad_body_name_or_label_is_tenant_invalid_and_writes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");

        foreach (var (body, contentType) in new[]
        {
            (Body("   ", "acme", "dev"), "application/json"),
            (Body(new string('n', 101), "acme", "dev"), "application/json"),
            (Body("Acme\u0007", "acme", "dev"), "application/json"),
            (Body("Acme", "acme", "production"), "application/json"),
            (Body("Acme", "acme", "Dev"), "application/json"),
            ("""{"name":"Acme","subdomain":"acme"}""", "application/json"),
            ("""{"name":"Acme","subdomain":"acme","label":null}""", "application/json"),
            ("""{"name":"Acme","subdomain":7,"label":"dev"}""", "application/json"),
            ("""{"name":["Acme"],"subdomain":"acme","label":"dev"}""", "application/json"),
            ("not json", "application/json"),
            ("", "application/json"),
            (Body("Acme", "acme", "dev"), "text/plain"),
            (Body("Acme", "acme", "dev"), "application/x-www-form-urlencoded"),
            ($$"""{"name":"Acme","subdomain":"acme","label":"dev","pad":"{{new string('p', 4096)}}"}""", "application/json"),
        })
        {
            using var response = await host.SendAsync(HttpMethod.Post, TenantsPath, cookie, csrf, AdminHost.Origin, body, contentType: contentType);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("tenant_invalid", await CodeAsync(response));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant"));
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));

        // An unknown extra property is ignored, and the name is trimmed.
        using var extra = await host.SendAsync(
            HttpMethod.Post,
            TenantsPath,
            cookie,
            csrf,
            AdminHost.Origin,
            """{"name":"  Acme  ","subdomain":"acme","label":"prod","region":"eu"}""");
        Assert.Equal(HttpStatusCode.Accepted, extra.StatusCode);
        Assert.Equal("Acme|prod", await host.ScalarAsync<string>("SELECT name || '|' || label FROM tenant"));
    }

    [Fact]
    public async Task Non_Owner_is_refused_and_audited_on_every_Deployment_Tenant_route()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.OwnerSessionAsync();
        var (cookie, csrf, session) = await host.InsertFullSessionAsync();
        var admin = await host.AdminOfSessionAsync(session);
        var operation = PublicId.Format(PublicIdType.Operation, Guid.CreateVersion7());

        foreach (var (method, path, body) in new (HttpMethod, string, string?)[]
        {
            (HttpMethod.Post, TenantsPath, Body("Acme", "acme", "dev")),
            (HttpMethod.Get, TenantsPath, null),
            (HttpMethod.Post, $"/api/v1/deployment/operations/{operation}/retry", null),
        })
        {
            var before = await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND actor_id = '{admin}'");
            using var response = await host.SendAsync(method, path, cookie, csrf, AdminHost.Origin, body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
            Assert.Equal(before + 1, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND actor_id = '{admin}'"));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant_role"));
    }

    [Fact]
    public async Task Restricted_missing_and_forged_Sessions_are_refused_first()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (setup, setupCsrf, _) = await host.ClaimedAsync();
        var tenant = PublicId.Format(PublicIdType.Tenant, Guid.CreateVersion7());
        var operation = PublicId.Format(PublicIdType.Operation, Guid.CreateVersion7());

        var routes = new (HttpMethod Method, string Path, string? Body)[]
        {
            (HttpMethod.Post, TenantsPath, Body("Acme", "acme", "dev")),
            (HttpMethod.Get, TenantsPath, null),
            (HttpMethod.Post, $"/api/v1/deployment/operations/{operation}/retry", null),
            (HttpMethod.Get, $"/api/v1/tenants/{tenant}/operations/{operation}", null),
        };

        foreach (var (method, path, body) in routes)
        {
            // A setup Session reaches none of them: the bodiless 403.
            using (var restricted = await host.SendAsync(method, path, setup, setupCsrf, AdminHost.Origin, body))
            {
                Assert.Equal(HttpStatusCode.Forbidden, restricted.StatusCode);
                Assert.Empty(await restricted.Content.ReadAsByteArrayAsync(Cancellation));
            }

            using (var missing = await host.SendAsync(method, path, origin: AdminHost.Origin, body: body))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
            }
        }

        var (cookie, csrf, _) = await host.InsertFullSessionAsync();
        foreach (var (method, path, body) in routes.Where(r => r.Method == HttpMethod.Post))
        {
            using (var wrongCsrf = await host.SendAsync(method, path, cookie, "wrong", AdminHost.Origin, body))
            {
                Assert.Equal(HttpStatusCode.Forbidden, wrongCsrf.StatusCode);
                Assert.Empty(await wrongCsrf.Content.ReadAsByteArrayAsync(Cancellation));
            }

            using var wrongOrigin = await host.SendAsync(method, path, cookie, csrf, "https://evil.example", body);
            Assert.Equal(HttpStatusCode.Forbidden, wrongOrigin.StatusCode);
            Assert.Empty(await wrongOrigin.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant"));
    }

    [Fact]
    public async Task No_route_changes_a_subdomain()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        var (tenantId, _) = await CreatedAsync(host, cookie, csrf, "acme-dev");
        var tenant = PublicId.Format(PublicIdType.Tenant, tenantId);
        var body = """{"subdomain":"moved"}""";

        foreach (var path in new[] { $"{TenantsPath}/{tenant}", $"/api/v1/tenants/{tenant}", $"/api/v1/tenants/{tenant}/host", TenantsPath })
        {
            foreach (var method in new[] { HttpMethod.Put, HttpMethod.Patch, HttpMethod.Delete })
            {
                using var response = await host.SendAsync(method, path, cookie, csrf, AdminHost.Origin, body);
                Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
                Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
            }
        }

        Assert.Equal("acme-dev.gatekeep.test", await host.ScalarAsync<string>("SELECT string_agg(host, ',') FROM tenant_host"));
    }

    [Fact]
    public async Task Creator_becomes_Tenant_Owner_and_another_Admin_doesnt()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        var (tenantId, _) = await CreatedAsync(host, cookie, csrf, "acme-dev");
        var path = $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, tenantId)}/capabilities";

        using (var mine = await host.SendAsync(HttpMethod.Get, path, cookie))
        {
            Assert.Equal(HttpStatusCode.OK, mine.StatusCode);
            using var json = JsonDocument.Parse(await mine.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(
                AdminCapabilities.All.Where(c => c.Scope == CapabilityScope.Tenant).Select(c => c.Name),
                json.RootElement.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()));
        }

        var (other, _, _) = await host.InsertFullSessionAsync();
        using var theirs = await host.SendAsync(HttpMethod.Get, path, other);
        Assert.Equal(HttpStatusCode.Forbidden, theirs.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(theirs));
    }

    [Fact]
    public async Task Operation_is_read_through_its_own_Tenant_path_only()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        var (a, operationA) = await CreatedAsync(host, cookie, csrf, "tenant-a");
        var (b, _) = await CreatedAsync(host, cookie, csrf, "tenant-b");
        var tenantA = PublicId.Format(PublicIdType.Tenant, a);
        var tenantB = PublicId.Format(PublicIdType.Tenant, b);
        var opA = PublicId.Format(PublicIdType.Operation, operationA);

        using (var mine = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{tenantA}/operations/{opA}", cookie))
        {
            Assert.Equal(HttpStatusCode.OK, mine.StatusCode);
            Assert.Equal("no-store", mine.Headers.CacheControl?.ToString());
            using var json = JsonDocument.Parse(await mine.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(opA, json.RootElement.GetProperty("id").GetString());
            Assert.Equal(tenantA, json.RootElement.GetProperty("tenantId").GetString());
            var steps = json.RootElement.GetProperty("steps").EnumerateArray().ToList();
            Assert.Equal(["keys.secret_classes", "keys.signing"], steps.Select(s => s.GetProperty("stage").GetString()));
            Assert.All(steps, step =>
            {
                Assert.Equal(tenantA, step.GetProperty("tenantId").GetString());
                Assert.Equal(["attempts", "resultCode", "stage", "status", "tenantId", "updatedAt"], step.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
            });
        }

        // Owner of both: another Tenant's Operation, an unknown one and a malformed ID look alike.
        var snapshots = new List<string>();
        foreach (var path in new[]
        {
            $"/api/v1/tenants/{tenantB}/operations/{opA}",
            $"/api/v1/tenants/{tenantA}/operations/{PublicId.Format(PublicIdType.Operation, Guid.CreateVersion7())}",
            $"/api/v1/tenants/{tenantA}/operations/opr_nope",
            $"/api/v1/tenants/{tenantA}/operations/{tenantB}",
        })
        {
            using var response = await host.SendAsync(HttpMethod.Get, path, cookie);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        using (var unknownPath = await host.SendAsync(HttpMethod.Get, "/api/v1/nothing", cookie))
        {
            snapshots.Add(await AdminHost.SnapshotAsync(unknownPath));
        }

        Assert.Single(snapshots.Distinct());
    }

    [Fact]
    public async Task List_pages_by_creation_with_the_zone_and_the_creating_ones_Operation()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        var (first, firstOperation) = await CreatedAsync(host, cookie, csrf, "first");
        var (second, _) = await CreatedAsync(host, cookie, csrf, "second");
        var (third, _) = await CreatedAsync(host, cookie, csrf, "third");

        // The first is activated as its Operation would; the others are still creating.
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE operation SET status = 'succeeded', finished_at = now() WHERE id = '{firstOperation}'; INSERT INTO tenant_settings (tenant_id) VALUES ('{first}'); SET session_replication_role = replica; UPDATE tenant SET status = 'active' WHERE id = '{first}'; SET session_replication_role = DEFAULT");

        using var response = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("gatekeep.test", json.RootElement.GetProperty("tenantZone").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("nextCursor").ValueKind);
        var tenants = json.RootElement.GetProperty("tenants").EnumerateArray().ToList();
        Assert.Equal(
            new[] { first, second, third }.Select(id => PublicId.Format(PublicIdType.Tenant, id)),
            tenants.Select(t => t.GetProperty("id").GetString()));
        Assert.Equal(["first.gatekeep.test", "second.gatekeep.test", "third.gatekeep.test"], tenants.Select(t => t.GetProperty("host").GetString()));
        Assert.Equal(JsonValueKind.Null, tenants[0].GetProperty("creation").ValueKind);
        Assert.Equal("active", tenants[0].GetProperty("status").GetString());
        Assert.Equal("running", tenants[1].GetProperty("creation").GetProperty("status").GetString());

        using var after = await host.SendAsync(HttpMethod.Get, $"{TenantsPath}?cursor={PublicId.Format(PublicIdType.Tenant, first)}", cookie);
        using var page = JsonDocument.Parse(await after.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(
            new[] { second, third }.Select(id => PublicId.Format(PublicIdType.Tenant, id)),
            page.RootElement.GetProperty("tenants").EnumerateArray().Select(t => t.GetProperty("id").GetString()));

        foreach (var cursor in new[] { "nope", "ten_", PublicId.Format(PublicIdType.Operation, first), $"{PublicId.Format(PublicIdType.Tenant, first)}&cursor={PublicId.Format(PublicIdType.Tenant, first)}" })
        {
            using var refused = await host.SendAsync(HttpMethod.Get, $"{TenantsPath}?cursor={cursor}", cookie);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Equal("tenant_invalid", await CodeAsync(refused));
        }
    }

    [Fact]
    public async Task List_reports_the_next_page_past_fifty()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        var ids = Enumerable.Range(0, 51).Select(_ => Guid.CreateVersion7()).ToList();
        foreach (var id in ids)
        {
            await TestTenants.InsertAsync(host.Superuser, id, TestTenants.Host(id));
        }

        using var response = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(50, json.RootElement.GetProperty("tenants").GetArrayLength());
        var fiftieth = await host.ScalarAsync<Guid>("SELECT id FROM tenant ORDER BY created_at, id OFFSET 49 LIMIT 1");
        Assert.Equal(PublicId.Format(PublicIdType.Tenant, fiftieth), json.RootElement.GetProperty("nextCursor").GetString());
    }

    [Fact]
    public async Task Failed_creation_is_retried_once_and_then_activates()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, owner) = await host.OwnerSessionAsync();
        var (tenantId, operationId) = await CreatedAsync(host, cookie, csrf, "acme-dev");
        var operation = PublicId.Format(PublicIdType.Operation, operationId);
        var retryPath = $"/api/v1/deployment/operations/{operation}/retry";

        // Running: nothing to retry.
        using (var running = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Conflict, running.StatusCode);
            Assert.Equal("operation_not_failed", await CodeAsync(running));
        }

        // The Worker without custody: the keys stage fails.
        await DrainAsync(host, custody: null);
        Assert.Equal("failed", await host.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operationId}'"));

        using (var list = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie))
        {
            using var json = JsonDocument.Parse(await list.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("failed", json.RootElement.GetProperty("tenants")[0].GetProperty("creation").GetProperty("status").GetString());
        }

        using (var retried = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Accepted, retried.StatusCode);
            using var json = JsonDocument.Parse(await retried.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("running", json.RootElement.GetProperty("status").GetString());
            Assert.Equal("pending", json.RootElement.GetProperty("steps")[0].GetProperty("status").GetString());
        }

        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried' AND actor_id = '{owner}' AND target_id = '{tenantId}'"));

        using (var again = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        }

        await DrainAsync(host, new RecordingCustody());
        Assert.Equal("active", await host.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{tenantId}'"));

        using var succeeded = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin);
        Assert.Equal(HttpStatusCode.Conflict, succeeded.StatusCode);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried'"));
    }

    [Fact]
    public async Task Retry_of_another_type_unknown_or_malformed_is_the_unknown_path_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.OwnerSessionAsync();
        var tenant = Guid.CreateVersion7();
        await TestTenants.InsertAsync(host.Superuser, tenant);
        var purge = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"INSERT INTO operation (id, type, tenant_id, status, finished_at) VALUES ('{purge}', 'audit.chain.purge', '{tenant}', 'failed', now())");

        var snapshots = new List<string>();
        foreach (var operation in new[]
        {
            PublicId.Format(PublicIdType.Operation, purge),
            PublicId.Format(PublicIdType.Operation, Guid.CreateVersion7()),
            "opr_nope",
            PublicId.Format(PublicIdType.Tenant, tenant),
        })
        {
            using var response = await host.SendAsync(HttpMethod.Post, $"/api/v1/deployment/operations/{operation}/retry", cookie, csrf, AdminHost.Origin);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        Assert.Single(snapshots.Distinct());
        Assert.Equal("failed", await host.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{purge}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried'"));
    }

    [Fact]
    public async Task Tenant_name_and_subdomain_never_reach_a_log_line()
    {
        var canary = "cnry-tenant-name-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        var subdomain = "cnry-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        await using var host = await AdminHost.StartAsync(
            postgres,
            null,
            "--Logging:LogLevel:Default=Trace",
            "--Logging:LogLevel:Microsoft=Trace");
        var (cookie, csrf, _) = await host.OwnerSessionAsync();

        using (var created = await CreateAsync(host, cookie, csrf, canary, subdomain, "dev"))
        {
            Assert.Equal(HttpStatusCode.Accepted, created.StatusCode);
        }

        using (var taken = await CreateAsync(host, cookie, csrf, canary, subdomain, "dev"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, taken.StatusCode);
        }

        using (var invalid = await CreateAsync(host, cookie, csrf, canary + "\u0007", subdomain, "dev"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        }

        using (var list = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie))
        {
            Assert.Contains(canary, await list.Content.ReadAsStringAsync(Cancellation));
        }

        await host.StopAsync();
        Assert.Contains("subdomain_refused", host.Output);
        Assert.DoesNotContain(canary, host.Output);
        Assert.DoesNotContain(subdomain, host.Output);
    }

    private static string Body(string name, string subdomain, string label) =>
        JsonSerializer.Serialize(new { name, subdomain, label });

    private static Task<HttpResponseMessage> CreateAsync(AdminHost host, string cookie, string csrf, string name, string subdomain, string label) =>
        host.SendAsync(HttpMethod.Post, TenantsPath, cookie, csrf, AdminHost.Origin, Body(name, subdomain, label));

    /// <summary>Creates a Tenant named after its subdomain, which must pass. Returns it and its Operation.</summary>
    private static async Task<(Guid Tenant, Guid Operation)> CreatedAsync(AdminHost host, string cookie, string csrf, string subdomain)
    {
        using var response = await CreateAsync(host, cookie, csrf, subdomain, subdomain, "dev");
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.True(PublicId.TryParse(PublicIdType.Tenant, json.RootElement.GetProperty("tenant").GetProperty("id").GetString(), out var tenant));
        Assert.True(PublicId.TryParse(PublicIdType.Operation, json.RootElement.GetProperty("operation").GetProperty("id").GetString(), out var operation));
        return (tenant, operation);
    }

    /// <summary>Runs the Worker's jobs in-process against the host's database until none is due.</summary>
    private async Task DrainAsync(AdminHost host, Gatekeep.Kernel.Secrets.IKeyCustody? custody)
    {
        await using var runner = OperationsContract.CreateRunner(
            OperationsContract.ProductionRegistry,
            new JobDatabases(
                postgres.RoleConnection(TableRegistry.Dispatch, host.Database),
                postgres.RoleConnection(TableRegistry.Worker, host.Database),
                postgres.RoleConnection(TableRegistry.Sealer, host.Database),
                postgres.RoleConnection(TableRegistry.Retention, host.Database)),
            Jobs.JobDatabase.FastOptions,
            custody,
            logger: null);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response)
    {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("code").GetString();
    }

    /// <summary>The response as bytes on the wire would compare, with its trace ID masked.</summary>
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
