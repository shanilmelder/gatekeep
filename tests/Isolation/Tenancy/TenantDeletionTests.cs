using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Operations;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.29 (FR-7, FR-46, AD-5, AD-6, AD-20, AD-30) on the real Host.Admin and PostgreSQL:
/// deleting a Tenant needs a fresh assertion for <c>deployment.tenants.delete</c> bound to that
/// Tenant, which the request checks use up first, and its host typed exactly. The start sets it
/// deleting and removes every role in it in one transaction, so access ends at once; each refusal
/// is its own fixed code and writes nothing; the deletion is read and retried on its own routes,
/// a retry needing a new assertion; and the subdomain is never issued again.
/// </summary>
public sealed class TenantDeletionTests(PostgresFixture postgres)
{
    private const string Action = "deployment.tenants.delete";
    private const string TenantsPath = "/api/v1/deployment/tenants";
    private const string Started = "tenancy.tenant.deletion_started";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task No_grant_is_403_fresh_assertion_required_and_writes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");

        using var response = await DeleteAsync(host, cookie, csrf, tenant, TestTenants.Host(tenant));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("fresh_assertion_required", await CodeAsync(response));
        Assert.Equal("active", await StatusAsync(host, tenant));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task Confirmed_deletion_ends_access_and_starts_the_Operation_in_one_transaction()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var other = await InsertAsync(host);
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant, other);
        var (editor, editorCsrf, _) = await RoleSessionAsync(host, tenant, "editor");
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        Assert.Equal(1L, await GrantsAsync(host));

        using var response = await DeleteAsync(host, cookie, csrf, tenant, TestTenants.Host(tenant));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal($"{TenantsPath}/{Id(tenant)}/deletion", response.Headers.Location?.OriginalString);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("tenancy.tenant.delete", json.RootElement.GetProperty("type").GetString());
        Assert.Equal("running", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(Id(tenant), json.RootElement.GetProperty("tenantId").GetString());
        Assert.Equal(
            ["tenancy.tenant.purge", "keys.secret_classes.destroy"],
            json.RootElement.GetProperty("steps").EnumerateArray().Select(s => s.GetProperty("stage").GetString()));
        Assert.All(json.RootElement.GetProperty("steps").EnumerateArray(), s => Assert.Equal(Id(tenant), s.GetProperty("tenantId").GetString()));

        Assert.Equal("deleting", await StatusAsync(host, tenant));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM tenant_role WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM tenant_role WHERE tenant_id = '{other}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = 'operations.operation.run'"));
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Started}' AND actor_kind = 'admin' AND actor_id = '{owner}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.fresh_assertion.verified' AND actor_id = '{owner}'"));
        Assert.Equal(0L, await GrantsAsync(host));

        // Access ends at the start: every route of the Tenant refuses its former members, and the
        // switcher no longer lists it.
        using (var read = await GetLabelAsync(host, editor, tenant))
        {
            Assert.Equal(HttpStatusCode.Forbidden, read.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(read));
        }

        using (var write = await SetLabelAsync(host, editor, editorCsrf, tenant, "staging"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, write.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(write));
        }

        using (var mine = await host.SendAsync(HttpMethod.Get, MyTenantsPath, cookie))
        {
            using var list = JsonDocument.Parse(await mine.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal([Id(other)], list.RootElement.GetProperty("tenants").EnumerateArray().Select(t => t.GetProperty("id").GetString()));
        }

        // The list shows it deleting, with its deletion.
        using (var tenants = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie))
        {
            using var list = JsonDocument.Parse(await tenants.Content.ReadAsStringAsync(Cancellation));
            var row = list.RootElement.GetProperty("tenants").EnumerateArray().Single(t => t.GetProperty("id").GetString() == Id(tenant));
            Assert.Equal("deleting", row.GetProperty("status").GetString());
            Assert.Equal(json.RootElement.GetProperty("id").GetString(), row.GetProperty("deletion").GetProperty("operationId").GetString());
            Assert.Equal("running", row.GetProperty("deletion").GetProperty("status").GetString());
            Assert.Equal(JsonValueKind.Null, row.GetProperty("creation").ValueKind);
        }

        Dispose(authenticators);
    }

    [Fact]
    public async Task A_grant_for_one_Tenant_never_serves_another_and_is_used_once()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(a));

        using (var other = await DeleteAsync(host, cookie, csrf, b, TestTenants.Host(b)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);
            Assert.Equal("fresh_assertion_required", await CodeAsync(other));
        }

        Assert.Equal(1L, await GrantsAsync(host));
        Assert.Equal("active", await StatusAsync(host, b));

        // A refusal after the checks still used the grant up: the resend needs a new confirmation.
        using (var mismatch = await DeleteAsync(host, cookie, csrf, a, "wrong"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);
            Assert.Equal("confirmation_mismatch", await CodeAsync(mismatch));
        }

        using (var resend = await DeleteAsync(host, cookie, csrf, a, TestTenants.Host(a)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, resend.StatusCode);
            Assert.Equal("fresh_assertion_required", await CodeAsync(resend));
        }

        Assert.Equal("active", await StatusAsync(host, a));
        Dispose(authenticators);
    }

    [Fact]
    public async Task A_typed_value_that_isnt_the_host_exactly_is_400_and_writes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        var stored = TestTenants.Host(tenant);
        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code <> 'admin.fresh_assertion.verified'");

        foreach (var typed in new[] { stored.ToUpperInvariant(), " " + stored, stored.Split('.')[0] })
        {
            await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
            using var response = await DeleteAsync(host, cookie, csrf, tenant, typed);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("confirmation_mismatch", await CodeAsync(response));
            Assert.Equal(0L, await GrantsAsync(host));
        }

        Assert.Equal("active", await StatusAsync(host, tenant));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code <> 'admin.fresh_assertion.verified'"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task A_bad_body_is_tenant_invalid_and_writes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();

        foreach (var (body, contentType) in new[]
        {
            ("{}", "application/json"),
            ("""{"confirmation":1}""", "application/json"),
            (JsonSerializer.Serialize(new { confirmation = TestTenants.Host(tenant) }), "text/plain"),
            (JsonSerializer.Serialize(new { confirmation = TestTenants.Host(tenant), pad = new string('x', 4096) }), "application/json"),
        })
        {
            await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
            using var response = await host.SendAsync(HttpMethod.Post, DeletionPath(Id(tenant)), cookie, csrf, AdminHost.Origin, body, contentType: contentType);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("tenant_invalid", await CodeAsync(response));
        }

        Assert.Equal("active", await StatusAsync(host, tenant));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task An_unknown_or_malformed_Tenant_is_the_unknown_path_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();

        var snapshots = new List<string>();
        foreach (var target in new[] { Id(Guid.CreateVersion7()), "nope" })
        {
            await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, target);
            using var response = await host.SendAsync(HttpMethod.Post, DeletionPath(target), cookie, csrf, AdminHost.Origin, Body("x.gatekeep.test"));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        foreach (var target in new[] { Id(Guid.CreateVersion7()), "nope" })
        {
            using var read = await host.SendAsync(HttpMethod.Get, DeletionPath(target), cookie);
            Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(read));
        }

        using (var unknown = await host.SendAsync(HttpMethod.Get, "/api/v1/nothing", cookie))
        {
            snapshots.Add(await AdminHost.SnapshotAsync(unknown));
        }

        Assert.Single(snapshots.Distinct());
        Dispose(authenticators);
    }

    [Fact]
    public async Task A_Tenant_Owner_who_isnt_the_Deployment_Owner_is_refused_and_audited_on_every_deletion_route()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.OwnerSessionAsync();
        var tenant = await InsertAsync(host);
        var (cookie, csrf, admin) = await RoleSessionAsync(host, tenant, "owner");

        foreach (var (method, path, body) in new (HttpMethod, string, string?)[]
        {
            (HttpMethod.Post, DeletionPath(Id(tenant)), Body(TestTenants.Host(tenant))),
            (HttpMethod.Get, DeletionPath(Id(tenant)), null),
            (HttpMethod.Post, DeletionPath(Id(tenant)) + "/retry", null),
        })
        {
            var before = await DeniedAsync(host, admin);
            using var response = await host.SendAsync(method, path, cookie, csrf, AdminHost.Origin, body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
            Assert.Equal(before + 1, await DeniedAsync(host, admin));
        }

        // Nor can the Deployment begin be started for it.
        var (begin, _) = await host.BeginAssertionAsync(cookie, csrf, Action, Id(tenant));
        using (begin)
        {
            Assert.Equal(HttpStatusCode.Forbidden, begin.StatusCode);
        }

        Assert.Equal("active", await StatusAsync(host, tenant));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM tenant_role WHERE tenant_id = '{tenant}'"));
    }

    [Theory]
    [InlineData("deleting")]
    [InlineData("deleted")]
    public async Task A_Tenant_already_being_deleted_is_409_tenant_deleted(string status)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, status: status);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));

        using var response = await DeleteAsync(host, cookie, csrf, tenant, TestTenants.Host(tenant));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_deleted", await CodeAsync(response));
        Assert.Equal(status, await StatusAsync(host, tenant));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task A_running_creation_is_409_tenant_busy_and_a_failed_one_can_be_deleted_but_never_retried()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        var (tenant, creation) = await CreatedAsync(host, cookie, csrf, "acme");
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));

        using (var busy = await DeleteAsync(host, cookie, csrf, tenant, "acme.gatekeep.test"))
        {
            Assert.Equal(HttpStatusCode.Conflict, busy.StatusCode);
            Assert.Equal("tenant_busy", await CodeAsync(busy));
        }

        Assert.Equal("creating", await StatusAsync(host, tenant));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM tenant_role WHERE tenant_id = '{tenant}'"));

        // The Worker without custody: the creation fails, and the Tenant can be deleted.
        await DrainAsync(host, custody: null);
        Assert.Equal("failed", await host.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{creation}'"));
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var started = await DeleteAsync(host, cookie, csrf, tenant, "acme.gatekeep.test"))
        {
            Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        }

        Assert.Equal("deleting", await StatusAsync(host, tenant));
        using (var retry = await host.SendAsync(HttpMethod.Post, $"/api/v1/deployment/operations/{PublicId.Format(PublicIdType.Operation, creation)}/retry", cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Conflict, retry.StatusCode);
            Assert.Equal("tenant_deleted", await CodeAsync(retry));
        }

        Assert.Equal("failed", await host.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{creation}'"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task Two_confirmed_starts_at_once_make_one_deletion()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        var (second, secondCsrf) = await host.SignInAsync(authenticators[1]);
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        await host.ConfirmAsync(second, secondCsrf, authenticators[1], Action, Id(tenant));

        var responses = await Task.WhenAll(
            DeleteAsync(host, cookie, csrf, tenant, TestTenants.Host(tenant)),
            DeleteAsync(host, second, secondCsrf, tenant, TestTenants.Host(tenant)));
        try
        {
            Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Accepted);
            var refused = Assert.Single(responses, r => r.StatusCode != HttpStatusCode.Accepted);
            Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
            Assert.Equal("tenant_deleted", await CodeAsync(refused));
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM operation WHERE type = 'tenancy.tenant.delete'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Started}'"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task A_failed_deletion_is_read_and_retried_with_a_new_assertion_then_finishes()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, owner, authenticators) = await host.OwnerWithCredentialsAsync();
        var retryPath = DeletionPath(Id(tenant)) + "/retry";

        using (var never = await host.SendAsync(HttpMethod.Get, DeletionPath(Id(tenant)), cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, never.StatusCode);
        }

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var started = await DeleteAsync(host, cookie, csrf, tenant, TestTenants.Host(tenant)))
        {
            Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        }

        // Running: nothing to retry, even confirmed.
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var running = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Conflict, running.StatusCode);
            Assert.Equal("operation_not_failed", await CodeAsync(running));
        }

        // The Worker without custody: the destroy step fails, the purge succeeds.
        await DrainAsync(host, custody: null);
        using (var read = await host.SendAsync(HttpMethod.Get, DeletionPath(Id(tenant)), cookie))
        {
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            Assert.Equal("no-store", read.Headers.CacheControl?.ToString());
            using var json = JsonDocument.Parse(await read.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("failed", json.RootElement.GetProperty("status").GetString());
            Assert.Equal(
                ["succeeded", "failed"],
                json.RootElement.GetProperty("steps").EnumerateArray().Select(s => s.GetProperty("status").GetString()));
            Assert.Equal("custody_unavailable", json.RootElement.GetProperty("steps")[1].GetProperty("resultCode").GetString());
        }

        using (var list = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie))
        {
            using var json = JsonDocument.Parse(await list.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("failed", json.RootElement.GetProperty("tenants")[0].GetProperty("deletion").GetProperty("status").GetString());
        }

        // A retry needs its own fresh assertion.
        using (var unconfirmed = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Forbidden, unconfirmed.StatusCode);
            Assert.Equal("fresh_assertion_required", await CodeAsync(unconfirmed));
        }

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var retried = await host.SendAsync(HttpMethod.Post, retryPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Accepted, retried.StatusCode);
            using var json = JsonDocument.Parse(await retried.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("running", json.RootElement.GetProperty("status").GetString());
            Assert.Equal(["succeeded", "pending"], json.RootElement.GetProperty("steps").EnumerateArray().Select(s => s.GetProperty("status").GetString()));
        }

        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried' AND actor_id = '{owner}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));

        await DrainAsync(host, new RecordingCustody());
        Assert.Equal("deleted", await StatusAsync(host, tenant));

        // Deleted: it leaves the list, its deletion reads succeeded, and there is nothing to retry.
        using (var list = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie))
        {
            using var json = JsonDocument.Parse(await list.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(0, json.RootElement.GetProperty("tenants").GetArrayLength());
        }

        using (var read = await host.SendAsync(HttpMethod.Get, DeletionPath(Id(tenant)), cookie))
        {
            using var json = JsonDocument.Parse(await read.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("succeeded", json.RootElement.GetProperty("status").GetString());
        }

        Dispose(authenticators);
    }

    [Fact]
    public async Task Retry_of_a_deletion_that_isnt_failed_or_through_the_generic_route_is_refused()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var active = await InsertAsync(host);
        var deleted = await InsertAsync(host);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();

        // An active Tenant has no deletion to retry.
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(active));
        using (var none = await host.SendAsync(HttpMethod.Post, DeletionPath(Id(active)) + "/retry", cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Conflict, none.StatusCode);
            Assert.Equal("operation_not_failed", await CodeAsync(none));
        }

        // A deletion that succeeded: nothing to retry either, and the generic retry never reaches one.
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(deleted));
        Guid operation;
        using (var started = await DeleteAsync(host, cookie, csrf, deleted, TestTenants.Host(deleted)))
        {
            using var json = JsonDocument.Parse(await started.Content.ReadAsStringAsync(Cancellation));
            Assert.True(PublicId.TryParse(PublicIdType.Operation, json.RootElement.GetProperty("id").GetString(), out operation));
        }

        await DrainAsync(host, new RecordingCustody());
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(deleted));
        using (var succeeded = await host.SendAsync(HttpMethod.Post, DeletionPath(Id(deleted)) + "/retry", cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Conflict, succeeded.StatusCode);
            Assert.Equal("operation_not_failed", await CodeAsync(succeeded));
        }

        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE operation SET status = 'failed' WHERE id = '{operation}'");
        using (var generic = await host.SendAsync(HttpMethod.Post, $"/api/v1/deployment/operations/{PublicId.Format(PublicIdType.Operation, operation)}/retry", cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.NotFound, generic.StatusCode);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried'"));
        Dispose(authenticators);
    }

    [Fact]
    public async Task A_deleted_Tenants_subdomain_is_refused_for_good()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        var (tenant, _) = await CreatedAsync(host, cookie, csrf, "acme");
        await DrainAsync(host, new RecordingCustody());
        Assert.Equal("active", await StatusAsync(host, tenant));

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var started = await DeleteAsync(host, cookie, csrf, tenant, "acme.gatekeep.test"))
        {
            Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        }

        foreach (var drained in new[] { false, true })
        {
            if (drained)
            {
                await DrainAsync(host, new RecordingCustody());
                Assert.Equal("deleted", await StatusAsync(host, tenant));
            }

            var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");
            using var again = await host.SendAsync(HttpMethod.Post, TenantsPath, cookie, csrf, AdminHost.Origin, JsonSerializer.Serialize(new { name = "Acme again", subdomain = "acme", label = "dev" }));
            Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
            Assert.Equal("subdomain_refused", await CodeAsync(again));
            Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM tenant"));
            Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        }

        Dispose(authenticators);
    }

    [Fact]
    public async Task Tenant_name_and_host_never_reach_a_log_line()
    {
        var canary = "cnry-tenant-name-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        var subdomain = "cnry-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));
        await using var host = await AdminHost.StartAsync(postgres, null, "--Logging:LogLevel:Default=Trace", "--Logging:LogLevel:Microsoft=Trace");
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        using (var created = await host.SendAsync(HttpMethod.Post, TenantsPath, cookie, csrf, AdminHost.Origin, JsonSerializer.Serialize(new { name = canary, subdomain, label = "dev" })))
        {
            Assert.Equal(HttpStatusCode.Accepted, created.StatusCode);
        }

        var tenant = await host.ScalarAsync<Guid>("SELECT id FROM tenant");
        var worker = new Jobs.RecordingLogger();
        await DrainAsync(host, new RecordingCustody(), worker);
        var stored = $"{subdomain}.gatekeep.test";

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var mismatch = await DeleteAsync(host, cookie, csrf, tenant, stored + "x"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, mismatch.StatusCode);
        }

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var started = await DeleteAsync(host, cookie, csrf, tenant, stored))
        {
            Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        }

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));
        using (var again = await DeleteAsync(host, cookie, csrf, tenant, stored))
        {
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        }

        // The Worker runs the deletion, logging as it goes: its lines are scanned too.
        await DrainAsync(host, new RecordingCustody(), worker);
        Assert.Equal("deleted", await StatusAsync(host, tenant));
        // A healthy run logs only its failures, so this is often empty: whatever it logs is scanned.
        var workerOutput = string.Join("\n", worker.Lines);
        foreach (var secret in new[] { canary, subdomain, tenant.ToString("D"), tenant.ToString("N") })
        {
            Assert.DoesNotContain(secret, workerOutput, StringComparison.OrdinalIgnoreCase);
        }

        await host.StopAsync();
        Assert.Contains("confirmation_mismatch", host.Output);
        Assert.Contains("tenant_deleted", host.Output);
        Assert.DoesNotContain(canary, host.Output);
        Assert.DoesNotContain(subdomain, host.Output);
        Assert.DoesNotContain(tenant.ToString("D"), host.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(tenant.ToString("N"), host.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("{Code}", host.Output);
        Dispose(authenticators);
    }

    /// <summary>Review item: the list cursor still works when it names a Tenant deleted since.</summary>
    [Fact]
    public async Task A_cursor_naming_a_Tenant_deleted_since_still_pages()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        var first = await InsertAsync(host);
        var second = await InsertAsync(host);
        var third = await InsertAsync(host);
        await PostgresFixture.ExecuteAsync(host.Superuser, $"SET session_replication_role = replica; UPDATE tenant SET status = 'deleted' WHERE id = '{first}'; SET session_replication_role = DEFAULT");

        using var response = await host.SendAsync(HttpMethod.Get, $"{TenantsPath}?cursor={Id(first)}", cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal([Id(second), Id(third)], json.RootElement.GetProperty("tenants").EnumerateArray().Select(t => t.GetProperty("id").GetString()));

        using var all = await host.SendAsync(HttpMethod.Get, TenantsPath, cookie);
        using var page = JsonDocument.Parse(await all.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal([Id(second), Id(third)], page.RootElement.GetProperty("tenants").EnumerateArray().Select(t => t.GetProperty("id").GetString()));
    }

    /// <summary>Review item: a Tenant with no subdomain host can still be deleted: no typed value matches, so it is a mismatch, never a 404.</summary>
    [Fact]
    public async Task A_Tenant_with_no_host_is_a_confirmation_mismatch_not_unknown()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = Guid.CreateVersion7();
        await TestTenants.InsertAsync(host.Superuser, tenant);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync();
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Action, Id(tenant));

        using var response = await DeleteAsync(host, cookie, csrf, tenant, TestTenants.Host(tenant));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("confirmation_mismatch", await CodeAsync(response));
        Assert.Equal("active", await StatusAsync(host, tenant));
        Dispose(authenticators);
    }

    private static string DeletionPath(string tenant) => $"{TenantsPath}/{tenant}/deletion";

    private static string Body(string confirmation) => JsonSerializer.Serialize(new { confirmation });

    private static Task<HttpResponseMessage> DeleteAsync(AdminHost host, string cookie, string csrf, Guid tenant, string confirmation) =>
        host.SendAsync(HttpMethod.Post, DeletionPath(Id(tenant)), cookie, csrf, AdminHost.Origin, Body(confirmation));

    private static Task<string> StatusAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{tenant}'");

    private static Task<long> DeniedAsync(AdminHost host, Guid admin) =>
        host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{admin}'");

    private static void Dispose(SoftwareAuthenticator[] authenticators)
    {
        foreach (var authenticator in authenticators)
        {
            authenticator.Dispose();
        }
    }

    /// <summary>Creates a Tenant named after its subdomain through the API, which must pass. Returns it and its creation Operation.</summary>
    private static async Task<(Guid Tenant, Guid Operation)> CreatedAsync(AdminHost host, string cookie, string csrf, string subdomain)
    {
        using var response = await host.SendAsync(HttpMethod.Post, TenantsPath, cookie, csrf, AdminHost.Origin, JsonSerializer.Serialize(new { name = subdomain, subdomain, label = "dev" }));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.True(PublicId.TryParse(PublicIdType.Tenant, json.RootElement.GetProperty("tenant").GetProperty("id").GetString(), out var tenant));
        Assert.True(PublicId.TryParse(PublicIdType.Operation, json.RootElement.GetProperty("operation").GetProperty("id").GetString(), out var operation));
        return (tenant, operation);
    }

    /// <summary>Runs the Worker's jobs in-process against the host's database until none is due.</summary>
    private async Task DrainAsync(AdminHost host, IKeyCustody? custody, Microsoft.Extensions.Logging.ILogger? logger = null)
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
            logger);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }
}
