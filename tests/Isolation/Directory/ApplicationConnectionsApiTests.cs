using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Connections;

/// <summary>
/// Story 4.12 (FR-14, AD-5) on the real Host.Admin and PostgreSQL: an Application's Connections
/// (<c>GET …/applications/{applicationId}/connections</c>), its toggle (<c>PUT …/connections/{connectionId}</c>) and a
/// Connection's Applications (<c>GET …/connections/database/applications</c>). Any Tenant Role reads; Editors, Owners and
/// machine principals with <c>tenant.connections.toggle</c> toggle, writing <c>directory.application_connection.updated</c>
/// only when the value changes; a Viewer is 403. An unknown, malformed, deleted, other-Tenant or system Application, and an
/// unknown Connection, is 404 <c>not_found</c>.
/// </summary>
public sealed class ApplicationConnectionsApiTests(PostgresFixture postgres)
{
    private const string Updated = "directory.application_connection.updated";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Every_role_reads_a_new_Applications_Connections_on()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (owner, ownerCsrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var app = await CreateAppAsync(host, owner, ownerCsrf, tenant, "Shop", "web");

        foreach (var role in new[] { "viewer", "editor", "owner" })
        {
            var (cookie, _, _) = await RoleSessionAsync(host, tenant, role);
            using var response = await host.SendAsync(HttpMethod.Get, ConnectionsPath(tenant, app), cookie);
            var json = await OkAsync(response);
            Assert.Equal(["connections"], json.EnumerateObject().Select(p => p.Name));
            var connection = Assert.Single(json.GetProperty("connections").EnumerateArray());
            Assert.Equal(
                """{"connectionId":"database","name":"Username-Password","kind":"database","enabled":true,"tenantEnabled":true}""",
                connection.GetRawText());
        }
    }

    [Fact]
    public async Task An_Editor_toggles_with_one_event_and_an_unchanged_toggle_writes_none()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "Shop", "web");

        using (var response = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, app), """{"enabled":false}"""))
        {
            var json = await OkAsync(response);
            Assert.False(json.GetProperty("enabled").GetBoolean());
            Assert.True(json.GetProperty("tenantEnabled").GetBoolean());
            Assert.Equal("database", json.GetProperty("connectionId").GetString());
        }

        Assert.False(await host.ScalarAsync<bool>($"SELECT enabled FROM application_connection WHERE application_id = '{IdOf(app)}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_kind = 'admin' " +
            $"AND actor_id = '{editor}' AND target_kind = 'client' AND target_id = '{IdOf(app)}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_detail d JOIN audit_event e ON e.id = d.event_id WHERE e.tenant_id = '{tenant}' AND e.type_code = '{Updated}'"));

        // The same value again: 200, and no event.
        using (var again = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, app), """{"enabled":false}"""))
        {
            Assert.False((await OkAsync(again)).GetProperty("enabled").GetBoolean());
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));

        using (var read = await host.SendAsync(HttpMethod.Get, ConnectionsPath(tenant, app), cookie))
        {
            var connection = Assert.Single((await OkAsync(read)).GetProperty("connections").EnumerateArray());
            Assert.False(connection.GetProperty("enabled").GetBoolean());
        }

        using (var on = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, app), """{"enabled":true}"""))
        {
            Assert.True((await OkAsync(on)).GetProperty("enabled").GetBoolean());
        }

        Assert.Equal(2L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_Viewer_reads_but_is_403_on_the_toggle_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (owner, ownerCsrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var app = await CreateAppAsync(host, owner, ownerCsrf, tenant, "Shop", "spa");
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using (var read = await host.SendAsync(HttpMethod.Get, ConnectionsPath(tenant, app), cookie))
        {
            await OkAsync(read);
        }

        using (var response = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, app), """{"enabled":false}"""))
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.True(await host.ScalarAsync<bool>($"SELECT enabled FROM application_connection WHERE application_id = '{IdOf(app)}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task The_system_another_Tenants_deleted_unknown_and_malformed_Application_and_an_unknown_Connection_are_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host);
        var b = await TenantAsync(host);
        var system = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{b}', '{system}', 'Account Portal', 'system', now())");
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var appOfA = await CreateAppAsync(host, ownerA, csrfA, a, "A app", "web");
        var (editorB, csrfB, _) = await RoleSessionAsync(host, b, "editor");
        var deleted = await CreateAppAsync(host, editorB, csrfB, b, "Gone", "web");
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE application SET deleted_at = now() WHERE id = '{IdOf(deleted)}'");

        foreach (var id in new[]
            { appOfA, deleted, PublicId.Format(PublicIdType.Application, system), PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()), "app_x", "nope" })
        {
            using (var read = await host.SendAsync(HttpMethod.Get, ConnectionsPath(b, id), editorB))
            {
                Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
                Assert.Equal("not_found", await CodeAsync(read));
            }

            using var save = await PutAsync(host, editorB, csrfB, b, ConnectionPath(b, id), """{"enabled":false}""");
            Assert.Equal(HttpStatusCode.NotFound, save.StatusCode);
            Assert.Equal("not_found", await CodeAsync(save));
        }

        // A Connection other than the database one.
        var own = await CreateAppAsync(host, editorB, csrfB, b, "B app", "web");
        using (var unknown = await PutAsync(host, editorB, csrfB, b, $"{ConnectionsPath(b, own)}/social", """{"enabled":false}"""))
        {
            Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
            Assert.Equal("not_found", await CodeAsync(unknown));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM application_connection WHERE application_id = '{system}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM application_connection WHERE NOT enabled"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Updated}'"));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"enabled":"no"}""")]
    [InlineData("not json")]
    public async Task A_malformed_toggle_is_400_with_no_errors(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "Shop", "web");

        using var response = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, app), body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("connection_invalid", json.RootElement.GetProperty("code").GetString());
        Assert.False(json.RootElement.TryGetProperty("errors", out _));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task The_Connections_Applications_are_those_it_is_enabled_for_by_name_never_the_system_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{tenant}', gen_random_uuid(), 'Account Portal', 'system', now())");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var shop = await CreateAppAsync(host, cookie, csrf, tenant, "Shop", "web");
        var off = await CreateAppAsync(host, cookie, csrf, tenant, "Back office", "spa");
        var admin = await CreateAppAsync(host, cookie, csrf, tenant, "Admin console", "native");
        using (var toggled = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, off), """{"enabled":false}"""))
        {
            await OkAsync(toggled);
        }

        var (viewer, _, _) = await RoleSessionAsync(host, tenant, "viewer");
        using var response = await host.SendAsync(HttpMethod.Get, ApplicationsPath(tenant), viewer);
        var json = await OkAsync(response);

        Assert.Equal(
            $$"""[{"id":"{{admin}}","name":"Admin console","type":"native"},{"id":"{{shop}}","name":"Shop","type":"web"}]""",
            json.GetProperty("applications").GetRawText());
    }

    [Fact]
    public async Task A_Tenant_with_no_Connection_lists_no_Applications_as_404_and_a_foreign_Owner_is_403()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var none = await InsertAsync(host, "dev");
        var other = await TenantAsync(host);
        var (cookie, _, _) = await RoleSessionAsync(host, none, "owner");

        using (var read = await host.SendAsync(HttpMethod.Get, ApplicationsPath(none), cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
            Assert.Equal("not_found", await CodeAsync(read));
        }

        using var foreign = await host.SendAsync(HttpMethod.Get, ApplicationsPath(other), cookie);
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
    }

    [Fact]
    public async Task A_Tenant_that_isnt_active_is_409_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "Shop", "web");
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"SET session_replication_role = replica; UPDATE tenant SET status = 'creating' WHERE id = '{tenant}'; SET session_replication_role = DEFAULT");

        using var response = await PutAsync(host, cookie, csrf, tenant, ConnectionPath(tenant, app), """{"enabled":false}""");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_not_active", await CodeAsync(response));
        Assert.True(await host.ScalarAsync<bool>($"SELECT enabled FROM application_connection WHERE application_id = '{IdOf(app)}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    /// <summary>
    /// Management decides again (AD-5): a machine principal of the path Tenant holds tenant.connections.toggle and toggles as
    /// itself; one of another Tenant, and an Admin with no grant there, are refused.
    /// </summary>
    [Fact]
    public async Task Management_lets_the_path_Tenants_machine_principal_toggle_and_refuses_the_others()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(superuser, TestTenants.InsertSql(a, b));
        await PostgresFixture.ExecuteAsync(
            superuser, $"SELECT set_config('gatekeep.tenant_id', '{a}', false); {Migration20261127000000ConfigureDatabaseConnection.BackfillConnection}");
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());
        var connections = ManagementContract.CreateDatabaseConnections(AuditContract.CreateAppender());
        var own = TestOnlyMachinePrincipal.For(a);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
        var context = scope.CreateCommandContext();
        var created = await applications.CreateAsync(context, own, null, a, "Worker", "machine", Cancellation);
        var id = created.Application!.Id;

        foreach (var principal in new Gatekeep.Modules.Admins.Contracts.Principal[]
        {
            TestOnlyMachinePrincipal.For(b),
            new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true),
        })
        {
            Assert.Equal(
                ConnectionStatus.Forbidden,
                (await connections.SetApplicationConnectionAsync(context, principal, null, a, id, "database", false, Cancellation)).Status);
        }

        var saved = await connections.SetApplicationConnectionAsync(context, own, null, a, id, "database", false, Cancellation);
        Assert.Equal(ConnectionStatus.Done, saved.Status);
        Assert.True(saved.Changed);
        Assert.False(Assert.Single(saved.Connections).Enabled);
        await scope.CommitAsync(Cancellation);

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = '{Updated}' AND actor_kind = 'client' AND actor_id = '{own.ClientId}' AND target_id = '{id}'"));
    }

    /// <summary>A Tenant with its database Connection, as the migration's backfill writes it.</summary>
    private static async Task<Guid> TenantAsync(AdminHost host)
    {
        var tenant = await InsertAsync(host, "dev");
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SELECT set_config('gatekeep.tenant_id', '{tenant}', false); {Migration20261127000000ConfigureDatabaseConnection.BackfillConnection}");
        return tenant;
    }

    private static string ConnectionsPath(Guid tenant, string app) => $"/api/v1/tenants/{Id(tenant)}/applications/{app}/connections";

    private static string ConnectionPath(Guid tenant, string app) => $"{ConnectionsPath(tenant, app)}/database";

    private static string ApplicationsPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/connections/database/applications";

    private static Guid IdOf(string app) =>
        PublicId.TryParse(PublicIdType.Application, app, out var id) ? id : throw new ArgumentException("Not an app_ ID.", nameof(app));

    private static Task<HttpResponseMessage> PutAsync(AdminHost host, string cookie, string csrf, Guid tenant, string path, string body) =>
        SetBodyAsync(host, cookie, csrf, path, body, Id(tenant));

    private static async Task<string> CreateAppAsync(AdminHost host, string cookie, string csrf, Guid tenant, string name, string type)
    {
        using var response = await host.SendAsync(
            HttpMethod.Post,
            $"/api/v1/tenants/{Id(tenant)}/applications",
            cookie,
            csrf,
            AdminHost.Origin,
            JsonSerializer.Serialize(new { name, type }),
            [(Header, Id(tenant))]);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("id").GetString()!;
    }

    private static async Task<JsonElement> OkAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.Clone();
    }
}
