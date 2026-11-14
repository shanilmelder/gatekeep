using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Apis;

/// <summary>
/// Story 3.7 (FR-16) on the real Host.Admin and PostgreSQL: the Permissions of an API granted to a machine-to-machine
/// Application, under <c>/api/v1/tenants/{tenantId}/apis/{apiId}/grants/{applicationId}</c>. Editors and Owners set and
/// remove them with <c>tenant.apis.manage</c>; a change writes one event naming the API, an unchanged set or a missing
/// grant writes none; any other kind of Application, the built-in Management API and an unknown Permission are refused
/// with nothing written; another Tenant's, a deleted and the system Application are the same 404. One test or more per
/// row of the story's grant API rows; the token rows are <c>Protocol/ApiTargetTests</c>.
/// </summary>
public sealed class ApiGrantsApiTests(PostgresFixture postgres)
{
    private const string Updated = "directory.api.grant_updated";
    private const string Removed = "directory.api.grant_removed";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_Editor_grants_replaces_and_reads_back_the_Permissions_with_one_event_per_change()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var api = await ApiAsync(host, tenant, "invoices:read", "payments:write", "reports:read");
        var machine = await ApplicationAsync(host, tenant, "machine", "Billing worker");

        using (var granted = await PutAsync(host, cookie, csrf, tenant, api, machine, "payments:write", "invoices:read"))
        {
            var detail = await OkAsync(granted);
            var grant = Assert.Single(detail.GetProperty("grants").EnumerateArray());
            Assert.Equal(Public(machine), grant.GetProperty("applicationId").GetString());
            Assert.Equal("Billing worker", grant.GetProperty("name").GetString());
            Assert.Equal(["invoices:read", "payments:write"], Values(grant));
        }

        Assert.Equal(2L, await RowsAsync(host, api, machine));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_kind = 'admin' AND actor_id = '{editor}' AND target_kind = 'api' AND target_id = '{api}'"));

        // The same set again changes nothing: 200, and no event.
        using (var same = await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read", "payments:write"))
        {
            await OkAsync(same);
        }

        Assert.Equal(1L, await EventsAsync(host, tenant, Updated));

        // A replace keeps only what it names.
        using (var narrowed = await PutAsync(host, cookie, csrf, tenant, api, machine, "reports:read"))
        {
            Assert.Equal(["reports:read"], Values(Assert.Single((await OkAsync(narrowed)).GetProperty("grants").EnumerateArray())));
        }

        Assert.Equal(1L, await RowsAsync(host, api, machine));
        Assert.Equal(2L, await EventsAsync(host, tenant, Updated));

        // A Viewer reads the grants on the API's detail.
        var (viewer, _, _) = await RoleSessionAsync(host, tenant, "viewer");
        using var read = await host.SendAsync(HttpMethod.Get, ApiPath(tenant, PublicApi(api)), viewer);
        Assert.Equal(["reports:read"], Values(Assert.Single((await OkAsync(read)).GetProperty("grants").EnumerateArray())));
    }

    [Fact]
    public async Task Removing_a_grant_answers_204_with_one_event_and_a_missing_one_204_with_none()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var api = await ApiAsync(host, tenant, "invoices:read");
        var machine = await ApplicationAsync(host, tenant, "machine", "Billing worker");
        using (var granted = await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read"))
        {
            await OkAsync(granted);
        }

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var removed = await DeleteAsync(host, cookie, csrf, tenant, api, machine);
            Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        }

        Assert.Equal(0L, await RowsAsync(host, api, machine));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Removed}' AND target_kind = 'api' AND target_id = '{api}'"));

        using var read = await host.SendAsync(HttpMethod.Get, ApiPath(tenant, PublicApi(api)), cookie);
        Assert.Empty((await OkAsync(read)).GetProperty("grants").EnumerateArray());
    }

    [Fact]
    public async Task A_non_machine_Application_the_built_in_API_and_bad_values_are_refused_with_nothing_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await ApiAsync(host, tenant, "invoices:read");
        var builtIn = await host.ScalarAsync<Guid>($"SELECT id FROM api WHERE tenant_id = '{tenant}' AND built_in");
        var machine = await ApplicationAsync(host, tenant, "machine", "Billing worker");

        foreach (var kind in new[] { "spa", "web", "native" })
        {
            var other = await ApplicationAsync(host, tenant, kind, $"A {kind}");
            using var refused = await PutAsync(host, cookie, csrf, tenant, api, other, "invoices:read");
            Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
            Assert.Equal("application_not_machine", await CodeAsync(refused));
        }

        using (var management = await PutAsync(host, cookie, csrf, tenant, builtIn, machine, "users:read"))
        {
            Assert.Equal(HttpStatusCode.Conflict, management.StatusCode);
            Assert.Equal("api_built_in", await CodeAsync(management));
        }

        using (var managementRemoval = await DeleteAsync(host, cookie, csrf, tenant, builtIn, machine))
        {
            Assert.Equal(HttpStatusCode.Conflict, managementRemoval.StatusCode);
            Assert.Equal("api_built_in", await CodeAsync(managementRemoval));
        }

        using (var unknown = await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read", "admin:all", "reports:read"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
            Assert.Equal("permissions 1 unknown; permissions 2 unknown", await ErrorsAsync(unknown));
        }

        using (var malformed = await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read", "Invoices", "invoices:read"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
            Assert.Equal("permissions 1 invalid; permissions 2 duplicate", await ErrorsAsync(malformed));
        }

        using (var empty = await PutAsync(host, cookie, csrf, tenant, api, machine))
        {
            Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);
            Assert.Equal("permissions - invalid", await ErrorsAsync(empty));
        }

        using (var tooMany = await PutAsync(host, cookie, csrf, tenant, api, machine, [.. Enumerable.Range(0, 201).Select(n => $"p:v{n}")]))
        {
            Assert.Equal(HttpStatusCode.BadRequest, tooMany.StatusCode);
            Assert.Equal("permissions - too_many", await ErrorsAsync(tooMany));
        }

        foreach (var body in new[] { "{}", "{\"permissions\":null}", "{\"permissions\":\"invoices:read\"}", "not json" })
        {
            using var shapeless = await SetBodyAsync(host, cookie, csrf, GrantPath(tenant, api, machine), body, Id(tenant));
            Assert.Equal(HttpStatusCode.BadRequest, shapeless.StatusCode);
            Assert.Equal("api_invalid", await CodeAsync(shapeless));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM api_grant WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code LIKE 'directory.api.grant_%'"));
    }

    [Fact]
    public async Task Another_Tenants_a_deleted_the_system_and_an_unknown_Application_are_the_same_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host);
        var b = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, a, "owner");
        var api = await ApiAsync(host, a, "invoices:read");
        var ofB = await ApiAsync(host, b, "invoices:read");
        var otherTenants = await ApplicationAsync(host, b, "machine", "B's worker");
        var deleted = await ApplicationAsync(host, a, "machine", "Deleted worker");
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE application SET deleted_at = now() WHERE id = '{deleted}'");
        var system = await SystemApplicationAsync(host, a);
        var machine = await ApplicationAsync(host, a, "machine", "Billing worker");

        foreach (var (apiId, applicationId) in new[]
        {
            (PublicApi(api), Public(otherTenants)),
            (PublicApi(api), Public(deleted)),
            (PublicApi(api), Public(system)),
            (PublicApi(api), PublicId.Format(PublicIdType.Application, Guid.CreateVersion7())),
            (PublicApi(api), "app_x"),
            (PublicApi(api), PublicId.Format(PublicIdType.Api, Guid.CreateVersion7())),
            (PublicApi(ofB), Public(machine)),
            ("nope", Public(machine)),
        })
        {
            var path = $"{ApiPath(a, apiId)}/grants/{applicationId}";
            foreach (var response in new[]
            {
                await SetBodyAsync(host, cookie, csrf, path, Body("invoices:read"), Id(a)),
                await host.SendAsync(HttpMethod.Delete, path, cookie, csrf, AdminHost.Origin, headers: [(Header, Id(a))]),
            })
            {
                using (response)
                {
                    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
                    Assert.Equal("not_found", await CodeAsync(response));
                }
            }
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM api_grant"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code LIKE 'directory.api.grant_%'"));
    }

    [Fact]
    public async Task A_Viewer_may_read_but_neither_set_nor_remove_a_grant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");
        var api = await ApiAsync(host, tenant, "invoices:read");
        var machine = await ApplicationAsync(host, tenant, "machine", "Billing worker");

        foreach (var response in new[]
        {
            await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read"),
            await DeleteAsync(host, cookie, csrf, tenant, api, machine),
        })
        {
            using (response)
            {
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                Assert.Equal("access_denied", await CodeAsync(response));
            }
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM api_grant"));
        Assert.Equal(2L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task Removing_a_Permission_removes_its_grant_rows_in_the_same_command()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await ApiAsync(host, tenant, "invoices:read", "payments:write");
        var first = await ApplicationAsync(host, tenant, "machine", "First");
        var second = await ApplicationAsync(host, tenant, "machine", "Second");
        foreach (var machine in new[] { first, second })
        {
            using var granted = await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read", "payments:write");
            await OkAsync(granted);
        }

        using (var removed = await host.SendAsync(
            HttpMethod.Delete, $"{ApiPath(tenant, PublicApi(api))}/permissions/invoices:read", cookie, csrf, AdminHost.Origin, headers: [(Header, Id(tenant))]))
        {
            Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM api_grant WHERE api_id = '{api}' AND value = 'invoices:read'"));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM api_grant WHERE api_id = '{api}' AND value = 'payments:write'"));

        using var read = await host.SendAsync(HttpMethod.Get, ApiPath(tenant, PublicApi(api)), cookie);
        Assert.All((await OkAsync(read)).GetProperty("grants").EnumerateArray(), g => Assert.Equal(["payments:write"], Values(g)));
    }

    /// <summary>A deleted Application's grant is hidden from the API's detail until its purge removes it.</summary>
    [Fact]
    public async Task A_deleted_Applications_grant_is_not_listed_on_the_API()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await ApiAsync(host, tenant, "invoices:read");
        var machine = await ApplicationAsync(host, tenant, "machine", "Billing worker");
        using (var granted = await PutAsync(host, cookie, csrf, tenant, api, machine, "invoices:read"))
        {
            Assert.Single((await OkAsync(granted)).GetProperty("grants").EnumerateArray());
        }

        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE application SET deleted_at = now() WHERE id = '{machine}'");

        using var read = await host.SendAsync(HttpMethod.Get, ApiPath(tenant, PublicApi(api)), cookie);
        Assert.Empty((await OkAsync(read)).GetProperty("grants").EnumerateArray());
        Assert.Equal(1L, await RowsAsync(host, api, machine));
    }

    /// <summary>The deleted-Application purge deletes its grants before its row, so no foreign key refuses it.</summary>
    [Fact]
    public async Task A_deleted_Applications_purge_deletes_its_grants_first()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var api = await ApiAsync(host, tenant, "invoices:read");
        var machine = await ApplicationAsync(host, tenant, "machine", "Billing worker");
        await PostgresFixture.ExecuteAsync(host.Superuser,
            $"INSERT INTO api_grant (tenant_id, api_id, application_id, value) VALUES ('{tenant}', '{api}', '{machine}', 'invoices:read'); " +
            $"UPDATE application SET deleted_at = now() WHERE id = '{machine}'");

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, host.Database));
        await using (var scope = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            await DirectoryContract.PurgeDeletedApplicationsAsync(scope.CreateCommandContext(), [machine], Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM api_grant WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{machine}'"));
    }

    private static async Task<Guid> TenantAsync(AdminHost host)
    {
        var tenant = await InsertAsync(host, "dev");
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SELECT set_config('gatekeep.tenant_id', '{tenant}', false); {Migration20261119000000DefineApis.BackfillApi}; {Migration20261119000000DefineApis.BackfillPermissions}");
        return tenant;
    }

    /// <summary>An API with <paramref name="values"/> as its Permissions, written as the superuser.</summary>
    private static async Task<Guid> ApiAsync(AdminHost host, Guid tenant, params string[] values)
    {
        var id = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(host.Superuser,
            $"INSERT INTO api (tenant_id, id, name, identifier, created_at) VALUES ('{tenant}', '{id}', 'Invoices', 'https://api.ex/{id}', now()); " +
            string.Join("; ", values.Select(v => $"INSERT INTO permission (tenant_id, api_id, value, created_at) VALUES ('{tenant}', '{id}', '{v}', now())")));
        return id;
    }

    private static async Task<Guid> ApplicationAsync(AdminHost host, Guid tenant, string kind, string name)
    {
        var id = Guid.CreateVersion7();
        var grants = kind switch { "machine" => "ARRAY['client_credentials']", "web" => "ARRAY['authorization_code']", _ => "'{}'" };
        await PostgresFixture.ExecuteAsync(host.Superuser,
            $"INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES ('{tenant}', '{id}', '{name.Replace("'", "''", StringComparison.Ordinal)}', '{kind}', {grants}, now())");
        return id;
    }

    private async Task<Guid> SystemApplicationAsync(AdminHost host, Guid tenant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, host.Database));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var id = await DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System)
            .EnsureSystemApplicationAsync(scope.CreateCommandContext(), Cancellation);
        await scope.CommitAsync(Cancellation);
        return id;
    }

    private static Task<long> RowsAsync(AdminHost host, Guid api, Guid application) =>
        host.ScalarAsync<long>($"SELECT count(*) FROM api_grant WHERE api_id = '{api}' AND application_id = '{application}'");

    private static Task<long> EventsAsync(AdminHost host, Guid tenant, string code) =>
        host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{code}'");

    private static string Public(Guid application) => PublicId.Format(PublicIdType.Application, application);

    private static string PublicApi(Guid api) => PublicId.Format(PublicIdType.Api, api);

    private static string ApiPath(Guid tenant, string api) => $"/api/v1/tenants/{Id(tenant)}/apis/{api}";

    private static string GrantPath(Guid tenant, Guid api, Guid application) =>
        $"{ApiPath(tenant, PublicId.Format(PublicIdType.Api, api))}/grants/{PublicId.Format(PublicIdType.Application, application)}";

    private static string Body(params string[] permissions) => JsonSerializer.Serialize(new { permissions });

    private static Task<HttpResponseMessage> PutAsync(
        AdminHost host, string cookie, string csrf, Guid tenant, Guid api, Guid application, params string[] permissions) =>
        SetBodyAsync(host, cookie, csrf, GrantPath(tenant, api, application), Body(permissions), Id(tenant));

    private static Task<HttpResponseMessage> DeleteAsync(AdminHost host, string cookie, string csrf, Guid tenant, Guid api, Guid application) =>
        host.SendAsync(HttpMethod.Delete, GrantPath(tenant, api, application), cookie, csrf, AdminHost.Origin, headers: [(Header, Id(tenant))]);

    private static List<string> Values(JsonElement grant) =>
        [.. grant.GetProperty("permissions").EnumerateArray().Select(p => p.GetString()!)];

    private static async Task<JsonElement> OkAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.Clone();
    }

    /// <summary>Each error as "field index reason", the index "-" when the whole field is refused, joined by "; ".</summary>
    private static async Task<string> ErrorsAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("api_invalid", json.RootElement.GetProperty("code").GetString());
        return string.Join("; ", json.RootElement.GetProperty("errors").EnumerateArray().Select(e =>
            $"{e.GetProperty("field").GetString()} {(e.GetProperty("index").ValueKind == JsonValueKind.Null ? "-" : e.GetProperty("index").GetInt32().ToString(System.Globalization.CultureInfo.InvariantCulture))} {e.GetProperty("reason").GetString()}"));
    }
}
