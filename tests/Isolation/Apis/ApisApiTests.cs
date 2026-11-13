using System.Net;
using System.Reflection;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Apis;

/// <summary>
/// Story 3.6 (FR-15, FR-16) on the real Host.Admin and PostgreSQL: a Tenant's APIs and their Permissions under
/// <c>/api/v1/tenants/{tenantId}/apis</c>. Any Tenant Role reads; Editors, Owners and machine principals with
/// <c>tenant.apis.manage</c> create APIs, save their settings and add and remove Permissions, each write one command
/// with one event. The built-in Management API is listed first, and its identifier and Permissions are fixed. One test
/// or more per row of the story's I/O matrix; the creation and backfill rows are in the Operations and Keys tests.
/// </summary>
public sealed class ApisApiTests(PostgresFixture postgres)
{
    private const string Created = "directory.api.created";
    private const string Updated = "directory.api.updated";
    private const string Added = "directory.api.permission_added";
    private const string Removed = "directory.api.permission_removed";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_list_shows_the_built_in_Management_API_first_with_its_18_Permissions()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var created = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");

        using var list = await host.SendAsync(HttpMethod.Get, ApisPath(tenant), cookie);
        var json = await OkAsync(list);
        var apis = json.GetProperty("apis").EnumerateArray().ToList();

        Assert.Equal(2, apis.Count);
        Assert.True(apis[0].GetProperty("builtIn").GetBoolean());
        Assert.Equal(DirectoryContract.ManagementApiName, apis[0].GetProperty("name").GetString());
        Assert.Equal(DirectoryContract.ManagementApiIdentifier, apis[0].GetProperty("identifier").GetString());
        Assert.False(apis[0].GetProperty("offlineAccess").GetBoolean());
        Assert.False(apis[0].GetProperty("rbac").GetBoolean());
        Assert.Equal(created, apis[1].GetProperty("id").GetString());
        Assert.Equal(JsonValueKind.Null, json.GetProperty("nextCursor").ValueKind);

        using var read = await host.SendAsync(HttpMethod.Get, ApiPath(tenant, apis[0].GetProperty("id").GetString()!), cookie);
        var detail = await OkAsync(read);
        Assert.Equal(
            DirectoryContract.ManagementPermissions.Order(StringComparer.Ordinal),
            detail.GetProperty("permissions").EnumerateArray().Select(p => p.GetProperty("value").GetString()!));
    }

    [Fact]
    public async Task An_Editor_creates_an_API_with_the_defaults_one_event_and_a_Location()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PostAsync(host, cookie, csrf, ApisPath(tenant), tenant, JsonSerializer.Serialize(new { name = "  Billing  ", identifier = "https://api.example.com" }));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var api = json.RootElement.GetProperty("api");
        var id = api.GetProperty("id").GetString()!;
        Assert.Equal($"{ApisPath(tenant)}/{id}", response.Headers.Location?.ToString());
        Assert.Equal("Billing", api.GetProperty("name").GetString());
        Assert.Equal("https://api.example.com", api.GetProperty("identifier").GetString());
        Assert.False(api.GetProperty("builtIn").GetBoolean());
        Assert.False(api.GetProperty("offlineAccess").GetBoolean());
        Assert.False(api.GetProperty("rbac").GetBoolean());
        AssertLifetimes(api, 900, 900, 2592000, 604800);
        Assert.Empty(json.RootElement.GetProperty("permissions").EnumerateArray());

        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Created}' AND actor_kind = 'admin' AND actor_id = '{editor}' AND target_kind = 'api' AND target_id = '{IdOf(id)}'"));
    }

    /// <summary>
    /// More than a page: every page by nextCursor holds each API exactly once, the built-in one only first on the first
    /// page, and the rest newest first throughout.
    /// </summary>
    [Fact]
    public async Task The_list_pages_by_cursor_with_the_built_in_API_only_on_the_first_page()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");
        var builtIn = await host.ScalarAsync<Guid>($"SELECT id FROM api WHERE tenant_id = '{tenant}' AND built_in");
        var created = Enumerable.Range(0, 55).Select(_ => Guid.CreateVersion7()).ToList();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            string.Join("; ", created.Select((id, n) =>
                $"INSERT INTO api (tenant_id, id, name, identifier, created_at) VALUES ('{tenant}', '{id}', 'API {n}', 'https://api{n}.example.com', now())")));

        var pages = new List<List<string>>();
        string? cursor = null;
        do
        {
            using var response = await host.SendAsync(HttpMethod.Get, ApisPath(tenant) + (cursor is null ? string.Empty : $"?cursor={cursor}"), cookie);
            var json = await OkAsync(response);
            pages.Add([.. json.GetProperty("apis").EnumerateArray().Select(a => a.GetProperty("id").GetString()!)]);
            cursor = json.GetProperty("nextCursor").GetString();
        }
        while (cursor is not null && pages.Count < 5);

        Assert.Equal([50, 6], pages.Select(p => p.Count));
        // Newest first is the database's uuid order: IDs made in one millisecond aren't ordered by when they were made.
        var newestFirst = (await host.ScalarAsync<string>($"SELECT string_agg(id::text, ',' ORDER BY id DESC) FROM api WHERE tenant_id = '{tenant}' AND NOT built_in"))
            .Split(',')
            .Select(Guid.Parse);
        Assert.Equal(created.Order(), newestFirst.Order());
        var expected = new[] { builtIn }.Concat(newestFirst).Select(id => PublicId.Format(PublicIdType.Api, id));
        Assert.Equal(expected, pages.SelectMany(p => p));
        Assert.Equal(PublicId.Format(PublicIdType.Api, builtIn), pages[0][0]);
        Assert.DoesNotContain(PublicId.Format(PublicIdType.Api, builtIn), pages[1]);
    }

    [Fact]
    public async Task A_malformed_or_repeated_cursor_is_400_invalid_request()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");
        var valid = PublicId.Format(PublicIdType.Api, Guid.CreateVersion7());

        foreach (var query in new[] { "?cursor=nope", "?cursor=", $"?cursor={PublicId.Format(PublicIdType.Application, Guid.CreateVersion7())}", $"?cursor={valid}&cursor={valid}" })
        {
            using var response = await host.SendAsync(HttpMethod.Get, ApisPath(tenant) + query, cookie);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_request", await CodeAsync(response));
        }
    }

    /// <summary>An API holds at most 200 Permissions: the 200th is added, the 201st is 409 permission_limit_reached and writes nothing.</summary>
    [Fact]
    public async Task The_200th_Permission_is_added_and_the_201st_is_409_permission_limit_reached()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"INSERT INTO permission (tenant_id, api_id, value, description, created_at) SELECT '{tenant}', '{IdOf(api)}', 'seeded:p' || g, '', now() FROM generate_series(1, 199) AS g");

        using (var last = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, Permission("invoices:read", "")))
        {
            Assert.Equal(HttpStatusCode.Created, last.StatusCode);
        }

        using (var over = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, Permission("invoices:write", "")))
        {
            Assert.Equal(HttpStatusCode.Conflict, over.StatusCode);
            Assert.Equal("permission_limit_reached", await CodeAsync(over));
        }

        Assert.Equal(200L, await host.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE api_id = '{IdOf(api)}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE api_id = '{IdOf(api)}' AND value = 'invoices:write'"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Added));
    }

    [Fact]
    public async Task A_malformed_settings_body_is_400_api_invalid_with_no_errors_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");
        var before = await host.ScalarAsync<string>($"SELECT to_jsonb(a)::text FROM api a WHERE id = '{IdOf(api)}'");

        foreach (var body in new[]
        {
            """{"rbac":true,"accessTokenLifetime":600,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""",
            """{"offlineAccess":true,"accessTokenLifetime":600,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""",
            """{"offlineAccess":true,"rbac":true,"accessTokenLifetime":"600","idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""",
            """{"offlineAccess":true,"rbac":true,"accessTokenLifetime":1.5,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""",
            """{"offlineAccess":true,"rbac":true,"accessTokenLifetime":null,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""",
        })
        {
            using var response = await SaveAsync(host, cookie, csrf, tenant, api, body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("api_invalid", json.RootElement.GetProperty("code").GetString());
            Assert.True(
                !json.RootElement.TryGetProperty("errors", out var errors) || errors.ValueKind == JsonValueKind.Null,
                $"{body} answered errors.");
        }

        Assert.Equal(before, await host.ScalarAsync<string>($"SELECT to_jsonb(a)::text FROM api a WHERE id = '{IdOf(api)}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    /// <summary>The Log reads an event aimed at an API (Story 3.6): its target is kind api with the API's public ID.</summary>
    [Fact]
    public async Task The_Log_shows_an_API_event_with_the_api_target_kind_and_its_public_ID()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");

        using var response = await host.SendAsync(HttpMethod.Get, $"/api/v1/tenants/{Id(tenant)}/logs?type={Created}", cookie);
        var json = await OkAsync(response);

        var created = Assert.Single(json.GetProperty("events").EnumerateArray());
        Assert.Equal(Created, created.GetProperty("type").GetString());
        Assert.Equal("api", created.GetProperty("target").GetProperty("kind").GetString());
        Assert.Equal(api, created.GetProperty("target").GetProperty("id").GetString());
    }

    [Fact]
    public async Task An_identifier_is_unique_in_its_Tenant_only()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host);
        var b = await TenantAsync(host);
        var (cookieA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var (cookieB, csrfB, _) = await RoleSessionAsync(host, b, "owner");
        await CreateApiAsync(host, cookieA, csrfA, a, "https://api.example.com");

        using (var duplicate = await PostAsync(host, cookieA, csrfA, ApisPath(a), a, Body("Again", "https://api.example.com")))
        {
            Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
            Assert.Equal("api_identifier_taken", await CodeAsync(duplicate));
        }

        // Exact match: a different case is another identifier.
        await CreateApiAsync(host, cookieA, csrfA, a, "https://API.example.com");
        await CreateApiAsync(host, cookieB, csrfB, b, "https://api.example.com");

        Assert.Equal(1L, await TenantEventsAsync(host, b, Created));
        Assert.Equal(2L, await TenantEventsAsync(host, a, Created));
        Assert.Equal(3L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{a}'"));
    }

    public static TheoryData<string, string> BadCreates => new()
    {
        { Body("API", ""), "identifier invalid" },
        { Body("API", "api.example.com"), "identifier invalid" },
        { Body("API", "https://api.example.com/#frag"), "identifier invalid" },
        { Body("API", "https://" + new string('a', 248)), "identifier invalid" },
        { Body("API", " https://api.example.com"), "identifier invalid" },
        { Body("API", "urn:gatekeep:x"), "identifier reserved" },
        { Body("API", "urn:gatekeep:management"), "identifier reserved" },
        { Body("   ", "https://api.example.com"), "name invalid" },
        { Body(new string('n', 201), "https://api.example.com"), "name invalid" },
        { Body("", "nope"), "name invalid; identifier invalid" },
    };

    [Theory]
    [MemberData(nameof(BadCreates))]
    public async Task A_bad_name_or_identifier_is_400_api_invalid_naming_each_and_nothing_is_written(string body, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PostAsync(host, cookie, csrf, ApisPath(tenant), tenant, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(expected, await ErrorsAsync(response, "api_invalid"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Created));
    }

    [Fact]
    public async Task A_malformed_create_body_is_400_api_invalid_with_no_errors()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        foreach (var body in new[] { "{", """{"name":"API"}""", """{"name":1,"identifier":"https://a.example"}""", "null" })
        {
            using var response = await PostAsync(host, cookie, csrf, ApisPath(tenant), tenant, body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("api_invalid", await CodeAsync(response));
        }

        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Created));
    }

    [Fact]
    public async Task A_Permission_is_added_once_and_a_bad_one_is_refused()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var api = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");

        using (var added = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, Permission("invoices:read", "  Read invoices  ")))
        {
            Assert.Equal(HttpStatusCode.Created, added.StatusCode);
            using var json = JsonDocument.Parse(await added.Content.ReadAsStringAsync(Cancellation));
            var permission = Assert.Single(json.RootElement.GetProperty("permissions").EnumerateArray());
            Assert.Equal("invoices:read", permission.GetProperty("value").GetString());
            Assert.Equal("Read invoices", permission.GetProperty("description").GetString());
        }

        using (var again = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, Permission("invoices:read", "")))
        {
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
            Assert.Equal("permission_taken", await CodeAsync(again));
        }

        foreach (var (body, expected) in new[]
        {
            (Permission("Invoices:read", ""), "value invalid"),
            (Permission("invoices", ""), "value invalid"),
            (Permission(":read", ""), "value invalid"),
            (Permission("invoices:read\n", ""), "value invalid"),
            (Permission("invoices:write", new string('d', 201)), "description invalid"),
        })
        {
            using var refused = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, body);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Equal(expected, await ErrorsAsync(refused, "api_invalid"));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE api_id = '{IdOf(api)}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Added}' AND actor_id = '{editor}' AND target_kind = 'api' AND target_id = '{IdOf(api)}'"));
    }

    [Fact]
    public async Task A_Permission_is_removed_with_one_event_and_an_unknown_one_is_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var api = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");
        using (var added = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, Permission("invoices:read", "")))
        {
            Assert.Equal(HttpStatusCode.Created, added.StatusCode);
        }

        using (var removed = await DeleteAsync(host, cookie, csrf, $"{PermissionsPath(tenant, api)}/invoices%3Aread", tenant))
        {
            Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        }

        using (var again = await DeleteAsync(host, cookie, csrf, $"{PermissionsPath(tenant, api)}/invoices:read", tenant))
        {
            Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);
            Assert.Equal("not_found", await CodeAsync(again));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE api_id = '{IdOf(api)}'"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Removed));
    }

    [Fact]
    public async Task The_built_in_APIs_Permissions_are_fixed_but_its_settings_save()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var builtIn = PublicId.Format(PublicIdType.Api, await host.ScalarAsync<Guid>($"SELECT id FROM api WHERE tenant_id = '{tenant}' AND built_in"));

        using (var add = await PostAsync(host, cookie, csrf, PermissionsPath(tenant, builtIn), tenant, Permission("extra:read", "")))
        {
            Assert.Equal(HttpStatusCode.Conflict, add.StatusCode);
            Assert.Equal("api_built_in", await CodeAsync(add));
        }

        using (var remove = await DeleteAsync(host, cookie, csrf, $"{PermissionsPath(tenant, builtIn)}/users:read", tenant))
        {
            Assert.Equal(HttpStatusCode.Conflict, remove.StatusCode);
            Assert.Equal("api_built_in", await CodeAsync(remove));
        }

        Assert.Equal(18L, await host.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE api_id = '{IdOf(builtIn)}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Added) + await TenantEventsAsync(host, tenant, Removed));

        using var saved = await SaveAsync(host, cookie, csrf, tenant, builtIn, Settings(false, true, 600, 900, 2592000, 604800));
        var api = (await OkAsync(saved)).GetProperty("api");
        Assert.True(api.GetProperty("rbac").GetBoolean());
        Assert.Equal(DirectoryContract.ManagementApiIdentifier, api.GetProperty("identifier").GetString());
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task Settings_save_with_one_event_an_unchanged_save_writes_nothing_and_a_lifetime_over_its_limit_is_named()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var api = await CreateApiAsync(host, cookie, csrf, tenant, "https://api.example.com");

        using (var saved = await SaveAsync(host, cookie, csrf, tenant, api, Settings(true, true, 600, 900, 2592000, 604800)))
        {
            var json = (await OkAsync(saved)).GetProperty("api");
            Assert.True(json.GetProperty("offlineAccess").GetBoolean());
            Assert.True(json.GetProperty("rbac").GetBoolean());
            AssertLifetimes(json, 600, 900, 2592000, 604800);
        }

        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_id = '{editor}' AND target_kind = 'api' AND target_id = '{IdOf(api)}'"));

        using (var unchanged = await SaveAsync(host, cookie, csrf, tenant, api, Settings(true, true, 600, 900, 2592000, 604800)))
        {
            await OkAsync(unchanged);
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));

        using (var over = await SaveAsync(host, cookie, csrf, tenant, api, Settings(true, true, 3601, 900, 2592000, 604800)))
        {
            Assert.Equal(HttpStatusCode.BadRequest, over.StatusCode);
            using var json = JsonDocument.Parse(await over.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("api_invalid", json.RootElement.GetProperty("code").GetString());
            var error = Assert.Single(json.RootElement.GetProperty("errors").EnumerateArray());
            Assert.Equal("accessTokenLifetime", error.GetProperty("field").GetString());
            Assert.Equal("above_maximum", error.GetProperty("reason").GetString());
            Assert.Equal(3600, error.GetProperty("maximum").GetInt32());
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE id = '{IdOf(api)}' AND access_token_lifetime = 600"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_Viewer_reads_but_every_write_is_403_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (editor, editorCsrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var api = await CreateApiAsync(host, editor, editorCsrf, tenant, "https://api.example.com");
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using (var list = await host.SendAsync(HttpMethod.Get, ApisPath(tenant), cookie))
        {
            await OkAsync(list);
        }

        using (var read = await host.SendAsync(HttpMethod.Get, ApiPath(tenant, api), cookie))
        {
            await OkAsync(read);
        }

        var writes = new List<HttpResponseMessage>
        {
            await PostAsync(host, cookie, csrf, ApisPath(tenant), tenant, Body("API", "https://other.example.com")),
            await SaveAsync(host, cookie, csrf, tenant, api, Settings(true, true, 600, 900, 2592000, 604800)),
            await PostAsync(host, cookie, csrf, PermissionsPath(tenant, api), tenant, Permission("invoices:read", "")),
            await DeleteAsync(host, cookie, csrf, $"{PermissionsPath(tenant, api)}/invoices:read", tenant),
        };
        foreach (var response in writes)
        {
            using (response)
            {
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                Assert.Equal("access_denied", await CodeAsync(response));
            }
        }

        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code LIKE 'directory.api.%'"));
        Assert.Equal(4L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task Another_Tenants_unknown_and_malformed_API_are_the_same_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host);
        var b = await TenantAsync(host);
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var apiOfA = await CreateApiAsync(host, ownerA, csrfA, a, "https://api.example.com");
        var (ownerB, csrfB, _) = await RoleSessionAsync(host, b, "owner");

        foreach (var id in new[] { apiOfA, PublicId.Format(PublicIdType.Api, Guid.CreateVersion7()), "api_x", "nope" })
        {
            foreach (var response in new[]
            {
                await host.SendAsync(HttpMethod.Get, ApiPath(b, id), ownerB),
                await SaveAsync(host, ownerB, csrfB, b, id, Settings(true, true, 600, 900, 2592000, 604800)),
                await PostAsync(host, ownerB, csrfB, PermissionsPath(b, id), b, Permission("invoices:read", "")),
                await DeleteAsync(host, ownerB, csrfB, $"{PermissionsPath(b, id)}/invoices:read", b),
            })
            {
                using (response)
                {
                    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
                    Assert.Equal("not_found", await CodeAsync(response));
                }
            }
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{b}' AND type_code LIKE 'directory.api.%'"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE id = '{IdOf(apiOfA)}' AND NOT offline_access"));
    }

    [Fact]
    public async Task The_identifier_column_is_never_updatable_by_gk_admin()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);

        await using var connection = new NpgsqlConnection(postgres.RoleConnection(TableRegistry.Admin, host.Database));
        await connection.OpenAsync(Cancellation);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT set_config('gatekeep.tenant_id', '{tenant}', false); UPDATE api SET identifier = 'https://changed.example' WHERE tenant_id = '{tenant}'";
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{tenant}' AND identifier = '{DirectoryContract.ManagementApiIdentifier}'"));
    }

    /// <summary>
    /// Management decides again (AD-5): a machine principal of the path Tenant holds tenant.apis.manage and creates as
    /// itself; one of another Tenant, and an Admin with no grant there, are refused.
    /// </summary>
    [Fact]
    public async Task Management_lets_the_path_Tenants_machine_principal_create_and_refuses_the_others()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a, b));
        var apis = ManagementContract.CreateApis(AuditContract.CreateAppender());
        var own = TestOnlyMachinePrincipal.For(a);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
        var context = scope.CreateCommandContext();

        foreach (var principal in new Gatekeep.Modules.Admins.Contracts.Principal[]
        {
            TestOnlyMachinePrincipal.For(b),
            new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true),
        })
        {
            Assert.Equal(ApiStatus.Forbidden, (await apis.CreateAsync(context, principal, null, a, "Worker", "https://w.example", Cancellation)).Status);
        }

        var created = await apis.CreateAsync(context, own, null, a, "Worker", "https://w.example", Cancellation);
        Assert.Equal(ApiStatus.Done, created.Status);
        await scope.CommitAsync(Cancellation);

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database),
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = '{Created}' AND actor_kind = 'client' AND actor_id = '{own.ClientId}' AND target_id = '{created.Api!.Id}'"));
    }

    /// <summary>
    /// The shorter-wins row (FR-15), at Protocol's one lifetime lookup: each lifetime is the shorter of the Application's
    /// and the API's, and with no API it is the Application's. No token names an API until Story 3.7.
    /// </summary>
    [Theory]
    [InlineData(900, 600, 600)]
    [InlineData(300, 900, 300)]
    [InlineData(900, null, 900)]
    public void Of_takes_the_shorter_of_each_lifetime(int application, int? api, int expected)
    {
        var app = Application(new ApplicationLifetimes(application, 900, 2592000, 604800));
        var resource = api is { } seconds
            ? new DirectoryApi(Guid.CreateVersion7(), "API", "https://api.example.com", false, false, false, new ApplicationLifetimes(seconds, 600, 86400, 3600), DateTimeOffset.UtcNow)
            : null;

        var lifetimes = Of(app, resource);

        Assert.Equal(TimeSpan.FromSeconds(expected), lifetimes.AccessToken);
        Assert.Equal(TimeSpan.FromSeconds(api is null ? 900 : 600), lifetimes.IdentityToken);
        Assert.Equal(TimeSpan.FromSeconds(api is null ? 2592000 : 86400), lifetimes.RefreshTokenAbsolute);
        Assert.Equal(TimeSpan.FromSeconds(api is null ? 604800 : 3600), lifetimes.RefreshTokenInactivity);
    }

    /// <summary>Protocol's internal <c>ApplicationTokenLifetimes.Of</c>, by reflection: no seam opens it to tests.</summary>
    private static (TimeSpan AccessToken, TimeSpan IdentityToken, TimeSpan RefreshTokenAbsolute, TimeSpan RefreshTokenInactivity) Of(DirectoryApplication application, DirectoryApi? api)
    {
        var type = typeof(ProtocolContract).Assembly.GetType("Gatekeep.Modules.Protocol.Core.ApplicationTokenLifetimes", throwOnError: true)!;
        var issued = type.GetMethod("Of", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, [application, api])!;
        TimeSpan Get(string name) => (TimeSpan)issued.GetType().GetProperty(name)!.GetValue(issued)!;
        return (Get("AccessToken"), Get("IdentityToken"), Get("RefreshTokenAbsolute"), Get("RefreshTokenInactivity"));
    }

    /// <summary>An Application row as Directory hands it over, built by its internal constructor.</summary>
    private static DirectoryApplication Application(ApplicationLifetimes lifetimes)
    {
        var id = Guid.CreateVersion7();
        return (DirectoryApplication)Activator.CreateInstance(
            typeof(DirectoryApplication),
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            args:
            [
                id,
                PublicId.Format(PublicIdType.Application, id),
                "App",
                "machine",
                System.Collections.Immutable.ImmutableArray.Create("client_credentials"),
                System.Collections.Immutable.ImmutableArray<string>.Empty,
                System.Collections.Immutable.ImmutableArray<string>.Empty,
                System.Collections.Immutable.ImmutableArray<string>.Empty,
                System.Collections.Immutable.ImmutableArray<string>.Empty,
                DateTimeOffset.UtcNow,
                lifetimes,
            ],
            culture: null)!;
    }

    /// <summary>An active Tenant with its built-in Management API, as the migration's backfill writes it.</summary>
    private static async Task<Guid> TenantAsync(AdminHost host)
    {
        var tenant = await InsertAsync(host, "dev");
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SELECT set_config('gatekeep.tenant_id', '{tenant}', false); {Migration20261118000000DefineApis.BackfillApi}; {Migration20261118000000DefineApis.BackfillPermissions}");
        return tenant;
    }

    private static string ApisPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/apis";

    private static string ApiPath(Guid tenant, string api) => $"{ApisPath(tenant)}/{api}";

    private static string PermissionsPath(Guid tenant, string api) => $"{ApiPath(tenant, api)}/permissions";

    private static string Body(string name, string identifier) => JsonSerializer.Serialize(new { name, identifier });

    private static string Permission(string value, string description) => JsonSerializer.Serialize(new { value, description });

    private static string Settings(bool offline, bool rbac, int access, int id, int absolute, int inactivity) =>
        JsonSerializer.Serialize(new
        {
            offlineAccess = offline,
            rbac,
            accessTokenLifetime = access,
            idTokenLifetime = id,
            refreshTokenAbsoluteLifetime = absolute,
            refreshTokenInactivityLifetime = inactivity,
        });

    private static Guid IdOf(string api) =>
        PublicId.TryParse(PublicIdType.Api, api, out var id) ? id : throw new ArgumentException("Not an api_ ID.", nameof(api));

    private static void AssertLifetimes(JsonElement api, int access, int id, int absolute, int inactivity)
    {
        Assert.Equal(access, api.GetProperty("accessTokenLifetime").GetInt32());
        Assert.Equal(id, api.GetProperty("idTokenLifetime").GetInt32());
        Assert.Equal(absolute, api.GetProperty("refreshTokenAbsoluteLifetime").GetInt32());
        Assert.Equal(inactivity, api.GetProperty("refreshTokenInactivityLifetime").GetInt32());
    }

    private static Task<HttpResponseMessage> PostAsync(AdminHost host, string cookie, string csrf, string path, Guid tenant, string body) =>
        host.SendAsync(HttpMethod.Post, path, cookie, csrf, AdminHost.Origin, body, [(Header, Id(tenant))]);

    private static Task<HttpResponseMessage> DeleteAsync(AdminHost host, string cookie, string csrf, string path, Guid tenant) =>
        host.SendAsync(HttpMethod.Delete, path, cookie, csrf, AdminHost.Origin, headers: [(Header, Id(tenant))]);

    private static Task<HttpResponseMessage> SaveAsync(AdminHost host, string cookie, string csrf, Guid tenant, string api, string body) =>
        SetBodyAsync(host, cookie, csrf, $"{ApiPath(tenant, api)}/settings", body, Id(tenant));

    private static async Task<string> CreateApiAsync(AdminHost host, string cookie, string csrf, Guid tenant, string identifier)
    {
        using var response = await PostAsync(host, cookie, csrf, ApisPath(tenant), tenant, Body("API", identifier));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("api").GetProperty("id").GetString()!;
    }

    private static async Task<JsonElement> OkAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.Clone();
    }

    /// <summary>The problem's code, which must be <paramref name="code"/>, then each error as "field reason", joined by "; ".</summary>
    private static async Task<string> ErrorsAsync(HttpResponseMessage response, string code)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
        return string.Join("; ", json.RootElement.GetProperty("errors").EnumerateArray().Select(e => $"{e.GetProperty("field").GetString()} {e.GetProperty("reason").GetString()}"));
    }
}
