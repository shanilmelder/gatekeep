using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Applications;

/// <summary>
/// Story 3.4 (FR-15, PRD §5.2) on the real Host.Admin and PostgreSQL:
/// <c>PUT /api/v1/tenants/{tenantId}/applications/{applicationId}/tokens</c>. Editors and Owners, and machine
/// principals with <c>tenant.applications.manage</c>, save an Application's four token lifetimes in seconds, each
/// 1 to its hard limit, with no fresh assertion; an over-limit value is 400 <c>above_maximum</c> with the limit as
/// <c>maximum</c>, and the table's CHECKs refuse it too. A save writes <c>directory.application.updated</c>, a
/// no-op nothing. One test or more per API row of the story's I/O matrix; the issuance rows are
/// <see cref="ApplicationLifetimeProtocolTests"/>.
/// </summary>
public sealed class ApplicationTokensApiTests(PostgresFixture postgres)
{
    private const string Updated = "directory.application.updated";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("spa")]
    [InlineData("web")]
    [InlineData("native")]
    [InlineData("machine")]
    public async Task A_new_Application_reads_the_Deployment_defaults(string type)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, type);

        using var read = await host.SendAsync(HttpMethod.Get, AppPath(tenant, app), cookie);

        AssertLifetimes(await ApplicationAsync(read), 900, 900, 2592000, 604800);
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM application WHERE id = '{IdOf(app)}' AND access_token_lifetime = 900 AND id_token_lifetime = 900 AND refresh_token_absolute_lifetime = 2592000 AND refresh_token_inactivity_lifetime = 604800"));
    }

    [Fact]
    public async Task An_Editor_saves_the_lifetimes_with_one_event_and_no_assertion()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Lifetimes(300, 600, 864000, 86400));

        var saved = await ApplicationAsync(response);
        Assert.Equal(app, saved.GetProperty("id").GetString());
        AssertLifetimes(saved, 300, 600, 864000, 86400);

        var id = IdOf(app);
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM application WHERE id = '{id}' AND access_token_lifetime = 300 AND id_token_lifetime = 600 AND refresh_token_absolute_lifetime = 864000 AND refresh_token_inactivity_lifetime = 86400"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_kind = 'admin' AND actor_id = '{editor}' AND target_kind = 'client' AND target_id = '{id}'"));
        Assert.Equal(0L, await GrantsAsync(host));

        // The read answers the same lifetimes.
        using var read = await host.SendAsync(HttpMethod.Get, AppPath(tenant, app), cookie);
        Assert.Equal(saved.GetRawText(), (await ApplicationAsync(read)).GetRawText());
    }

    [Fact]
    public async Task An_Owner_saves_too()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "machine");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Lifetimes(120, 900, 2592000, 604800));

        AssertLifetimes(await ApplicationAsync(response), 120, 900, 2592000, 604800);
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
    }

    public static TheoryData<string, string> Refusals => new()
    {
        // body, then each expected error as "field reason maximum", joined by "; ".
        { Lifetimes(3601, 900, 2592000, 604800), "accessTokenLifetime above_maximum 3600" },
        { Lifetimes(900, 3601, 2592000, 604800), "idTokenLifetime above_maximum 3600" },
        { Lifetimes(900, 900, 7776001, 604800), "refreshTokenAbsoluteLifetime above_maximum 7776000" },
        { Lifetimes(900, 900, 2592000, 2592001), "refreshTokenInactivityLifetime above_maximum 2592000" },
        { Lifetimes(900, 900, 7776001, 2592001), "refreshTokenAbsoluteLifetime above_maximum 7776000; refreshTokenInactivityLifetime above_maximum 2592000" },
        { Lifetimes(0, 900, 2592000, 604800), "accessTokenLifetime below_minimum -" },
        { Lifetimes(900, -1, 2592000, 604800), "idTokenLifetime below_minimum -" },
        { Lifetimes(0, 3601, 0, int.MaxValue), "accessTokenLifetime below_minimum -; idTokenLifetime above_maximum 3600; refreshTokenAbsoluteLifetime below_minimum -; refreshTokenInactivityLifetime above_maximum 2592000" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task A_lifetime_outside_its_limits_is_400_application_invalid_naming_each_and_nothing_is_written(string body, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        var before = await RowAsync(host, app);

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("application_invalid", json.RootElement.GetProperty("code").GetString());
        Assert.Equal(["code", "traceId", "errors"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(expected, string.Join("; ", json.RootElement.GetProperty("errors").EnumerateArray().Select(e =>
        {
            Assert.Equal(JsonValueKind.Null, e.GetProperty("index").ValueKind);
            var maximum = e.TryGetProperty("maximum", out var m) ? m.GetInt32().ToString(System.Globalization.CultureInfo.InvariantCulture) : "-";
            return $"{e.GetProperty("field").GetString()} {e.GetProperty("reason").GetString()} {maximum}";
        })));

        Assert.Equal(before, await RowAsync(host, app));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_body_that_isnt_four_whole_lifetimes_is_400_application_invalid_with_no_errors()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        var before = await RowAsync(host, app);

        foreach (var (body, contentType) in new[]
        {
            ("""{"accessTokenLifetime":900,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000}""", "application/json"),
            ("""{"accessTokenLifetime":null,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""", "application/json"),
            ("""{"accessTokenLifetime":"900","idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""", "application/json"),
            ("""{"accessTokenLifetime":900.5,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""", "application/json"),
            ("""{"accessTokenLifetime":99999999999,"idTokenLifetime":900,"refreshTokenAbsoluteLifetime":2592000,"refreshTokenInactivityLifetime":604800}""", "application/json"),
            ("not json", "application/json"),
            (Lifetimes(300, 300, 300, 300), "text/plain"),
            ($$"""{"accessTokenLifetime":300,"idTokenLifetime":300,"refreshTokenAbsoluteLifetime":300,"refreshTokenInactivityLifetime":300,"pad":"{{new string('p', 4096)}}"}""", "application/json"),
        })
        {
            using var response = await SaveAsync(host, cookie, csrf, tenant, app, body, contentType: contentType);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("application_invalid", json.RootElement.GetProperty("code").GetString());
            Assert.False(json.RootElement.TryGetProperty("errors", out _));
        }

        Assert.Equal(before, await RowAsync(host, app));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_save_that_changes_nothing_is_200_with_no_event()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "spa");
        var xmin = await host.ScalarAsync<string>($"SELECT xmin::text FROM application WHERE id = '{IdOf(app)}'");

        // The defaults, as stored.
        using (var defaults = await SaveAsync(host, cookie, csrf, tenant, app, Lifetimes(900, 900, 2592000, 604800)))
        {
            AssertLifetimes(await ApplicationAsync(defaults), 900, 900, 2592000, 604800);
        }

        Assert.Equal(xmin, await host.ScalarAsync<string>($"SELECT xmin::text FROM application WHERE id = '{IdOf(app)}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));

        using (var first = await SaveAsync(host, cookie, csrf, tenant, app, Lifetimes(300, 300, 86400, 3600)))
        {
            await ApplicationAsync(first);
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
        xmin = await host.ScalarAsync<string>($"SELECT xmin::text FROM application WHERE id = '{IdOf(app)}'");

        using var again = await SaveAsync(host, cookie, csrf, tenant, app, Lifetimes(300, 300, 86400, 3600));

        AssertLifetimes(await ApplicationAsync(again), 300, 300, 86400, 3600);
        Assert.Equal(xmin, await host.ScalarAsync<string>($"SELECT xmin::text FROM application WHERE id = '{IdOf(app)}'"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_Viewer_is_403_audited_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (editor, editorCsrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, editor, editorCsrf, tenant, "web");
        var before = await RowAsync(host, app);
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Lifetimes(300, 300, 86400, 3600));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Equal(before, await RowAsync(host, app));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task The_system_another_Tenants_unknown_and_malformed_Application_are_the_same_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "dev");
        var b = await InsertAsync(host, "dev");
        var system = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{b}', '{system}', 'Account Portal', 'system', now())");
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var appOfA = await CreateAppAsync(host, ownerA, csrfA, a, "web");
        var (editorB, csrfB, _) = await RoleSessionAsync(host, b, "editor");

        foreach (var id in new[] { appOfA, PublicId.Format(PublicIdType.Application, system), PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()), "app_x", "nope" })
        {
            using var response = await SaveAsync(host, editorB, csrfB, b, id, Lifetimes(300, 300, 86400, 3600));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await CodeAsync(response));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{IdOf(appOfA)}' AND access_token_lifetime = 900"));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{system}' AND access_token_lifetime = 900"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Updated}'"));
    }

    [Fact]
    public async Task Another_Tenants_Admin_is_403_and_a_page_Tenant_that_isnt_the_path_is_409()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await InsertAsync(host, "dev");
        var b = await InsertAsync(host, "dev");
        var (ownerA, csrfA, _) = await RoleSessionAsync(host, a, "owner");
        var app = await CreateAppAsync(host, ownerA, csrfA, a, "web");
        var (ownerB, csrfB, _) = await RoleSessionAsync(host, b, "owner");

        using (var foreign = await SaveAsync(host, ownerB, csrfB, a, app, Lifetimes(300, 300, 86400, 3600)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(foreign));
        }

        foreach (var header in new[] { Id(b), NoHeader })
        {
            using var mismatch = await SaveAsync(host, ownerA, csrfA, a, app, Lifetimes(300, 300, 86400, 3600), header);
            Assert.Equal(HttpStatusCode.Conflict, mismatch.StatusCode);
            Assert.Equal("tenant_mismatch", await CodeAsync(mismatch));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Updated}'"));
    }

    [Fact]
    public async Task No_Session_is_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");

        using var response = await host.SendAsync(
            HttpMethod.Put,
            $"{AppPath(tenant, PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()))}/tokens",
            origin: AdminHost.Origin,
            body: Lifetimes(300, 300, 86400, 3600));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// Management decides again (AD-5): a machine principal of the path Tenant holds tenant.applications.manage and
    /// saves as itself; one of another Tenant, and an Admin with no grant there, are refused.
    /// </summary>
    [Fact]
    public async Task Management_lets_the_path_Tenants_machine_principal_save_and_refuses_the_others()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a, b));
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());
        var own = TestOnlyMachinePrincipal.For(a);
        var input = new ApplicationLifetimesInput(120, 900, 2592000, 604800);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            var context = scope.CreateCommandContext();
            var created = await applications.CreateAsync(context, own, null, a, "Worker", "machine", Cancellation);
            var id = created.Application!.Id;

            foreach (var principal in new Gatekeep.Modules.Admins.Contracts.Principal[]
            {
                TestOnlyMachinePrincipal.For(b),
                new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true),
            })
            {
                Assert.Equal(ApplicationLifetimesStatus.Forbidden, (await applications.UpdateLifetimesAsync(context, principal, null, a, id, input, Cancellation)).Status);
            }

            var saved = await applications.UpdateLifetimesAsync(context, own, null, a, id, input, Cancellation);
            Assert.Equal(ApplicationLifetimesStatus.Saved, saved.Status);
            Assert.Equal(120, saved.Application!.AccessTokenLifetime);
            await scope.CommitAsync(Cancellation);

            Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database),
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = '{Updated}' AND actor_kind = 'client' AND actor_id = '{own.ClientId}' AND target_id = '{id}'"));
        }

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application WHERE access_token_lifetime = 120"));
    }

    /// <summary>
    /// The table backs the limits (Story 3.4): even the superuser can't store a lifetime over its hard limit or under
    /// 1 second, and gk_admin may update the four lifetimes but never the system Application (GK012).
    /// </summary>
    [Fact]
    public async Task The_table_refuses_a_lifetime_outside_its_limits_even_to_the_superuser()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a));
        var app = Guid.CreateVersion7();
        var system = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"""
            INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{a}', '{app}', 'Web', 'web', now());
            INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{a}', '{system}', 'Account Portal', 'system', now());
            """);

        foreach (var set in new[]
        {
            "access_token_lifetime = 3601",
            "id_token_lifetime = 3601",
            "refresh_token_absolute_lifetime = 7776001",
            "refresh_token_inactivity_lifetime = 2592001",
            "access_token_lifetime = 0",
            "id_token_lifetime = 0",
            "refresh_token_absolute_lifetime = 0",
            "refresh_token_inactivity_lifetime = -1",
        })
        {
            var refused = await Assert.ThrowsAsync<PostgresException>(() =>
                PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"UPDATE application SET {set} WHERE id = '{app}'"));
            Assert.Equal(PostgresErrorCodes.CheckViolation, refused.SqlState);
        }

        // At each limit is allowed.
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"""
            UPDATE application SET access_token_lifetime = 3600, id_token_lifetime = 3600,
              refresh_token_absolute_lifetime = 7776000, refresh_token_inactivity_lifetime = 2592000 WHERE id = '{app}';
            UPDATE application SET access_token_lifetime = 1, id_token_lifetime = 1,
              refresh_token_absolute_lifetime = 1, refresh_token_inactivity_lifetime = 1 WHERE id = '{app}';
            """);

        // gk_admin updates the lifetimes in its Tenant's scope, and GK012 still guards the system Application.
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            await using var command = scope.CreateCommandContext().CreateCommand();
            command.CommandText = $"UPDATE application SET access_token_lifetime = 300 WHERE tenant_id = '{a}' AND id = '{app}'";
            Assert.Equal(1, await command.ExecuteNonQueryAsync(Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        await using (var scope = await TenantScope.BeginAsync(source, a, Cancellation))
        {
            await using var command = scope.CreateCommandContext().CreateCommand();
            command.CommandText = $"UPDATE application SET access_token_lifetime = 300 WHERE tenant_id = '{a}' AND id = '{system}'";
            var guarded = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
            Assert.Equal("GK012", guarded.SqlState);
        }
    }

    private static string Lifetimes(int access, int id, int absolute, int inactivity) =>
        JsonSerializer.Serialize(new
        {
            accessTokenLifetime = access,
            idTokenLifetime = id,
            refreshTokenAbsoluteLifetime = absolute,
            refreshTokenInactivityLifetime = inactivity,
        });

    private static void AssertLifetimes(JsonElement application, int access, int id, int absolute, int inactivity)
    {
        Assert.Equal(access, application.GetProperty("accessTokenLifetime").GetInt32());
        Assert.Equal(id, application.GetProperty("idTokenLifetime").GetInt32());
        Assert.Equal(absolute, application.GetProperty("refreshTokenAbsoluteLifetime").GetInt32());
        Assert.Equal(inactivity, application.GetProperty("refreshTokenInactivityLifetime").GetInt32());
    }

    private static string AppPath(Guid tenant, string app) => $"/api/v1/tenants/{Id(tenant)}/applications/{app}";

    private static Guid IdOf(string app) =>
        PublicId.TryParse(PublicIdType.Application, app, out var id) ? id : throw new ArgumentException("Not an app_ ID.", nameof(app));

    private static Task<HttpResponseMessage> SaveAsync(
        AdminHost host, string cookie, string csrf, Guid tenant, string app, string body, string? header = null, string contentType = "application/json") =>
        SetBodyAsync(host, cookie, csrf, $"{AppPath(tenant, app)}/tokens", body, header ?? Id(tenant), contentType);

    private static async Task<string> CreateAppAsync(AdminHost host, string cookie, string csrf, Guid tenant, string type)
    {
        using var response = await host.SendAsync(
            HttpMethod.Post,
            $"/api/v1/tenants/{Id(tenant)}/applications",
            cookie,
            csrf,
            AdminHost.Origin,
            JsonSerializer.Serialize(new { name = "App", type }),
            [(Header, Id(tenant))]);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("id").GetString()!;
    }

    private static Task<string> RowAsync(AdminHost host, string app) =>
        host.ScalarAsync<string>($"SELECT (to_jsonb(a) - 'name')::text FROM application a WHERE id = '{IdOf(app)}'");

    private static async Task<JsonElement> ApplicationAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.Clone();
    }
}
