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
/// Story 3.2 (FR-11, FR-13, FR-46, UX-DR42, AD-20) on the real Host.Admin and PostgreSQL:
/// <c>PUT /api/v1/tenants/{tenantId}/applications/{applicationId}/settings</c>. Editors and Owners save an
/// Application's full settings by the type table, every refused line named; a Prod Tenant's changed
/// callbacks need a fresh assertion bound to the Application, and a new custom-scheme URL there an
/// acknowledgement; a save writes <c>directory.application.updated</c>, a Prod callback added
/// <c>directory.application.prod_callback_added</c>, and a no-op nothing. One test or more per API row of
/// the story's I/O matrix; the protocol rows are <see cref="ApplicationSettingsProtocolTests"/>.
/// </summary>
public sealed class ApplicationSettingsApiTests(PostgresFixture postgres)
{
    private const string Updated = "directory.application.updated";

    private const string ProdCallbackAdded = "directory.application.prod_callback_added";

    private const string Action = "tenant.application_callbacks.manage";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_Editor_saves_web_URLs_and_grants_in_Dev_with_one_event_and_no_assertion()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, admin) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings(
            ["https://app.example/cb", "http://127.0.0.1:8080/cb"], ["https://app.example/"], ["https://app.example"], ["refresh_token", "authorization_code"]));

        var saved = await ApplicationAsync(response);
        Assert.Equal(app, saved.GetProperty("id").GetString());
        Assert.Equal(["https://app.example/cb", "http://127.0.0.1:8080/cb"], Strings(saved, "callbackUrls"));
        Assert.Equal(["https://app.example/"], Strings(saved, "logoutUrls"));
        Assert.Equal(["https://app.example"], Strings(saved, "webOrigins"));
        Assert.Equal(["authorization_code", "refresh_token"], Strings(saved, "grantTypes"));

        var id = IdOf(app);
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM application WHERE id = '{id}' AND redirect_uris = ARRAY['https://app.example/cb', 'http://127.0.0.1:8080/cb'] AND post_logout_redirect_uris = ARRAY['https://app.example/'] AND web_origins = ARRAY['https://app.example'] AND grant_types = ARRAY['authorization_code', 'refresh_token']"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_kind = 'admin' AND actor_id = '{admin}' AND target_kind = 'client' AND target_id = '{id}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, ProdCallbackAdded));

        // The read answers the same settings.
        using var read = await host.SendAsync(HttpMethod.Get, AppPath(tenant, app), cookie);
        Assert.Equal(saved.GetRawText(), (await ApplicationAsync(read)).GetRawText());
    }

    [Fact]
    public async Task A_Prod_callback_change_with_no_grant_is_403_and_writes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "spa");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://app.example/cb"], [], [], ["authorization_code"]));

        await FreshAssertionTests.AssertProblemAsync(response, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{IdOf(app)}' AND redirect_uris <> '{{}}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_Prod_callback_change_with_a_grant_for_the_Application_saves_writes_both_events_and_uses_the_grant_once()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant);
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "spa");
        var other = await CreateAppAsync(host, cookie, csrf, tenant, "spa");

        // A grant bound to another Application never serves this one.
        await ConfirmAppAsync(host, cookie, csrf, authenticators[0], tenant, other);
        using (var wrongTarget = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://app.example/cb"], [], [], ["authorization_code"])))
        {
            await FreshAssertionTests.AssertProblemAsync(wrongTarget, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        await ConfirmAppAsync(host, cookie, csrf, authenticators[0], tenant, app);
        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://app.example/cb"], [], [], ["authorization_code"]));

        Assert.Equal(["https://app.example/cb"], Strings(await ApplicationAsync(response), "callbackUrls"));
        foreach (var code in new[] { Updated, ProdCallbackAdded })
        {
            Assert.Equal(1L, await host.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{code}' AND actor_kind = 'admin' AND actor_id = '{owner}' AND target_id = '{IdOf(app)}'"));
        }

        Assert.Equal(1L, await GrantsAsync(host));

        // Used up: the next callback change asks again.
        using var again = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://app.example/cb", "https://app.example/two"], [], [], ["authorization_code"]));
        await FreshAssertionTests.AssertProblemAsync(again, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_Prod_save_that_keeps_the_callbacks_needs_no_assertion_and_adds_no_Prod_event()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");

        // The grants and the logout URLs change; the callbacks, none, stay none.
        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings([], ["https://app.example/"], [], []));

        Assert.Empty(Strings(await ApplicationAsync(response), "grantTypes"));
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, ProdCallbackAdded));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_Prod_callback_removed_or_reordered_needs_an_assertion_only_when_the_set_changes()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        await ConfirmAppAsync(host, cookie, csrf, authenticators[0], tenant, app);
        using (var first = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://a.example/cb", "https://b.example/cb"], [], [], ["authorization_code"])))
        {
            await ApplicationAsync(first);
        }

        // The same set in another order: no assertion, and no callback was added.
        using (var reordered = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://b.example/cb", "https://a.example/cb"], [], [], ["authorization_code"])))
        {
            Assert.Equal(["https://b.example/cb", "https://a.example/cb"], Strings(await ApplicationAsync(reordered), "callbackUrls"));
        }

        // A removal changes the set: it needs one.
        using var removed = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://a.example/cb"], [], [], ["authorization_code"]));
        await FreshAssertionTests.AssertProblemAsync(removed, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal(1L, await TenantEventsAsync(host, tenant, ProdCallbackAdded));
        Assert.Equal(2L, await TenantEventsAsync(host, tenant, Updated));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_Viewer_is_403_audited_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (editor, editorCsrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, editor, editorCsrf, tenant, "web");
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["https://app.example/cb"], [], [], ["authorization_code"]));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    public static TheoryData<string, string, string> Refusals => new()
    {
        // type, body, then each expected error as "field index reason", joined by "; ".
        { "web", Settings(["https://*.a.example/cb", "/cb", "http://a.example/cb", "https://a.example/cb#x"], [], [], []), "callbackUrls 0 wildcard; callbackUrls 1 not_absolute; callbackUrls 2 scheme_not_allowed; callbackUrls 3 not_absolute" },
        { "spa", Settings([.. Enumerable.Range(0, 11).Select(i => $"https://a.example/{i}")], [], [], []), "callbackUrls - too_many" },
        { "spa", Settings([], ["https://a.example/", "https://a.example/"], [], []), "logoutUrls 1 duplicate" },
        { "spa", Settings(["https://a.example/" + new string('x', 1983)], [], [], []), "callbackUrls 0 too_long" },
        { "machine", Settings([], [], [], ["authorization_code"]), "grantTypes - not_allowed_for_type" },
        { "web", Settings([], [], [], ["client_credentials"]), "grantTypes - not_allowed_for_type" },
        { "spa", Settings([], [], [], ["refresh_token"]), "grantTypes - not_allowed_for_type" },
        { "machine", Settings(["https://a.example/cb"], [], [], ["client_credentials"]), "callbackUrls - not_allowed_for_type" },
        { "native", Settings([], [], ["https://a.example"], []), "webOrigins - not_allowed_for_type" },
        { "web", Settings(["com.example.app:/cb"], [], [], []), "callbackUrls 0 scheme_not_allowed" },
        { "spa", Settings([], ["com.example.app:/logout"], [], []), "logoutUrls 0 scheme_not_allowed" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task A_rule_broken_is_400_application_invalid_naming_each_line_and_nothing_is_written(string type, string body, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, type);
        var before = await RowAsync(host, app);

        using var response = await SaveBodyAsync(host, cookie, csrf, tenant, app, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("application_invalid", json.RootElement.GetProperty("code").GetString());
        Assert.Equal(["code", "traceId", "errors"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(expected, string.Join("; ", json.RootElement.GetProperty("errors").EnumerateArray().Select(e =>
        {
            Assert.Equal(["field", "index", "reason"], e.EnumerateObject().Select(p => p.Name));
            var index = e.GetProperty("index");
            return $"{e.GetProperty("field").GetString()} {(index.ValueKind == JsonValueKind.Null ? "-" : index.GetInt32().ToString(System.Globalization.CultureInfo.InvariantCulture))} {e.GetProperty("reason").GetString()}";
        })));

        // The refusal names lines, never their values.
        Assert.DoesNotContain("a.example", json.RootElement.GetRawText(), StringComparison.Ordinal);
        Assert.Equal(before, await RowAsync(host, app));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_body_that_isnt_the_full_settings_is_400_application_invalid_with_no_errors()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");

        foreach (var (body, contentType) in new[]
        {
            ("""{"callbackUrls":[],"logoutUrls":[],"webOrigins":[]}""", "application/json"),
            ("""{"callbackUrls":null,"logoutUrls":[],"webOrigins":[],"grantTypes":[]}""", "application/json"),
            ("""{"callbackUrls":[null],"logoutUrls":[],"webOrigins":[],"grantTypes":[]}""", "application/json"),
            ("""{"callbackUrls":"https://a.example/cb","logoutUrls":[],"webOrigins":[],"grantTypes":[]}""", "application/json"),
            ("not json", "application/json"),
            (Settings([], [], [], []), "text/plain"),
            ($$"""{"callbackUrls":[],"logoutUrls":[],"webOrigins":[],"grantTypes":[],"pad":"{{new string('p', 16384)}}"}""", "application/json"),
        })
        {
            using var response = await SaveBodyAsync(host, cookie, csrf, tenant, app, body, contentType: contentType);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("application_invalid", json.RootElement.GetProperty("code").GetString());
            Assert.False(json.RootElement.TryGetProperty("errors", out _));
        }

        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_native_custom_scheme_saves_in_Dev_with_no_acknowledgement()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "native");

        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["com.example.app:/cb", "http://127.0.0.1/cb"], [], [], ["authorization_code"]));

        Assert.Equal(["com.example.app:/cb", "http://127.0.0.1/cb"], Strings(await ApplicationAsync(response), "callbackUrls"));
    }

    [Fact]
    public async Task A_new_Prod_custom_scheme_needs_the_acknowledgement_which_isnt_stored()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "native");
        await ConfirmAppAsync(host, cookie, csrf, authenticators[0], tenant, app);

        // Refused before the gate: the grant is still there for the save that follows.
        using (var refused = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["com.example.app:/cb"], [], [], ["authorization_code"])))
        {
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Equal("custom_scheme_acknowledgement_required", await CodeAsync(refused));
        }

        Assert.Equal(1L, await GrantsAsync(host));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));

        using var acknowledged = await SaveAsync(
            host, cookie, csrf, tenant, app, Settings(["com.example.app:/cb"], [], [], ["authorization_code"], acknowledge: true));
        Assert.Equal(["com.example.app:/cb"], Strings(await ApplicationAsync(acknowledged), "callbackUrls"));
        Assert.Equal(0L, await GrantsAsync(host));

        // Stored already, it needs no acknowledgement again: here a logout URL change only.
        using var kept = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["com.example.app:/cb"], ["https://app.example/"], [], ["authorization_code"]));
        Assert.Equal(["https://app.example/"], Strings(await ApplicationAsync(kept), "logoutUrls"));

        // A new custom-scheme logout URL needs one too.
        using var logout = await SaveAsync(host, cookie, csrf, tenant, app, Settings(["com.example.app:/cb"], ["com.example.app:/bye"], [], ["authorization_code"]));
        Assert.Equal(HttpStatusCode.BadRequest, logout.StatusCode);
        Assert.Equal("custom_scheme_acknowledgement_required", await CodeAsync(logout));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_save_that_changes_nothing_is_200_with_no_event()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "prod");
        var (cookie, csrf, _, authenticators) = await OwnerOfAsync(host, tenant);
        var app = await CreateAppAsync(host, cookie, csrf, tenant, "web");
        var xmin = await host.ScalarAsync<string>($"SELECT xmin::text FROM application WHERE id = '{IdOf(app)}'");

        // As created: no URL and {authorization_code}, sent in any order.
        using var response = await SaveAsync(host, cookie, csrf, tenant, app, Settings([], [], [], ["authorization_code"]));

        Assert.Equal(["authorization_code"], Strings(await ApplicationAsync(response), "grantTypes"));
        Assert.Equal(xmin, await host.ScalarAsync<string>($"SELECT xmin::text FROM application WHERE id = '{IdOf(app)}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.All(authenticators, a => a.Dispose());
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
            using var response = await SaveAsync(host, editorB, csrfB, b, id, Settings([], [], [], []));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await CodeAsync(response));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM application WHERE id = '{IdOf(appOfA)}' AND grant_types = ARRAY['authorization_code']"));
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

        using (var foreign = await SaveAsync(host, ownerB, csrfB, a, app, Settings(["https://app.example/cb"], [], [], ["authorization_code"])))
        {
            Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(foreign));
        }

        foreach (var header in new[] { Id(b), NoHeader })
        {
            using var mismatch = await SaveBodyAsync(host, ownerA, csrfA, a, app, Settings(["https://app.example/cb"], [], [], ["authorization_code"]), header);
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
            HttpMethod.Put, $"{AppPath(tenant, PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()))}/settings", origin: AdminHost.Origin, body: Settings([], [], [], []));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>Management decides again (AD-5): the capability is machine-denied, so no machine principal saves, in any Tenant.</summary>
    [Fact]
    public async Task Management_refuses_every_machine_principal_and_an_Admin_with_no_grant()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(a, b));
        var applications = ManagementContract.CreateApplications(AuditContract.CreateAppender());
        var input = new ApplicationSettingsInput(["https://app.example/cb"], [], [], ["authorization_code"], AcknowledgeCustomScheme: false);
        var asked = false;
        Task<bool> Gate(CancellationToken _)
        {
            asked = true;
            return Task.FromResult(true);
        }

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
        var context = scope.CreateCommandContext();
        var created = await applications.CreateAsync(context, TestOnlyMachinePrincipal.For(a), null, a, "Web", "web", Cancellation);
        var id = created.Application!.Id;

        foreach (var principal in new Gatekeep.Modules.Admins.Contracts.Principal[]
        {
            TestOnlyMachinePrincipal.For(a),
            TestOnlyMachinePrincipal.For(b),
            new Gatekeep.Modules.Admins.Contracts.AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true),
        })
        {
            var result = await applications.UpdateSettingsAsync(context, principal, null, a, id, input, Gate, Cancellation);
            Assert.Equal(ApplicationSettingsStatus.Forbidden, result.Status);
        }

        Assert.False(asked);
        await scope.CommitAsync(Cancellation);
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM application WHERE redirect_uris <> '{}'"));
    }

    private static string Settings(string[] callbacks, string[] logouts, string[] origins, string[] grants, bool? acknowledge = null) =>
        acknowledge is null
            ? JsonSerializer.Serialize(new { callbackUrls = callbacks, logoutUrls = logouts, webOrigins = origins, grantTypes = grants })
            : JsonSerializer.Serialize(new { callbackUrls = callbacks, logoutUrls = logouts, webOrigins = origins, grantTypes = grants, acknowledgeCustomScheme = acknowledge });

    private static string AppPath(Guid tenant, string app) => $"/api/v1/tenants/{Id(tenant)}/applications/{app}";

    private static Guid IdOf(string app) =>
        PublicId.TryParse(PublicIdType.Application, app, out var id) ? id : throw new ArgumentException("Not an app_ ID.", nameof(app));

    private static Task<HttpResponseMessage> SaveAsync(AdminHost host, string cookie, string csrf, Guid tenant, string app, string body) =>
        SaveBodyAsync(host, cookie, csrf, tenant, app, body);

    private static Task<HttpResponseMessage> SaveBodyAsync(
        AdminHost host, string cookie, string csrf, Guid tenant, string app, string body, string? header = null, string contentType = "application/json") =>
        SetBodyAsync(host, cookie, csrf, $"{AppPath(tenant, app)}/settings", body, header ?? Id(tenant), contentType);

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

    /// <summary>Confirms tenant.application_callbacks.manage in the Tenant, bound to <paramref name="app"/>: the Tenant begin, the sheet and the complete.</summary>
    private static async Task ConfirmAppAsync(AdminHost host, string cookie, string csrf, SoftwareAuthenticator authenticator, Guid tenant, string app)
    {
        var (begin, options) = await BeginAsync(host, cookie, csrf, tenant, JsonSerializer.Serialize(new { action = Action, target = app }));
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        using var complete = await host.CompleteAssertionAsync(cookie, csrf, authenticator.Assert(options, AdminHost.Origin));
        Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
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

    private static string[] Strings(JsonElement application, string property) =>
        [.. application.GetProperty(property).EnumerateArray().Select(e => e.GetString()!)];
}
