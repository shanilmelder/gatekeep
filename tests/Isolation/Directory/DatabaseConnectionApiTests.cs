using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Tests.Isolation.Admins;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Connections;

/// <summary>
/// Story 4.6 (FR-17, FR-18, AD-5, AD-20) on the real Host.Admin and PostgreSQL: <c>GET /api/v1/tenants/{tenantId}/connections/database</c>
/// and its <c>settings</c> and <c>password-policy</c> saves. Any Tenant Role reads; Editors and Owners turn sign-up on or
/// off; only Owners save the password policy, whose minimum can't go below 12. Each save is one command with one
/// Tenant-targeted event, and only when a value changed. One test or more per row of the story's matrix; the creation,
/// backfill and purge rows are in the Operations, Keys, Directory and purge registry tests.
/// </summary>
public sealed class DatabaseConnectionApiTests(PostgresFixture postgres)
{
    private const string Updated = "directory.connection.updated";
    private const string PolicyUpdated = "directory.connection.password_policy_updated";

    private const string Policy = """{"minLength":16,"strength":"excellent","historyCount":3,"dictionary":false,"personalData":true}""";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Every_role_reads_the_default_Connection()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);

        foreach (var role in new[] { "viewer", "editor", "owner" })
        {
            var (cookie, _, _) = await RoleSessionAsync(host, tenant, role);
            using var response = await host.SendAsync(HttpMethod.Get, ConnectionPath(tenant), cookie);
            var json = await OkAsync(response);
            Assert.Equal(["kind", "name", "enabled", "signupEnabled", "passwordPolicy", "updatedAt"], json.EnumerateObject().Select(p => p.Name));
            Assert.Equal("database", json.GetProperty("kind").GetString());
            Assert.Equal("Username-Password", json.GetProperty("name").GetString());
            Assert.True(json.GetProperty("enabled").GetBoolean());
            Assert.True(json.GetProperty("signupEnabled").GetBoolean());
            Assert.Equal(
                """{"minLength":12,"strength":"good","historyCount":5,"dictionary":true,"personalData":true}""",
                json.GetProperty("passwordPolicy").GetRawText());
        }
    }

    [Fact]
    public async Task A_minimum_below_12_is_400_with_the_rule_text_and_nothing_is_saved()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await PutAsync(
            host, cookie, csrf, tenant, PolicyPath(tenant), """{"minLength":11,"strength":"good","historyCount":5,"dictionary":true,"personalData":true}""");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("connection_invalid", json.RootElement.GetProperty("code").GetString());
        var error = Assert.Single(json.RootElement.GetProperty("errors").EnumerateArray());
        Assert.Equal("minLength", error.GetProperty("field").GetString());
        Assert.Equal("below_minimum", error.GetProperty("reason").GetString());
        Assert.Equal("Minimum is 12 characters.", error.GetProperty("detail").GetString());

        Assert.Equal(12, await host.ScalarAsync<int>($"SELECT password_min_length FROM connection WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, PolicyUpdated));
    }

    public static TheoryData<string, string> BadPolicies => new()
    {
        { """{"minLength":65,"strength":"fair","historyCount":25,"dictionary":true,"personalData":true}""", "minLength above_maximum; strength invalid; historyCount above_maximum" },
        { """{"minLength":12,"strength":"good","historyCount":-1,"dictionary":true,"personalData":true}""", "historyCount below_minimum" },
        { """{"strength":"good","historyCount":5}""", "minLength required; dictionary required; personalData required" },
        { """{"minLength":12,"strength":"Good","historyCount":5,"dictionary":true,"personalData":true}""", "strength invalid" },
    };

    [Theory]
    [MemberData(nameof(BadPolicies))]
    public async Task A_policy_breaking_a_rule_is_400_naming_each_field(string body, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await PutAsync(host, cookie, csrf, tenant, PolicyPath(tenant), body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(expected, await ErrorsAsync(response));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, PolicyUpdated));
    }

    [Theory]
    [InlineData("""{"minLength":"twelve","strength":"good","historyCount":5,"dictionary":true,"personalData":true}""")]
    [InlineData("not json")]
    [InlineData("[]")]
    public async Task A_malformed_body_is_400_with_no_errors(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await PutAsync(host, cookie, csrf, tenant, PolicyPath(tenant), body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("connection_invalid", json.RootElement.GetProperty("code").GetString());
        Assert.False(json.RootElement.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task The_Owner_saves_the_policy_with_one_event_and_an_unchanged_save_writes_none()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, owner) = await RoleSessionAsync(host, tenant, "owner");

        using (var response = await PutAsync(host, cookie, csrf, tenant, PolicyPath(tenant), Policy))
        {
            var json = await OkAsync(response);
            Assert.Equal(Policy, json.GetProperty("passwordPolicy").GetRawText());
        }

        Assert.Equal(
            "16|excellent|3|False|True",
            await host.ScalarAsync<string>(
                $"SELECT password_min_length || '|' || password_strength || '|' || password_history_count || '|' || initcap(password_dictionary::text) || '|' || initcap(password_personal_data::text) FROM connection WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{PolicyUpdated}' AND actor_kind = 'admin' " +
            $"AND actor_id = '{owner}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_detail d JOIN audit_event e ON e.id = d.event_id WHERE e.tenant_id = '{tenant}' AND e.type_code = '{PolicyUpdated}'"));

        using (var again = await PutAsync(host, cookie, csrf, tenant, PolicyPath(tenant), Policy))
        {
            await OkAsync(again);
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, PolicyUpdated));
    }

    [Fact]
    public async Task An_Editor_toggles_sign_up_with_one_event_but_is_403_on_the_policy_which_they_still_read()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");

        using (var response = await PutAsync(host, cookie, csrf, tenant, SettingsPath(tenant), """{"signupEnabled":false}"""))
        {
            var json = await OkAsync(response);
            Assert.False(json.GetProperty("signupEnabled").GetBoolean());
        }

        Assert.False(await host.ScalarAsync<bool>($"SELECT signup_enabled FROM connection WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_id = '{editor}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));

        // The same value again: 200, and no event.
        using (var again = await PutAsync(host, cookie, csrf, tenant, SettingsPath(tenant), """{"signupEnabled":false}"""))
        {
            await OkAsync(again);
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));

        using (var policy = await PutAsync(host, cookie, csrf, tenant, PolicyPath(tenant), Policy))
        {
            Assert.Equal(HttpStatusCode.Forbidden, policy.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(policy));
        }

        using (var read = await host.SendAsync(HttpMethod.Get, ConnectionPath(tenant), cookie))
        {
            var json = await OkAsync(read);
            Assert.Equal(12, json.GetProperty("passwordPolicy").GetProperty("minLength").GetInt32());
        }

        Assert.Equal(0L, await TenantEventsAsync(host, tenant, PolicyUpdated));
    }

    [Fact]
    public async Task A_missing_sign_up_switch_is_400_naming_it()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PutAsync(host, cookie, csrf, tenant, SettingsPath(tenant), "{}");

        Assert.Equal("signupEnabled required", await ErrorsAsync(response));
        Assert.True(await host.ScalarAsync<bool>($"SELECT signup_enabled FROM connection WHERE tenant_id = '{tenant}'"));
    }

    [Fact]
    public async Task A_Viewer_reads_but_every_save_is_403_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host);
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using (var read = await host.SendAsync(HttpMethod.Get, ConnectionPath(tenant), cookie))
        {
            await OkAsync(read);
        }

        foreach (var (path, body) in new[] { (SettingsPath(tenant), """{"signupEnabled":false}"""), (PolicyPath(tenant), Policy) })
        {
            using var response = await PutAsync(host, cookie, csrf, tenant, path, body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.True(await host.ScalarAsync<bool>($"SELECT signup_enabled AND password_min_length = 12 FROM connection WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code LIKE 'directory.connection.%'"));
        Assert.Equal(2L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task An_Owner_of_another_Tenant_only_is_refused_and_this_Tenant_is_unchanged()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host);
        var b = await TenantAsync(host);
        var (cookie, csrf, _) = await RoleSessionAsync(host, b, "owner");

        foreach (var (path, body) in new[] { (SettingsPath(a), """{"signupEnabled":false}"""), (PolicyPath(a), Policy) })
        {
            using var response = await PutAsync(host, cookie, csrf, a, path, body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        using (var read = await host.SendAsync(HttpMethod.Get, ConnectionPath(a), cookie))
        {
            Assert.Equal(HttpStatusCode.Forbidden, read.StatusCode);
        }

        Assert.True(await host.ScalarAsync<bool>($"SELECT signup_enabled AND password_min_length = 12 AND password_strength = 'good' FROM connection WHERE tenant_id = '{a}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code LIKE 'directory.connection.%'"));
    }

    [Fact]
    public async Task A_Tenant_that_isnt_active_is_409_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, status: "creating");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        foreach (var (path, body) in new[] { (SettingsPath(tenant), """{"signupEnabled":false}"""), (PolicyPath(tenant), Policy) })
        {
            using var response = await PutAsync(host, cookie, csrf, tenant, path, body);
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal("tenant_not_active", await CodeAsync(response));
        }

        Assert.True(await host.ScalarAsync<bool>($"SELECT signup_enabled AND password_min_length = 12 FROM connection WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
    }

    [Fact]
    public async Task A_Tenant_with_no_Connection_is_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using (var read = await host.SendAsync(HttpMethod.Get, ConnectionPath(tenant), cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
            Assert.Equal("not_found", await CodeAsync(read));
        }

        using var save = await PutAsync(host, cookie, csrf, tenant, SettingsPath(tenant), """{"signupEnabled":false}""");
        Assert.Equal(HttpStatusCode.NotFound, save.StatusCode);
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
    }

    /// <summary>A Tenant with its database Connection, as the migration's backfill writes it.</summary>
    private static async Task<Guid> TenantAsync(AdminHost host, string status = "active")
    {
        var tenant = await InsertAsync(host, "dev", status);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SELECT set_config('gatekeep.tenant_id', '{tenant}', false); {Migration20261127000000ConfigureDatabaseConnection.BackfillConnection}");
        return tenant;
    }

    private static string ConnectionPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/connections/database";

    private static string SettingsPath(Guid tenant) => $"{ConnectionPath(tenant)}/settings";

    private static string PolicyPath(Guid tenant) => $"{ConnectionPath(tenant)}/password-policy";

    private static Task<HttpResponseMessage> PutAsync(AdminHost host, string cookie, string csrf, Guid tenant, string path, string body) =>
        SetBodyAsync(host, cookie, csrf, path, body, Id(tenant));

    private static async Task<JsonElement> OkAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.Clone();
    }

    /// <summary>The problem's errors as "field reason", joined by "; ", once its code is checked.</summary>
    private static async Task<string> ErrorsAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("connection_invalid", json.RootElement.GetProperty("code").GetString());
        return string.Join(
            "; ",
            json.RootElement.GetProperty("errors").EnumerateArray().Select(e => $"{e.GetProperty("field").GetString()} {e.GetProperty("reason").GetString()}"));
    }
}
