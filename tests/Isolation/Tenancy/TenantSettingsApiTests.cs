using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 4.6 (FR-10, AD-5, AD-20) on the real Host.Admin and PostgreSQL: <c>GET</c> and <c>PUT /api/v1/tenants/{tenantId}/settings</c>,
/// the terms URL, the default audience and the Dev-only email verification switch a sign-up reads. Any Tenant Role reads;
/// Editors and Owners save, each save one command with one Tenant-targeted event, and only when a value changed. The read
/// port Stories 4.7 and 4.9 use gives verification off only while the Tenant is Dev. One test or more per row of the
/// story's matrix.
/// </summary>
public sealed class TenantSettingsApiTests(PostgresFixture postgres)
{
    private const string Updated = "tenancy.tenant.settings_updated";

    private const string Audience = "https://api.example.com";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Every_role_reads_the_defaults_and_only_a_Dev_Tenant_offers_verification_off()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var dev = await TenantAsync(host, "dev");
        var staging = await TenantAsync(host, "staging");

        foreach (var role in new[] { "viewer", "editor", "owner" })
        {
            var (cookie, _, _) = await RoleSessionAsync(host, dev, role);
            using var response = await host.SendAsync(HttpMethod.Get, SettingsPath(dev), cookie);
            Assert.Equal(
                """{"termsUrl":null,"emailVerificationOff":false,"emailVerificationOffAvailable":true,"defaultAudience":null}""",
                (await OkAsync(response)).GetRawText());
        }

        var (viewer, _, _) = await RoleSessionAsync(host, staging, "viewer");
        using var read = await host.SendAsync(HttpMethod.Get, SettingsPath(staging), viewer);
        Assert.False((await OkAsync(read)).GetProperty("emailVerificationOffAvailable").GetBoolean());
    }

    [Fact]
    public async Task An_Editor_saves_all_three_with_one_event_and_the_read_port_returns_them()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, editor) = await RoleSessionAsync(host, tenant, "editor");
        var body = Body("https://example.com/terms", true, Audience);

        using (var response = await PutAsync(host, cookie, csrf, tenant, body))
        {
            Assert.Equal(
                $$"""{"termsUrl":"https://example.com/terms","emailVerificationOff":true,"emailVerificationOffAvailable":true,"defaultAudience":"{{Audience}}"}""",
                (await OkAsync(response)).GetRawText());
        }

        Assert.Equal(
            $"https://example.com/terms|true|{Audience}",
            await host.ScalarAsync<string>($"SELECT terms_url || '|' || email_verification_off || '|' || default_audience FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Updated}' AND actor_kind = 'admin' " +
            $"AND actor_id = '{editor}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_detail d JOIN audit_event e ON e.id = d.event_id WHERE e.tenant_id = '{tenant}' AND e.type_code = '{Updated}'"));

        Assert.Equal(new TenantSignupSettings("https://example.com/terms", true, Audience), await SignupSettingsAsync(host, tenant));

        // The same values again: 200, and no event.
        using (var again = await PutAsync(host, cookie, csrf, tenant, body))
        {
            await OkAsync(again);
        }

        Assert.Equal(1L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task Verification_off_in_a_Tenant_that_isnt_Dev_is_400_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "staging");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await PutAsync(host, cookie, csrf, tenant, Body(null, true, null));

        Assert.Equal("emailVerificationOff dev_only", await ErrorsAsync(response));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.False(await host.ScalarAsync<bool>($"SELECT coalesce((SELECT email_verification_off FROM tenant_settings WHERE tenant_id = '{tenant}'), false)"));
    }

    [Fact]
    public async Task Verification_off_counts_only_while_the_Tenant_is_Dev()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using (var response = await PutAsync(host, cookie, csrf, tenant, Body(null, true, null)))
        {
            Assert.True((await OkAsync(response)).GetProperty("emailVerificationOff").GetBoolean());
        }

        Assert.True((await SignupSettingsAsync(host, tenant)).EmailVerificationOff);

        await PostgresFixture.ExecuteAsync(host.Superuser, $"SET session_replication_role = replica; UPDATE tenant SET label = 'prod' WHERE id = '{tenant}'; SET session_replication_role = DEFAULT");

        Assert.False((await SignupSettingsAsync(host, tenant)).EmailVerificationOff);
        using (var read = await host.SendAsync(HttpMethod.Get, SettingsPath(tenant), cookie))
        {
            var json = await OkAsync(read);
            Assert.False(json.GetProperty("emailVerificationOff").GetBoolean());
            Assert.False(json.GetProperty("emailVerificationOffAvailable").GetBoolean());
        }

        // Saving it on again is refused now.
        using var refused = await PutAsync(host, cookie, csrf, tenant, Body(null, true, null));
        Assert.Equal("emailVerificationOff dev_only", await ErrorsAsync(refused));
    }

    public static TheoryData<string, string> BadAudiences => new()
    {
        { "urn:gatekeep:management", "defaultAudience built_in" },
        { "https://unknown.example.com", "defaultAudience not_found" },
        { "https://API.example.com", "defaultAudience not_found" },
        { "has space", "defaultAudience invalid" },
        { "", "defaultAudience invalid" },
        { new string('a', 256), "defaultAudience too_long" },
    };

    [Theory]
    [MemberData(nameof(BadAudiences))]
    public async Task A_default_audience_that_isnt_one_of_the_Tenants_own_APIs_is_400(string audience, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PutAsync(host, cookie, csrf, tenant, Body(null, false, audience));

        Assert.Equal(expected, await ErrorsAsync(response));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    /// <summary>A stored audience whose API has since gone is kept as it is, and never blocks saving the other settings.</summary>
    [Fact]
    public async Task A_stored_audience_whose_API_is_gone_doesnt_block_a_save_and_is_kept()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        using (var first = await PutAsync(host, cookie, csrf, tenant, Body(null, false, Audience)))
        {
            await OkAsync(first);
        }

        await PostgresFixture.ExecuteAsync(host.Superuser, $"DELETE FROM api WHERE tenant_id = '{tenant}' AND identifier = '{Audience}'");

        using (var response = await PutAsync(host, cookie, csrf, tenant, Body("https://example.com/terms", false, Audience)))
        {
            var json = await OkAsync(response);
            Assert.Equal("https://example.com/terms", json.GetProperty("termsUrl").GetString());
            Assert.Equal(Audience, json.GetProperty("defaultAudience").GetString());
        }

        Assert.Equal(
            $"https://example.com/terms|{Audience}",
            await host.ScalarAsync<string>($"SELECT terms_url || '|' || default_audience FROM tenant_settings WHERE tenant_id = '{tenant}'"));

        // Choosing it anew is still checked.
        using (var cleared = await PutAsync(host, cookie, csrf, tenant, Body(null, false, null)))
        {
            await OkAsync(cleared);
        }

        using var again = await PutAsync(host, cookie, csrf, tenant, Body(null, false, Audience));
        Assert.Equal("defaultAudience not_found", await ErrorsAsync(again));
    }

    [Fact]
    public async Task Another_Tenants_API_isnt_a_default_audience()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host, "dev");
        var b = await InsertAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, b, "editor");

        // Only Tenant A has the API.
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM api WHERE identifier = '{Audience}' AND tenant_id = '{a}'"));
        using var response = await PutAsync(host, cookie, csrf, b, Body(null, false, Audience));

        Assert.Equal("defaultAudience not_found", await ErrorsAsync(response));
    }

    public static TheoryData<string, string> BadTermsUrls => new()
    {
        { "http://example.com/terms", "termsUrl invalid" },
        { "https://user:pass@example.com/terms", "termsUrl invalid" },
        { "https://user@example.com/terms", "termsUrl invalid" },
        { "example.com/terms", "termsUrl invalid" },
        { "https://example.com/ terms", "termsUrl invalid" },
        { "", "termsUrl invalid" },
        { "https://example.com/" + new string('a', 2030), "termsUrl too_long" },
    };

    [Theory]
    [MemberData(nameof(BadTermsUrls))]
    public async Task A_terms_URL_that_isnt_https_without_userinfo_is_400(string url, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PutAsync(host, cookie, csrf, tenant, Body(url, false, null));

        Assert.Equal(expected, await ErrorsAsync(response));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
    }

    [Fact]
    public async Task A_terms_URL_at_the_limit_saves()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        var url = "https://example.com/" + new string('a', 2048 - "https://example.com/".Length);

        using var response = await PutAsync(host, cookie, csrf, tenant, Body(url, false, null));

        Assert.Equal(url, (await OkAsync(response)).GetProperty("termsUrl").GetString());
    }

    [Fact]
    public async Task Null_clears_the_terms_URL_and_the_default_audience()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");
        using (var first = await PutAsync(host, cookie, csrf, tenant, Body("https://example.com/terms", false, Audience)))
        {
            await OkAsync(first);
        }

        using (var cleared = await PutAsync(host, cookie, csrf, tenant, Body(null, false, null)))
        {
            Assert.Equal(
                """{"termsUrl":null,"emailVerificationOff":false,"emailVerificationOffAvailable":true,"defaultAudience":null}""",
                (await OkAsync(cleared)).GetRawText());
        }

        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}' AND terms_url IS NULL AND default_audience IS NULL"));
        Assert.Equal(2L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(new TenantSignupSettings(null, false, null), await SignupSettingsAsync(host, tenant));
    }

    [Theory]
    [InlineData("""{"termsUrl":null,"defaultAudience":null}""", "emailVerificationOff required")]
    public async Task A_missing_verification_switch_is_400_naming_it(string body, string expected)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PutAsync(host, cookie, csrf, tenant, body);

        Assert.Equal(expected, await ErrorsAsync(response));
    }

    [Theory]
    [InlineData("""{"termsUrl":1,"emailVerificationOff":false,"defaultAudience":null}""")]
    [InlineData("not json")]
    public async Task A_malformed_body_is_400_with_no_errors(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "editor");

        using var response = await PutAsync(host, cookie, csrf, tenant, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("tenant_settings_invalid", json.RootElement.GetProperty("code").GetString());
        Assert.False(json.RootElement.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task A_Viewer_reads_but_a_save_is_403_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await TenantAsync(host, "dev");
        var (cookie, csrf, viewer) = await RoleSessionAsync(host, tenant, "viewer");

        using var response = await PutAsync(host, cookie, csrf, tenant, Body("https://example.com/terms", false, null));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.access.denied' AND actor_id = '{viewer}' AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task An_Owner_of_another_Tenant_only_is_refused_and_this_Tenant_is_unchanged()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await TenantAsync(host, "dev");
        var b = await TenantAsync(host, "dev");
        var (cookie, csrf, _) = await RoleSessionAsync(host, b, "owner");

        using (var response = await PutAsync(host, cookie, csrf, a, Body("https://example.com/terms", true, null)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        using (var read = await host.SendAsync(HttpMethod.Get, SettingsPath(a), cookie))
        {
            Assert.Equal(HttpStatusCode.Forbidden, read.StatusCode);
        }

        Assert.Equal(new TenantSignupSettings(null, false, null), await SignupSettingsAsync(host, a));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Updated}'"));
    }

    [Fact]
    public async Task A_Tenant_that_isnt_active_is_409_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host, "dev", status: "creating");
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await PutAsync(host, cookie, csrf, tenant, Body("https://example.com/terms", false, null));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_not_active", await CodeAsync(response));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
    }

    /// <summary>A Tenant with <paramref name="label"/>, its built-in Management API and one API of its own, <see cref="Audience"/>.</summary>
    private static async Task<Guid> TenantAsync(AdminHost host, string label)
    {
        var tenant = await InsertAsync(host, label);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"SELECT set_config('gatekeep.tenant_id', '{tenant}', false); {Migration20261119000000DefineApis.BackfillApi}; " +
            $"INSERT INTO api (tenant_id, id, name, identifier, created_at) VALUES ('{tenant}', gen_random_uuid(), 'Billing', '{Audience}', now())");
        return tenant;
    }

    /// <summary>The read port, as Host.Hosted reads it.</summary>
    private async Task<TenantSignupSettings> SignupSettingsAsync(AdminHost host, Guid tenant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, host.Database));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var settings = await TenancyContract.CreateTenants(AuditContract.CreateAppender())
            .GetSignupSettingsAsync(scope.CreateCommandContext(), tenant, Cancellation);
        await scope.CommitAsync(Cancellation);
        return Assert.IsType<TenantSignupSettings>(settings);
    }

    private static string SettingsPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/settings";

    private static string Body(string? termsUrl, bool emailVerificationOff, string? defaultAudience) =>
        JsonSerializer.Serialize(new { termsUrl, emailVerificationOff, defaultAudience });

    private static Task<HttpResponseMessage> PutAsync(AdminHost host, string cookie, string csrf, Guid tenant, string body) =>
        SetBodyAsync(host, cookie, csrf, SettingsPath(tenant), body, Id(tenant));

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
        Assert.Equal("tenant_settings_invalid", json.RootElement.GetProperty("code").GetString());
        return string.Join(
            "; ",
            json.RootElement.GetProperty("errors").EnumerateArray().Select(e => $"{e.GetProperty("field").GetString()} {e.GetProperty("reason").GetString()}"));
    }
}
