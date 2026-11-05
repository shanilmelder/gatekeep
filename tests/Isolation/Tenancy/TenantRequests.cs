using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Tests.Isolation.Admins;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.28's requests on the real Host.Admin: the label read and change, the Tenant-surface
/// fresh-assertion begin and the switcher's list. A state-changing one carries
/// <c>X-Gatekeep-Tenant</c> equal to its path Tenant unless the test says otherwise.
/// </summary>
internal static class TenantRequests
{
    public const string Header = "X-Gatekeep-Tenant";

    public const string MyTenantsPath = "/api/v1/deployment/my-tenants";

    /// <summary>The value meaning "send no header".</summary>
    public const string NoHeader = "\0none";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static string Id(Guid tenant) => PublicId.Format(PublicIdType.Tenant, tenant);

    public static string LabelPath(Guid tenant) => LabelPath(Id(tenant));

    public static string LabelPath(string tenant) => $"/api/v1/tenants/{tenant}/label";

    public static string AssertionsPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/assertions";

    /// <summary>A new active Tenant with <paramref name="label"/>, as the superuser, and its host. Returns its ID.</summary>
    public static async Task<Guid> InsertAsync(AdminHost host, string label = "dev", string status = "active", string name = "Test Tenant")
    {
        var id = Guid.CreateVersion7();
        await TestTenants.InsertAsync(host.Superuser, id, TestTenants.Host(id), status, label, name);
        return id;
    }

    /// <summary>PUTs <paramref name="label"/> to the Tenant's label, with the page Tenant header as given (the path's by default).</summary>
    public static Task<HttpResponseMessage> SetLabelAsync(AdminHost host, string cookie, string csrf, Guid tenant, string label, string? header = null) =>
        SetBodyAsync(host, cookie, csrf, LabelPath(tenant), JsonSerializer.Serialize(new { label }), header ?? Id(tenant));

    public static Task<HttpResponseMessage> SetBodyAsync(
        AdminHost host,
        string cookie,
        string csrf,
        string path,
        string body,
        string header,
        string contentType = "application/json") =>
        host.SendAsync(HttpMethod.Put, path, cookie, csrf, AdminHost.Origin, body, Headers(header), contentType);

    public static Task<HttpResponseMessage> GetLabelAsync(AdminHost host, string cookie, Guid tenant) =>
        host.SendAsync(HttpMethod.Get, LabelPath(tenant), cookie);

    /// <summary>Begins a fresh assertion on the Tenant surface. Returns the options when it was a 200.</summary>
    public static async Task<(HttpResponseMessage Response, JsonElement Options)> BeginAsync(
        AdminHost host,
        string cookie,
        string csrf,
        Guid tenant,
        string body,
        string? header = null,
        string contentType = "application/json")
    {
        var response = await host.SendAsync(HttpMethod.Post, AssertionsPath(tenant), cookie, csrf, AdminHost.Origin, body, Headers(header ?? Id(tenant)), contentType);
        var options = response.StatusCode == HttpStatusCode.OK
            ? JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone()
            : default;
        return (response, options);
    }

    /// <summary>Confirms <c>tenant.label.manage</c> in the Tenant: the Tenant begin, the sheet and the Deployment complete, which must pass.</summary>
    public static async Task ConfirmAsync(AdminHost host, string cookie, string csrf, SoftwareAuthenticator authenticator, Guid tenant)
    {
        var (begin, options) = await BeginAsync(host, cookie, csrf, tenant, """{"action":"tenant.label.manage","target":null}""");
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        using var complete = await host.CompleteAssertionAsync(cookie, csrf, authenticator.Assert(options, AdminHost.Origin));
        Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
    }

    /// <summary>The Owner with two credentials, a full Session, and the Owner role in each of <paramref name="tenants"/>.</summary>
    public static async Task<(string Cookie, string Csrf, Guid AdminId, SoftwareAuthenticator[] Authenticators)> OwnerOfAsync(AdminHost host, params Guid[] tenants)
    {
        var owner = await host.OwnerWithCredentialsAsync();
        foreach (var tenant in tenants)
        {
            await host.GrantTenantRoleAsync(tenant, owner.AdminId, "owner");
        }

        return owner;
    }

    /// <summary>A full Session of a seeded Admin who isn't the Owner, with <paramref name="role"/> in <paramref name="tenant"/>.</summary>
    public static async Task<(string Cookie, string Csrf, Guid AdminId)> RoleSessionAsync(AdminHost host, Guid tenant, string role)
    {
        var (cookie, csrf, session) = await host.InsertFullSessionAsync();
        var admin = await host.AdminOfSessionAsync(session);
        await host.GrantTenantRoleAsync(tenant, admin, role);
        return (cookie, csrf, admin);
    }

    public static async Task<string> CodeAsync(HttpResponseMessage response)
    {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("code").GetString()!;
    }

    public static async Task<string> LabelOfAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return json.RootElement.GetProperty("label").GetString()!;
    }

    public static Task<string> StoredLabelAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<string>($"SELECT label FROM tenant WHERE id = '{tenant}'");

    /// <summary>Events of <paramref name="code"/> on the Tenant's own chain.</summary>
    public static Task<long> TenantEventsAsync(AdminHost host, Guid tenant, string code) =>
        host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{code}'");

    public static Task<long> GrantsAsync(AdminHost host) =>
        host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'");

    private static IEnumerable<(string, string)> Headers(string? header) =>
        header is null or NoHeader ? [] : [(Header, header)];
}
