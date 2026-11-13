using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Admins;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 9.1 (FR-37, UX-DR44, AD-5, AD-19, AD-33) on the real Host.Admin and PostgreSQL, with the
/// OpenBao stand-in answering each Signing Key's public half: <c>GET /api/v1/tenants/{tenantId}/signing-keys</c>
/// and <c>…/signing-keys/jwks</c>. Every Tenant Role reads both; another Tenant's, an unknown and a
/// malformed one are 403; the list never needs custody; and neither answer carries private
/// material, a ciphertext or a Management key. One test or more per API row of the story's matrix.
/// </summary>
public sealed class SigningKeysApiTests(PostgresFixture postgres)
{
    private const string Denied = "type_code = 'admin.access.denied'";

    private static readonly string[] Private = ["d", "p", "q", "dp", "dq", "qi"];

    private static readonly string[] JwkMembers = ["alg", "e", "kid", "kty", "n", "use"];

    private static readonly string[] SigningKeyMembers = ["algorithm", "createdAt", "keyId", "state"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> Roles => ["owner", "editor", "viewer"];

    [Fact]
    public async Task A_fresh_Tenant_lists_next_and_current_and_samples_current_then_next()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var fresh = await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        using var list = await GetAsync(host, cookie, KeysPath(tenant));
        var keys = await KeysAsync(list);
        Assert.Equal(fresh.Select(f => (f.KeyId, f.State)), keys.Select(k => (k.GetProperty("keyId").GetString()!, k.GetProperty("state").GetString()!)));
        Assert.All(keys, k => Assert.Equal("RS256", k.GetProperty("algorithm").GetString()));
        Assert.All(keys, k => Assert.Equal(SigningKeyMembers, k.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal)));
        Assert.All(keys, k => Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", k.GetProperty("createdAt").GetString()!));

        using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
        var (uri, sample) = await JwksAsync(jwks);
        Assert.Equal($"https://{TestTenants.Host(tenant)}/.well-known/jwks", uri);
        Assert.Equal([fresh[1].KeyId, fresh[0].KeyId], sample.Select(k => k.GetProperty("kid").GetString()));

        // Each key is the public half custody gave for its row's version, and nothing else.
        foreach (var key in sample)
        {
            Assert.Equal(JwkMembers, key.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
            Assert.Equal("RSA", key.GetProperty("kty").GetString());
            Assert.Equal("sig", key.GetProperty("use").GetString());
            Assert.Equal("RS256", key.GetProperty("alg").GetString());
            var expected = custody.Parameters(key.GetProperty("kid").GetString()!);
            Assert.True(Base64Url(expected.Modulus!) == key.GetProperty("n").GetString(), "The modulus isn't custody's public key.");
            Assert.Equal(Base64Url(expected.Exponent!), key.GetProperty("e").GetString());
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));
    }

    [Fact]
    public async Task Every_state_is_listed_in_order_and_only_published_keys_are_sampled()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var (signing, management) = await SigningKeySeeds.EveryStateAsync(host.Superuser, tenant);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "editor");

        using var list = await GetAsync(host, cookie, KeysPath(tenant));
        var keys = await KeysAsync(list);
        Assert.Equal(
            ["next", "current", "previous", "retired", "revoked", "retired"],
            keys.Select(k => k.GetProperty("state").GetString()));
        Assert.Equal(signing.Select(s => s.KeyId), keys.Select(k => k.GetProperty("keyId").GetString()));

        using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
        var (_, sample) = await JwksAsync(jwks);
        Assert.Equal(
            [signing[1].KeyId, signing[0].KeyId, signing[2].KeyId],
            sample.Select(k => k.GetProperty("kid").GetString()));

        foreach (var body in new[] { await list.Content.ReadAsStringAsync(Cancellation), await jwks.Content.ReadAsStringAsync(Cancellation) })
        {
            Assert.DoesNotContain("mgmt-", body, StringComparison.Ordinal);
            Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);
            Assert.All(management, m => Assert.DoesNotContain(m.Key.Value, body, StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Neither_answer_holds_a_private_member_a_ciphertext_or_a_Management_key()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.EveryStateAsync(host.Superuser, tenant);
        await PostgresFixture.ExecuteAsync(
            host.Superuser, $"INSERT INTO protection_key_wrap (tenant_id, ciphertext) VALUES ('{tenant}', 'vault:v1:AAAA')");
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "owner");

        using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
        var (_, sample) = await JwksAsync(jwks);
        Assert.NotEmpty(sample);
        Assert.All(sample, k => Assert.All(Private, member => Assert.False(k.TryGetProperty(member, out _), member)));

        using var list = await GetAsync(host, cookie, KeysPath(tenant));
        foreach (var body in new[] { await list.Content.ReadAsStringAsync(Cancellation), await jwks.Content.ReadAsStringAsync(Cancellation) })
        {
            Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);
            Assert.DoesNotContain("mgmt-", body, StringComparison.Ordinal);
            Assert.DoesNotContain("PRIVATE", body, StringComparison.Ordinal);
            Assert.DoesNotContain("transit", body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Theory]
    [MemberData(nameof(Roles))]
    public async Task Any_Tenant_Role_reads_both(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, role);

        using var list = await GetAsync(host, cookie, KeysPath(tenant));
        Assert.Equal(2, (await KeysAsync(list)).Count);
        using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
        Assert.Equal(2, (await JwksAsync(jwks)).Keys.Count);
    }

    [Fact]
    public async Task Another_Tenants_Owner_an_unknown_and_a_malformed_Tenant_are_403_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, a);
        var (cookie, _, _) = await RoleSessionAsync(host, b, "owner");

        foreach (var path in new[] { KeysPath(a), JwksPath(a) })
        {
            using var response = await GetAsync(host, cookie, path);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(response));
        }

        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{a}'"));

        foreach (var id in new[] { Id(Guid.CreateVersion7()), "ten_x", "ten_" + new string('a', 26) })
        {
            foreach (var path in new[] { $"/api/v1/tenants/{id}/signing-keys", $"/api/v1/tenants/{id}/signing-keys/jwks" })
            {
                using var response = await GetAsync(host, cookie, path);
                Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                Assert.Equal("access_denied", await CodeAsync(response));
            }
        }
    }

    [Fact]
    public async Task No_Session_is_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);

        foreach (var path in new[] { KeysPath(tenant), JwksPath(tenant) })
        {
            using var response = await host.SendAsync(HttpMethod.Get, path);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact]
    public async Task Custody_down_is_503_for_the_sample_and_the_list_still_answers()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        // OpenBao refuses every key read, then is gone altogether.
        host.OpenBao.RespondToBody = (path, body) =>
            path.Contains("/transit/keys/", StringComparison.Ordinal) ? (503, """{"errors":["sealed"]}""") : AdminHost.Custody(path, body);

        foreach (var stage in new[] { "refusing", "gone" })
        {
            if (stage == "gone")
            {
                host.OpenBao.Dispose();
            }

            using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, jwks.StatusCode);
            Assert.Equal("no-store", jwks.Headers.CacheControl?.ToString());
            Assert.Empty(await jwks.Content.ReadAsStringAsync(Cancellation));

            using var list = await GetAsync(host, cookie, KeysPath(tenant));
            Assert.Equal(2, (await KeysAsync(list)).Count);
        }

        Assert.DoesNotContain("sig-", host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_blank_public_half_from_custody_is_503_not_500()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var fresh = await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        custody.Blank[fresh[0].Key.Value] = true;
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, jwks.StatusCode);
        Assert.Empty(await jwks.Content.ReadAsStringAsync(Cancellation));
    }

    [Fact]
    public async Task A_published_key_whose_version_custody_lacks_is_503()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var fresh = await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        custody.Version[fresh[0].Key.Value] = 2;
        var (cookie, _, _) = await RoleSessionAsync(host, tenant, "viewer");

        using var jwks = await GetAsync(host, cookie, JwksPath(tenant));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, jwks.StatusCode);
    }

    private static string KeysPath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/signing-keys";

    private static string JwksPath(Guid tenant) => $"{KeysPath(tenant)}/jwks";

    private static Task<HttpResponseMessage> GetAsync(AdminHost host, string cookie, string path) =>
        host.SendAsync(HttpMethod.Get, path, cookie);

    private static async Task<List<JsonElement>> KeysAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["keys"], json.RootElement.EnumerateObject().Select(p => p.Name));
        return [.. json.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.Clone())];
    }

    private static async Task<(string Uri, List<JsonElement> Keys)> JwksAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["jwksUri", "keys"], json.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        return (
            json.RootElement.GetProperty("jwksUri").GetString()!,
            [.. json.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.Clone())]);
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
