using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server.AspNetCore;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>
/// Story 2.1: OpenIddict 7.7.2 wrapped per Tenant (AD-8). One test per row of the spike's I/O
/// matrix; <c>docs/spikes/2-1-openiddict-per-tenant.md</c> names each. No assertion compares a
/// token, code or key value directly, so a failure can't print one.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class PerTenantOptionsSpikeTests(OpenBaoFixture bao)
{
    private const string UnknownHost = "unknown.spike.test";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Gatekeep_handler_runs_first_and_swaps_in_a_separate_Tenant_options_object()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var global = spike.GlobalOptions;

        var first = global.Handlers.First(d => d.ContextType == typeof(ProcessRequestContext));
        Assert.Equal(typeof(SelectTenantOptions), first.ServiceDescriptor.ServiceType);
        Assert.DoesNotContain(global.Handlers, d =>
            d.ServiceDescriptor.ServiceType == typeof(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri));
        Assert.Null(global.Issuer);
        Assert.Equal([InertCredentials.SigningKeyId], global.SigningCredentials.Select(c => c.Key.KeyId));
        Assert.Equal([InertCredentials.EncryptionKeyId], global.EncryptionCredentials.Select(c => c.Key.KeyId));

        await GetJsonAsync(spike, spike.Tenants.A, SpikeServer.DiscoveryPath);
        await GetJsonAsync(spike, spike.Tenants.B, SpikeServer.DiscoveryPath);
        var a = spike.Runtimes.Built(spike.Tenants.A);
        var b = spike.Runtimes.Built(spike.Tenants.B);

        Assert.NotSame(global, a.Options);
        Assert.NotSame(global, b.Options);
        Assert.NotSame(a.Options, b.Options);

        foreach (var runtime in new[] { a, b })
        {
            var options = runtime.Options;
            Assert.Equal(runtime.Tenant.Issuer, options.Issuer);
            Assert.Equal([runtime.Signing.KeyId], options.SigningCredentials.Select(c => c.Key.KeyId));
            Assert.Equal([runtime.TokenProtection.KeyId], options.EncryptionCredentials.Select(c => c.Key.KeyId));
            Assert.Equal([runtime.Signing.KeyId], options.TokenValidationParameters.IssuerSigningKeys.Select(k => k.KeyId));
            Assert.Equal([runtime.TokenProtection.KeyId], options.TokenValidationParameters.TokenDecryptionKeys.Select(k => k.KeyId));
        }

        // None of A's key IDs reach B's options.
        var bKeyIds = b.Options.SigningCredentials.Select(c => c.Key.KeyId)
            .Concat(b.Options.EncryptionCredentials.Select(c => c.Key.KeyId))
            .Concat(b.Options.TokenValidationParameters.IssuerSigningKeys.Select(k => k.KeyId))
            .Concat(b.Options.TokenValidationParameters.TokenDecryptionKeys.Select(k => k.KeyId))
            .ToList();
        Assert.DoesNotContain(a.Signing.KeyId, bKeyIds);
        Assert.DoesNotContain(a.TokenProtection.KeyId, bKeyIds);

        // The global options are untouched by the copies.
        Assert.Equal([InertCredentials.SigningKeyId], global.SigningCredentials.Select(c => c.Key.KeyId));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Discovery_on_each_host_names_that_Tenants_stored_issuer_and_endpoints()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);

        foreach (var tenant in spike.Tenants.All)
        {
            using var document = await GetJsonAsync(spike, tenant, SpikeServer.DiscoveryPath);
            var root = document.RootElement;

            Assert.Equal(tenant.Issuer.AbsoluteUri, root.GetProperty("issuer").GetString());
            Assert.Equal(Endpoint(tenant, SpikeServer.AuthorizePath), root.GetProperty("authorization_endpoint").GetString());
            Assert.Equal(Endpoint(tenant, SpikeServer.TokenPath), root.GetProperty("token_endpoint").GetString());
            Assert.Equal(Endpoint(tenant, SpikeServer.JwksPath), root.GetProperty("jwks_uri").GetString());
            Assert.Equal(["RS256"], root.GetProperty("id_token_signing_alg_values_supported").EnumerateArray().Select(e => e.GetString()));
            Assert.Equal(["S256"], root.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()));
        }

        // BaseUri comes from the stored issuer, not the request: a port on the request URI
        // would appear in every endpoint if OpenIddict built BaseUri from the Host header.
        using var withPort = await GetJsonAsync(
            spike, new Uri($"https://{SpikeTenants.HostA}:8443{SpikeServer.DiscoveryPath}"));
        Assert.Equal(spike.Tenants.A.Issuer.AbsoluteUri, withPort.RootElement.GetProperty("issuer").GetString());
        Assert.Equal(Endpoint(spike.Tenants.A, SpikeServer.TokenPath), withPort.RootElement.GetProperty("token_endpoint").GetString());

        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Jwks_on_each_host_holds_only_that_Tenants_Transit_public_key()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var kids = new Dictionary<SpikeTenant, string>();

        foreach (var tenant in spike.Tenants.All)
        {
            using var jwks = await GetJsonAsync(spike, tenant, SpikeServer.JwksPath);
            var signing = spike.Runtimes.Built(tenant).Signing;
            var key = Assert.Single(jwks.RootElement.GetProperty("keys").EnumerateArray());

            Assert.Equal("RSA", key.GetProperty("kty").GetString());
            Assert.Equal("RS256", key.GetProperty("alg").GetString());
            Assert.Equal("sig", key.GetProperty("use").GetString());
            Assert.Equal(signing.KeyId, key.GetProperty("kid").GetString());
            Assert.StartsWith(tenant.SigningKey.Value + ".v", signing.KeyId, StringComparison.Ordinal);
            Assert.True(
                Base64UrlEncoder.Encode(signing.PublicParameters.Modulus) == key.GetProperty("n").GetString(),
                "The JWKS modulus isn't the Transit public key's.");
            Assert.Equal(384, Base64UrlEncoder.DecodeBytes(key.GetProperty("n").GetString()).Length);
            Assert.False(key.TryGetProperty("d", out _));
            kids[tenant] = key.GetProperty("kid").GetString()!;
        }

        Assert.NotEqual(kids[spike.Tenants.A], kids[spike.Tenants.B]);
        Assert.DoesNotContain(InertCredentials.SigningKeyId, kids.Values);
        Assert.DoesNotContain(InertCredentials.EncryptionKeyId, kids.Values);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Client_credentials_token_is_signed_in_Transit_and_verifies_only_against_its_Tenant()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var a = spike.Tenants.A;

        using var response = await ClientCredentialsAsync(spike, a);
        await GetJsonAsync(spike, spike.Tenants.B, SpikeServer.DiscoveryPath);
        var signingA = spike.Runtimes.Built(a).Signing;
        var signingB = spike.Runtimes.Built(spike.Tenants.B).Signing;

        var token = response.RootElement.GetProperty("access_token").GetString()!;
        var jwt = new JsonWebToken(token);
        Assert.Equal("at+jwt", jwt.Typ);
        Assert.Equal("RS256", jwt.Alg);
        Assert.Equal(signingA.KeyId, jwt.Kid);
        Assert.Equal(a.Issuer.AbsoluteUri, jwt.Issuer);
        Assert.Equal(SpikeClients.Confidential, jwt.Subject);

        Assert.True(await VerifiesAsync(token, signingA, a), "The token doesn't verify against A's Transit public key.");
        Assert.False(await VerifiesAsync(token, signingB, a), "The token verifies against B's Transit public key.");

        Assert.Equal(1, signingA.Signs);
        Assert.Equal(0, signingB.Signs);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Authorization_code_with_PKCE_S256_is_redeemed_on_its_own_host_and_signed_by_it()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var a = spike.Tenants.A;

        var (code, verifier, iss) = await AuthorizeAsync(spike, a);
        Assert.Equal(a.Issuer.AbsoluteUri, iss);

        var protection = spike.Runtimes.Built(a).TokenProtection;
        var codeJwt = new JsonWebToken(code);
        Assert.True(codeJwt.IsEncrypted, "The authorization code isn't encrypted.");
        Assert.Equal(protection.KeyId, codeJwt.Kid);
        Assert.Equal(SecurityAlgorithms.Aes256KW, codeJwt.Alg);

        using var redeemed = await RedeemAsync(spike, a, code, verifier);
        Assert.Equal(HttpStatusCode.OK, redeemed.Status);
        var signing = spike.Runtimes.Built(a).Signing;

        foreach (var name in new[] { "access_token", "id_token" })
        {
            var token = redeemed.Body.RootElement.GetProperty(name).GetString()!;
            var jwt = new JsonWebToken(token);
            Assert.Equal(signing.KeyId, jwt.Kid);
            Assert.Equal(a.Issuer.AbsoluteUri, jwt.Issuer);
            Assert.Equal(SpikeServer.Subject, jwt.Subject);
            Assert.True(await VerifiesAsync(token, signing, a), $"The {name} doesn't verify against A's Transit public key.");
        }

        // The code, the access token and the ID token: each signed once in Transit.
        Assert.Equal(3, signing.Signs);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Code_from_one_Tenant_is_refused_on_another_because_its_protection_key_cant_open_it()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var (a, b) = (spike.Tenants.A, spike.Tenants.B);

        var (code, verifier, _) = await AuthorizeAsync(spike, a);
        using var refused = await RedeemAsync(spike, b, code, verifier);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Body.RootElement.GetProperty("error").GetString());
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.False(refused.Body.RootElement.TryGetProperty("id_token", out _));

        // The reason: B's protection key can't open A's code, and A's can.
        var handler = new JsonWebTokenHandler();
        var keyA = spike.Runtimes.Built(a).TokenProtection;
        var keyB = spike.Runtimes.Built(b).TokenProtection;
        Assert.ThrowsAny<SecurityTokenException>(() =>
            handler.DecryptToken(new JsonWebToken(code), new TokenValidationParameters { TokenDecryptionKeys = [keyB] }));
        Assert.NotEmpty(handler.DecryptToken(new JsonWebToken(code), new TokenValidationParameters { TokenDecryptionKeys = [keyA] }));

        Assert.Equal(0, spike.Runtimes.Built(b).Signing.Signs);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Unknown_host_is_refused_with_404_before_any_other_OpenIddict_handler()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var root = new Uri($"https://{UnknownHost}/");

        var requests = new List<HttpRequestMessage>
        {
            new(HttpMethod.Get, new Uri(root, SpikeServer.DiscoveryPath)),
            new(HttpMethod.Get, new Uri(root, SpikeServer.JwksPath)),
            new(HttpMethod.Get, new Uri(root, SpikeServer.AuthorizePath + AuthorizeQuery("challenge-not-used"))),
            new(HttpMethod.Post, new Uri(root, SpikeServer.TokenPath)) { Content = ClientCredentialsForm() },
        };

        foreach (var request in requests)
        {
            using (request)
            using (var response = await spike.Client.SendAsync(request, Cancellation))
            {
                Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
                Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
                Assert.Null(response.Headers.Location);
            }
        }

        // No Tenant's options were built and no key was touched.
        Assert.Throws<InvalidOperationException>(() => spike.Runtimes.Built(spike.Tenants.A));
        Assert.Throws<InvalidOperationException>(() => spike.Runtimes.Built(spike.Tenants.B));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Inert_global_credentials_reach_no_token_or_JWKS_and_are_never_used()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var kids = new List<string?>();

        foreach (var tenant in spike.Tenants.All)
        {
            using (var discovery = await GetJsonAsync(spike, tenant, SpikeServer.DiscoveryPath))
            using (var jwks = await GetJsonAsync(spike, tenant, SpikeServer.JwksPath))
            using (var service = await ClientCredentialsAsync(spike, tenant))
            {
                kids.AddRange(jwks.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()));
                kids.Add(new JsonWebToken(service.RootElement.GetProperty("access_token").GetString()!).Kid);
            }

            var (code, verifier, _) = await AuthorizeAsync(spike, tenant);
            kids.Add(new JsonWebToken(code).Kid);

            using var redeemed = await RedeemAsync(spike, tenant, code, verifier);
            kids.Add(new JsonWebToken(redeemed.Body.RootElement.GetProperty("access_token").GetString()!).Kid);
            kids.Add(new JsonWebToken(redeemed.Body.RootElement.GetProperty("id_token").GetString()!).Kid);
        }

        // Per Tenant: the JWKS key, the service token, the code, and the redeemed access and ID tokens.
        Assert.Equal(10, kids.Count);
        Assert.All(kids, kid => Assert.False(string.IsNullOrEmpty(kid)));
        Assert.DoesNotContain(InertCredentials.SigningKeyId, kids);
        Assert.DoesNotContain(InertCredentials.EncryptionKeyId, kids);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public void Inert_credentials_throw_and_count_on_any_cryptographic_use()
    {
        var inert = new InertCredentials();
        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor { Issuer = "https://inert.spike.test/", Claims = new Dictionary<string, object> { ["sub"] = "x" } };

        descriptor.SigningCredentials = inert.Signing;
        AssertInertRefusal(Assert.ThrowsAny<Exception>(() => handler.CreateToken(descriptor)));
        var afterSigning = inert.Uses;

        var signing = new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), SecurityAlgorithms.HmacSha256);
        descriptor.SigningCredentials = signing;
        descriptor.EncryptingCredentials = inert.Encrypting;
        AssertInertRefusal(Assert.ThrowsAny<Exception>(() => handler.CreateToken(descriptor)));

        Assert.True(afterSigning > 0, "Signing with the inert key wasn't counted.");
        Assert.True(inert.Uses > afterSigning, "Encrypting with the inert key wasn't counted.");
    }

    [Fact]
    public async Task Concurrent_token_requests_complete_while_each_Sign_blocks_on_Transit()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        const int perTenant = 16;

        var requests = spike.Tenants.All
            .SelectMany(tenant => Enumerable.Range(0, perTenant).Select(async _ =>
            {
                using var body = await ClientCredentialsAsync(spike, tenant);
                return (tenant, kid: new JsonWebToken(body.RootElement.GetProperty("access_token").GetString()!).Kid);
            }))
            .ToList();

        var results = await Task.WhenAll(requests).WaitAsync(TimeSpan.FromSeconds(60), Cancellation);

        foreach (var tenant in spike.Tenants.All)
        {
            var signing = spike.Runtimes.Built(tenant).Signing;
            Assert.All(results.Where(r => r.tenant == tenant), r => Assert.Equal(signing.KeyId, r.kid));
            Assert.Equal(perTenant, signing.Signs);
        }

        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Authorize_without_S256_PKCE_is_refused_and_issues_no_code()
    {
        await using var spike = await SpikeServer.StartAsync(bao, Cancellation);
        var a = spike.Tenants.A;
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        var plain = AuthorizeQuery(verifier).Replace("code_challenge_method=S256", "code_challenge_method=plain", StringComparison.Ordinal);
        var missing = QueryString.Create(new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = SpikeClients.Public,
            ["redirect_uri"] = SpikeClients.RedirectUri,
            ["scope"] = "openid",
            ["state"] = "spike-state",
        }).ToUriComponent();
        Assert.Contains("code_challenge_method=plain", plain, StringComparison.Ordinal);

        foreach (var query in new[] { plain, missing })
        {
            using var response = await spike.Client.GetAsync(new Uri(a.Issuer, SpikeServer.AuthorizePath + query), Cancellation);
            var location = response.Headers.Location;
            var parameters = location is null
                ? QueryHelpers.ParseQuery(await response.Content.ReadAsStringAsync(Cancellation))
                : QueryHelpers.ParseQuery(location.Query);

            // An error comes back, by redirect or directly, and never a code.
            Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.False(parameters.ContainsKey("code"), "A code was issued without S256 PKCE.");
            if (location is not null)
            {
                Assert.True(parameters.ContainsKey("error"), "The redirect carries no error.");
            }
        }

        Assert.Equal(0, spike.Runtimes.Built(a).Signing.Signs);
        Assert.Equal(0, spike.Inert.Uses);
    }

    private static void AssertInertRefusal(Exception thrown)
    {
        for (Exception? current = thrown; current is not null; current = current.InnerException)
        {
            if (current is InertKeyUsedException)
            {
                return;
            }
        }

        Assert.Fail($"Expected an {nameof(InertKeyUsedException)}, got {thrown.GetType().Name}.");
    }

    private static string Endpoint(SpikeTenant tenant, string path) => new Uri(tenant.Issuer, path).AbsoluteUri;

    private static Task<JsonDocument> GetJsonAsync(SpikeServer spike, SpikeTenant tenant, string path) =>
        GetJsonAsync(spike, new Uri(tenant.Issuer, path));

    private static async Task<JsonDocument> GetJsonAsync(SpikeServer spike, Uri uri)
    {
        using var response = await spike.Client.GetAsync(uri, Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }

    private static FormUrlEncodedContent ClientCredentialsForm() => new(new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = SpikeClients.Confidential,
        ["client_secret"] = SpikeClients.ConfidentialSecret,
    });

    private static async Task<JsonDocument> ClientCredentialsAsync(SpikeServer spike, SpikeTenant tenant)
    {
        using var content = ClientCredentialsForm();
        using var response = await spike.Client.PostAsync(new Uri(tenant.Issuer, SpikeServer.TokenPath), content, Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }

    private static string AuthorizeQuery(string challenge) => QueryString.Create(new Dictionary<string, string?>
    {
        ["response_type"] = "code",
        ["client_id"] = SpikeClients.Public,
        ["redirect_uri"] = SpikeClients.RedirectUri,
        ["scope"] = "openid",
        ["state"] = "spike-state",
        ["code_challenge"] = challenge,
        ["code_challenge_method"] = "S256",
    }).ToUriComponent();

    private static async Task<(string Code, string Verifier, string? Iss)> AuthorizeAsync(SpikeServer spike, SpikeTenant tenant)
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        using var response = await spike.Client.GetAsync(
            new Uri(tenant.Issuer, SpikeServer.AuthorizePath + AuthorizeQuery(challenge)), Cancellation);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);

        var location = response.Headers.Location!;
        Assert.Equal(SpikeClients.RedirectUri, location.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("spike-state", query["state"].ToString());
        Assert.True(query.ContainsKey("code"), "The authorization response has no code.");

        return (query["code"].ToString(), verifier, query.TryGetValue("iss", out var iss) ? iss.ToString() : null);
    }

    private static async Task<Redemption> RedeemAsync(SpikeServer spike, SpikeTenant tenant, string code, string verifier)
    {
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = SpikeClients.Public,
            ["redirect_uri"] = SpikeClients.RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier,
        });
        using var response = await spike.Client.PostAsync(new Uri(tenant.Issuer, SpikeServer.TokenPath), content, Cancellation);
        return new Redemption(response.StatusCode, JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)));
    }

    /// <summary>Verifies outside OpenIddict, with the PEM public half and the default crypto.</summary>
    private static async Task<bool> VerifiesAsync(string token, TransitSigning signing, SpikeTenant issuer)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = signing.VerificationKey(),
            ValidIssuer = issuer.Issuer.AbsoluteUri,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        });
        return result.IsValid;
    }

    private sealed record Redemption(HttpStatusCode Status, JsonDocument Body) : IDisposable
    {
        public void Dispose() => Body.Dispose();
    }
}
