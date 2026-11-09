using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server.AspNetCore;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 2.3 (FR-23, FR-8, FR-37, AD-8, AD-9, AD-11): each Tenant's discovery and JWKS on
/// Host.Hosted, through the real Tenant resolution and Protocol registration, against the real
/// PostgreSQL as <c>gk_hosted</c> and the real OpenBao through the <c>host-hosted</c> login. One test
/// or more per row of the story's I/O matrix. No assertion prints a key, a ciphertext or a token.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class DiscoveryAndJwksTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.protocol.test";
    private const string HostB = "beta.protocol.test";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Discovery_names_the_stored_issuer_and_advertises_Client_Credentials_and_the_code_flow()
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var document = await GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        var root = document.RootElement;

        Assert.Equal(a.Issuer, root.GetProperty("issuer").GetString());
        Assert.Equal($"{a.Issuer}.well-known/jwks", root.GetProperty("jwks_uri").GetString());

        // Story 2.5: the token endpoint and the two secret methods it accepts. Story 2.9: the code flow,
        // with S256 PKCE only and iss in every authorization response.
        Assert.Equal($"{a.Issuer}connect/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal(
            ["authorization_code", "client_credentials"],
            root.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()).Order(StringComparer.Ordinal));
        Assert.Equal(
            ["client_secret_basic", "client_secret_post"],
            root.GetProperty("token_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()).Order(StringComparer.Ordinal));
        Assert.Equal($"{a.Issuer}connect/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal(["code"], root.GetProperty("response_types_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["S256"], root.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.True(root.GetProperty("authorization_response_iss_parameter_supported").GetBoolean());
        Assert.Equal(["RS256"], root.GetProperty("id_token_signing_alg_values_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(0, host.Custody.Calls(KeyOperation.Sign));
    }

    [Fact]
    public async Task Jwks_holds_exactly_the_Tenants_next_and_current_Signing_Keys_and_no_Management_key()
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await GetAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal($"public, max-age={(int)SecurityLimits.JwksMaxAge.TotalSeconds}", response.Headers.CacheControl?.ToString());
        Assert.Equal("public, max-age=900", response.Headers.CacheControl?.ToString());

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var keys = document.RootElement.GetProperty("keys").EnumerateArray().ToList();
        using var reader = bao.Custody(OpenBaoFixture.Hosted);

        Assert.Equal(await database.KeyIdsAsync(a.TenantId, "signing"), keys.Select(k => k.GetProperty("kid").GetString()).Order(StringComparer.Ordinal));
        Assert.Equal(2, keys.Count);
        foreach (var key in keys)
        {
            var kid = key.GetProperty("kid").GetString()!;
            Assert.Equal("RSA", key.GetProperty("kty").GetString());
            Assert.Equal("RS256", key.GetProperty("alg").GetString());
            Assert.Equal("sig", key.GetProperty("use").GetString());
            Assert.Matches($"^sig-{a.TenantId:D}-[0-9a-f-]{{36}}\\.v1$", kid);
            Assert.False(key.TryGetProperty("d", out _));
            Assert.Equal(384, Base64UrlEncoder.DecodeBytes(key.GetProperty("n").GetString()).Length);

            // The published modulus is Transit's own public key for that kid.
            var transit = await reader.GetPublicKeysAsync(KeyNameOf(kid), Cancellation);
            Assert.True(
                Base64UrlEncoder.Encode(ModulusFromPem(Assert.Single(transit).PublicKeyPem)) == key.GetProperty("n").GetString(),
                "The JWKS modulus isn't the Transit public key's.");
        }

        var management = await database.KeyIdsAsync(a.TenantId, "management");
        Assert.Equal(2, management.Count);
        Assert.DoesNotContain(keys, k => k.GetProperty("kid").GetString()!.StartsWith("mgmt-", StringComparison.Ordinal));
        Assert.Empty(keys.Select(k => k.GetProperty("kid").GetString()).Intersect(management));
    }

    [Fact]
    public async Task Jwks_also_publishes_a_previous_key()
    {
        var (database, a, _) = await TwoTenantsAsync();

        // A third Signing Key, as Story 2.4's rotation will leave one: Transit first, then its row.
        var id = Guid.CreateVersion7();
        var name = KeyName.Signing(a.TenantId, id);
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            await worker.CreateKeyAsync(name, Cancellation);
        }

        await database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, rotated_at, promoted_at) VALUES ('{id}', '{a.TenantId}', 'signing', 'previous', '{name.Value}', 1, now(), now(), now())");

        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        using var document = await GetJsonAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);
        var kids = document.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();

        Assert.Equal(3, kids.Count);
        Assert.Contains($"{name.Value}.v1", kids);
    }

    [Fact]
    public async Task A_retired_or_revoked_key_is_not_published()
    {
        var (database, a, _) = await TwoTenantsAsync();
        foreach (var state in new[] { "retired", "revoked" })
        {
            var id = Guid.CreateVersion7();
            await database.ExecuteAsync(
                $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, rotated_at, retired_at, promoted_at) VALUES ('{id}', '{a.TenantId}', 'signing', '{state}', 'sig-{a.TenantId:D}-{id:D}', 1, now(), now(), now(), now())");
        }

        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        using var document = await GetJsonAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);

        Assert.Equal(2, document.RootElement.GetProperty("keys").GetArrayLength());
    }

    [Fact]
    public async Task Two_Tenants_share_no_kid_or_modulus()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var a = await GetJsonAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);
        using var b = await GetJsonAsync(host, HostB, ProtocolContract.JsonWebKeySetPath);
        var aKeys = a.RootElement.GetProperty("keys").EnumerateArray().ToList();
        var bKeys = b.RootElement.GetProperty("keys").EnumerateArray().ToList();

        Assert.Equal(2, aKeys.Count);
        Assert.Equal(2, bKeys.Count);
        Assert.Empty(aKeys.Select(k => k.GetProperty("kid").GetString()).Intersect(bKeys.Select(k => k.GetProperty("kid").GetString())));
        Assert.True(
            !aKeys.Select(k => k.GetProperty("n").GetString()).Intersect(bKeys.Select(k => k.GetProperty("n").GetString())).Any(),
            "Two Tenants share a modulus.");
    }

    [Theory]
    [InlineData("X-Forwarded-Host", HostB)]
    [InlineData("X-Forwarded-Proto", "http")]
    [InlineData("Forwarded", "host=" + HostB + ";proto=http")]
    [InlineData("X-Forwarded-Port", "8443")]
    public async Task Forwarded_headers_change_neither_the_issuer_nor_the_jwks_uri(string header, string value)
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var document = await GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath, (header, value));

        Assert.Equal(a.Issuer, document.RootElement.GetProperty("issuer").GetString());
        Assert.Equal($"{a.Issuer}.well-known/jwks", document.RootElement.GetProperty("jwks_uri").GetString());
    }

    [Theory]
    [InlineData("http://acme.protocol.test:8443")]
    [InlineData("http://ACME.Protocol.Test")]
    [InlineData("https://acme.protocol.test:4443")]
    public async Task Request_scheme_port_and_case_change_nothing(string origin)
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await host.Http.GetAsync(new Uri(origin + ProtocolContract.ConfigurationPath), Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));

        Assert.Equal(a.Issuer, document.RootElement.GetProperty("issuer").GetString());
        Assert.Equal($"{a.Issuer}.well-known/jwks", document.RootElement.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task Unknown_host_gets_the_fixed_404_and_builds_nothing()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        foreach (var path in new[] { ProtocolContract.ConfigurationPath, ProtocolContract.JsonWebKeySetPath, ProtocolContract.TokenPath })
        {
            using var response = await GetAsync(host, "nobody.protocol.test", path);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0, host.Custody.TotalCalls);
    }

    [Fact]
    public async Task Other_paths_on_a_Tenant_host_get_the_fixed_404_without_touching_keys()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        foreach (var path in new[] { "/", "/connect/userinfo", "/.well-known/other", "/favicon.ico" })
        {
            using var response = await GetAsync(host, HostA, path);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0, host.Custody.TotalCalls);
    }

    [Fact]
    public async Task Tenant_with_no_keys_yet_has_an_empty_jwks_and_working_discovery()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var jwks = await GetAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);
        Assert.Equal(HttpStatusCode.OK, jwks.StatusCode);

        // Not cacheable: relying parties must see the keys as soon as the backfill gives them.
        Assert.Equal("no-store", jwks.Headers.CacheControl?.ToString());
        using (var document = JsonDocument.Parse(await jwks.Content.ReadAsStringAsync(Cancellation)))
        {
            Assert.Equal(0, document.RootElement.GetProperty("keys").GetArrayLength());
        }

        using var discovery = await GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        Assert.Equal(a.Issuer, discovery.RootElement.GetProperty("issuer").GetString());
        Assert.Equal(0, host.Custody.TotalCalls);

        var options = await host.TenantOptions.GetAsync(a, Cancellation);
        Assert.Empty(options.SigningCredentials);
        Assert.Empty(options.EncryptionCredentials);
    }

    /// <summary>Story 2.5 replaced the 2.3 refusal: a request no client could make a token from writes and signs nothing.</summary>
    [Theory]
    [InlineData("form", HttpStatusCode.Unauthorized, "invalid_client")]
    [InlineData("json", HttpStatusCode.BadRequest, "invalid_request")]
    [InlineData("empty", HttpStatusCode.BadRequest, "invalid_request")]
    [InlineData("get", HttpStatusCode.BadRequest, "invalid_request")]
    public async Task Token_endpoint_refuses_a_request_no_client_can_be_issued_for(string shape, HttpStatusCode status, string error)
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var request = new HttpRequestMessage(shape == "get" ? HttpMethod.Get : HttpMethod.Post, Url(HostA, ProtocolContract.TokenPath))
        {
            Content = shape switch
            {
                "form" => new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["client_id"] = "some-client",
                    ["client_secret"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
                }),
                "json" => new StringContent("{\"grant_type\":\"client_credentials\"}", System.Text.Encoding.UTF8, "application/json"),
                "empty" => new StringContent(string.Empty),
                _ => null,
            },
        };

        using var response = await host.Http.SendAsync(request, Cancellation);

        Assert.Equal(status, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(error, document.RootElement.GetProperty("error").GetString());
        Assert.False(document.RootElement.TryGetProperty("access_token", out _));

        // No store, no signature: nothing was read or written for it.
        Assert.Equal(0, host.Custody.Calls(KeyOperation.Sign));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM \"authorization\""));
    }

    [Theory]
    [InlineData(KeyOperation.ReadPublicKey)]
    [InlineData(KeyOperation.Decrypt)]
    public async Task Custody_down_is_a_503_and_the_failed_build_is_not_kept(KeyOperation failing)
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        host.Custody.Failing.Add(failing);

        foreach (var path in new[] { ProtocolContract.JsonWebKeySetPath, ProtocolContract.ConfigurationPath })
        {
            using var response = await GetAsync(host, HostA, path);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        // The very next request builds again, with no wait: a failure is never kept.
        host.Custody.Failing.Clear();
        using (var recovered = await GetAsync(host, HostA, ProtocolContract.JsonWebKeySetPath))
        {
            Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        }

        // Key names and public halves are published anyway; private halves, ciphertexts and the
        // unwrapped protection key never reach a log.
        var logs = string.Join('\n', host.Logs.Lines);
        Assert.Contains("Tenant protocol runtime failed on KeyCustodyException.", logs);
        Assert.DoesNotContain("vault:", logs);
        Assert.DoesNotContain("PRIVATE KEY", logs);
        Assert.DoesNotContain("PUBLIC KEY", logs);
        var wrap = await database.ScalarAsync<string>($"SELECT ciphertext FROM protection_key_wrap WHERE tenant_id = '{a.TenantId}'");
        Assert.False(logs.Contains(wrap, StringComparison.Ordinal), "The wrapped protection key reached a log.");

        using var hosted = bao.Custody(OpenBaoFixture.Hosted);
        var unwrapped = await hosted.DecryptAsync(KeysContract.TokenProtectionKey(a.TenantId), a.TenantId, new KeyCiphertext(wrap), Cancellation);
        Assert.False(
            unwrapped.Use(bytes => logs.Contains(Convert.ToBase64String(bytes), StringComparison.Ordinal)
                || logs.Contains(Base64UrlEncoder.Encode(bytes), StringComparison.Ordinal)
                || logs.Contains(Convert.ToHexString(bytes), StringComparison.OrdinalIgnoreCase)),
            "The unwrapped protection key reached a log.");
    }

    [Fact]
    public async Task A_stalled_custody_call_times_out_as_a_503()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        host.Custody.Hanging.Add(KeyOperation.ReadPublicKey);

        using var limit = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        limit.CancelAfter(SecurityLimits.KeyCustodyCallTimeout * 4);
        using var response = await host.Http.GetAsync(Url(HostA, ProtocolContract.JsonWebKeySetPath), limit.Token);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("Tenant protocol runtime failed on TimeoutException.", string.Join('\n', host.Logs.Lines));
    }

    [Fact]
    public async Task Runtime_is_kept_five_seconds_at_most()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var clock = new ManualTimeProvider();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, clock);

        Assert.Equal(2, await KeyCountAsync(host));
        var reads = host.Custody.Calls(KeyOperation.ReadPublicKey);

        // A key published after the build: the kept runtime doesn't see it yet.
        var id = Guid.CreateVersion7();
        var name = KeyName.Signing(a.TenantId, id);
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            await worker.CreateKeyAsync(name, Cancellation);
        }

        await database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, rotated_at, promoted_at) VALUES ('{id}', '{a.TenantId}', 'signing', 'previous', '{name.Value}', 1, now(), now(), now())");

        clock.Advance(SecurityLimits.TenantRuntimeLifetime - TimeSpan.FromMilliseconds(1));
        Assert.Equal(2, await KeyCountAsync(host));
        Assert.Equal(reads, host.Custody.Calls(KeyOperation.ReadPublicKey));

        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.Equal(3, await KeyCountAsync(host));
    }

    [Fact]
    public async Task Runtime_is_dropped_when_its_lifetime_ends_with_no_further_request()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var clock = new ManualTimeProvider();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, clock);

        Assert.Equal(2, await KeyCountAsync(host));
        await host.TenantOptions.GetAsync(b, Cancellation);
        Assert.Equal(2, Kept(host));

        clock.Advance(SecurityLimits.TenantRuntimeLifetime - TimeSpan.FromMilliseconds(1));
        Assert.Equal(2, Kept(host));

        // No request comes: the timer alone drops both, and the unwrapped protection keys with them.
        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.Equal(0, Kept(host));
        _ = a;
    }

    [Fact]
    public async Task Key_read_failure_is_a_503()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await database.ExecuteAsync("REVOKE SELECT ON signing_key FROM gk_hosted");
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        foreach (var path in new[] { ProtocolContract.JsonWebKeySetPath, ProtocolContract.ConfigurationPath })
        {
            using var response = await GetAsync(host, HostA, path);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Contains("Tenant protocol runtime failed on PostgresException.", string.Join('\n', host.Logs.Lines));
        Assert.Equal(0, host.Custody.TotalCalls);
    }

    [Fact]
    public async Task Issuer_with_a_path_is_refused_when_the_runtime_is_built()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await database.AddTenantAsync(HostA, issuer: $"https://{HostA}/tenant/");
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await GetAsync(host, HostA, ProtocolContract.ConfigurationPath);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await host.TenantOptions.GetAsync(tenant, Cancellation));
    }

    [Fact]
    public async Task Tenant_handler_is_first_and_ResolveRequestUri_is_removed()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        var handlers = host.GlobalOptions.Handlers;

        var first = handlers.Where(d => d.ContextType == typeof(ProcessRequestContext)).MinBy(d => d.Order)!;
        Assert.Equal(int.MinValue, first.Order);
        Assert.Equal("Gatekeep.Modules.Protocol.Core.SelectTenantOptions", first.ServiceDescriptor.ServiceType.FullName);
        Assert.Single(handlers, d => d.ContextType == typeof(ProcessRequestContext) && d.Order == int.MinValue);
        Assert.DoesNotContain(handlers, d => d.ServiceDescriptor.ServiceType == typeof(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri));

        // Story 2.5: OpenIddict's secret check is gone, and Gatekeep's runs on token request validation
        // after the grant type check, before OpenIddict's parameter checks and its client lookup (which
        // runs later, in ValidateAuthentication).
        Assert.DoesNotContain(handlers, d => d.ServiceDescriptor.ServiceType == typeof(OpenIddict.Server.OpenIddictServerHandlers.ValidateClientSecret));
        var gatekeep = Assert.Single(handlers, d => d.ServiceDescriptor.ServiceType.FullName == "Gatekeep.Modules.Protocol.Core.AuthenticateGatekeepClient");
        Assert.Equal(typeof(ValidateTokenRequestContext), gatekeep.ContextType);
        Assert.True(gatekeep.Order > OpenIddict.Server.OpenIddictServerHandlers.Exchange.ValidateGrantType.Descriptor.Order);
        Assert.True(gatekeep.Order < OpenIddict.Server.OpenIddictServerHandlers.Exchange.ValidateClientIdParameter.Descriptor.Order);
        Assert.True(gatekeep.Order < OpenIddict.Server.OpenIddictServerHandlers.Exchange.ValidateAuthentication.Descriptor.Order);
        Assert.False(host.GlobalOptions.EnableDegradedMode);
        Assert.Equal(
            ["client_secret_basic", "client_secret_post"],
            host.GlobalOptions.ClientAuthenticationMethods.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Tenant_options_copies_hold_only_their_Tenants_keys_and_never_an_inert_or_Management_key()
    {
        var (database, a, b) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        var global = host.GlobalOptions;

        var aOptions = await host.TenantOptions.GetAsync(a, Cancellation);
        var bOptions = await host.TenantOptions.GetAsync(b, Cancellation);
        Assert.NotSame(global, aOptions);
        Assert.NotSame(aOptions, bOptions);

        foreach (var (tenant, options) in new[] { (a, aOptions), (b, bOptions) })
        {
            var signing = await database.KeyIdsAsync(tenant.TenantId, "signing");
            var keyIds = KeyIds(options);

            Assert.Equal(new Uri(tenant.Issuer), options.Issuer);
            Assert.Equal(signing, options.SigningCredentials.Select(c => c.Key.KeyId).Order(StringComparer.Ordinal));
            Assert.Equal(signing, options.TokenValidationParameters.IssuerSigningKeys.Select(k => k.KeyId).Order(StringComparer.Ordinal));
            Assert.Equal([$"tpk-{tenant.TenantId:D}"], options.EncryptionCredentials.Select(c => c.Key.KeyId));
            Assert.Equal([$"tpk-{tenant.TenantId:D}"], options.TokenValidationParameters.TokenDecryptionKeys.Select(k => k.KeyId));
            Assert.All(options.SigningCredentials, c => Assert.Equal(SecurityAlgorithms.RsaSha256, c.Algorithm));

            Assert.DoesNotContain(ProtocolContract.InertSigningKeyId, keyIds);
            Assert.DoesNotContain(ProtocolContract.InertEncryptionKeyId, keyIds);
            Assert.DoesNotContain(keyIds, k => k.Contains("mgmt-", StringComparison.Ordinal));
            Assert.All(keyIds, k => Assert.Contains(tenant.TenantId.ToString("D"), k));
        }

        // The current key is the first, the one OpenIddict would sign with.
        var current = await database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'current'");
        Assert.Equal(current, aOptions.SigningCredentials[0].Key.KeyId);

        // The global options still hold only the inert credentials.
        Assert.Equal([ProtocolContract.InertSigningKeyId], global.SigningCredentials.Select(c => c.Key.KeyId));
        Assert.Equal([ProtocolContract.InertEncryptionKeyId], global.EncryptionCredentials.Select(c => c.Key.KeyId));
    }

    [Fact]
    public async Task Global_credentials_are_inert_and_never_reach_a_jwks()
    {
        var (database, _, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        var global = host.GlobalOptions;

        var signing = Assert.Single(global.SigningCredentials);
        Assert.ThrowsAny<InvalidOperationException>(() =>
            signing.Key.CryptoProviderFactory.CreateForSigning(signing.Key, signing.Algorithm));
        var encrypting = Assert.Single(global.EncryptionCredentials);
        Assert.ThrowsAny<InvalidOperationException>(() =>
            encrypting.Key.CryptoProviderFactory.CreateKeyWrapProvider(encrypting.Key, encrypting.Alg));

        foreach (var tenantHost in new[] { HostA, HostB })
        {
            using var document = await GetJsonAsync(host, tenantHost, ProtocolContract.JsonWebKeySetPath);
            var kids = document.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()).ToList();
            Assert.NotEmpty(kids);
            Assert.DoesNotContain(ProtocolContract.InertSigningKeyId, kids);
            Assert.DoesNotContain(ProtocolContract.InertEncryptionKeyId, kids);
        }
    }

    private async Task<(ProtocolDatabase Database, ResolvedTenant A, ResolvedTenant B)> TwoTenantsAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        var b = await database.AddTenantAsync(HostB);
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(bao, b.TenantId));
        return (database, a, b);
    }

    private static List<string> KeyIds(OpenIddict.Server.OpenIddictServerOptions options) =>
    [
        .. options.SigningCredentials.Select(c => c.Key.KeyId),
        .. options.EncryptionCredentials.Select(c => c.Key.KeyId),
        .. options.TokenValidationParameters.IssuerSigningKeys.Select(k => k.KeyId),
        .. options.TokenValidationParameters.TokenDecryptionKeys.Select(k => k.KeyId),
    ];

    /// <summary>How many Tenant runtimes the host keeps now, read from the internal cache.</summary>
    private static int Kept(ProtocolHost host) =>
        (int)host.TenantOptions.GetType().GetProperty("Kept")!.GetValue(host.TenantOptions)!;

    private static async Task<int> KeyCountAsync(ProtocolHost host)
    {
        using var document = await GetJsonAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);
        return document.RootElement.GetProperty("keys").GetArrayLength();
    }

    private static KeyName KeyNameOf(string kid)
    {
        // sig-{tenant}-{row}.v{n}: two UUIDs after the prefix.
        var name = kid[..kid.LastIndexOf(".v", StringComparison.Ordinal)];
        var tenant = Guid.Parse(name.Substring(4, 36));
        var row = Guid.Parse(name.Substring(41, 36));
        return KeyName.Signing(tenant, row);
    }

    private static byte[] ModulusFromPem(string pem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.ExportParameters(includePrivateParameters: false).Modulus!;
    }

    private static Uri Url(string host, string path) => new($"http://{host}{path}");

    private static async Task<HttpResponseMessage> GetAsync(ProtocolHost host, string tenantHost, string path, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Url(tenantHost, path));
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        var response = await host.Http.SendAsync(request, Cancellation);
        await response.Content.LoadIntoBufferAsync(Cancellation);
        return response;
    }

    private static async Task<JsonDocument> GetJsonAsync(ProtocolHost host, string tenantHost, string path, params (string Name, string Value)[] headers)
    {
        using var response = await GetAsync(host, tenantHost, path, headers);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }
}
