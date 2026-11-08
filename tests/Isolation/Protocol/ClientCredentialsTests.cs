using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 2.5 (FR-13, FR-23, AD-8, AD-9, AD-14): Client Credentials on each Tenant's token endpoint,
/// through the real Tenant resolution and Protocol registration, against the real PostgreSQL as
/// <c>gk_hosted</c> and the real OpenBao through the <c>host-hosted</c> login. One test or more per row
/// of the story's I/O matrix. No assertion prints a secret or a token: values are compared with
/// <c>Assert.True(a == b, …)</c>, and rows are searched by parameter.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ClientCredentialsTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.tokens.test";
    private const string HostB = "beta.tokens.test";
    private const string Rejected = "protocol.client.cross_tenant_rejected";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("basic")]
    [InlineData("post")]
    public async Task Machine_client_gets_an_RS256_at_jwt_signed_by_its_Tenants_current_key(string method)
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret, method);
        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("Bearer", response.Body.RootElement.GetProperty("token_type").GetString());
        Assert.Equal((int)SecurityLimits.DefaultAccessTokenLifetime.TotalSeconds, response.Body.RootElement.GetProperty("expires_in").GetInt32());
        Assert.Equal(900, response.Body.RootElement.GetProperty("expires_in").GetInt32());
        Assert.False(response.Body.RootElement.TryGetProperty("refresh_token", out _));
        Assert.False(response.Body.RootElement.TryGetProperty("id_token", out _));

        var token = new JsonWebToken(response.AccessToken);
        Assert.Equal("at+jwt", token.Typ);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Alg);
        Assert.Equal(await CurrentKidAsync(database, a.TenantId), token.Kid);
        Assert.Equal(a.Issuer, token.Issuer);
        Assert.Equal(client.ClientId, token.Subject);
        Assert.Equal(new[] { ProtocolContract.PlaceholderAudience }, token.Audiences);
        Assert.Equal(SecurityLimits.DefaultAccessTokenLifetime, token.ValidTo - token.IssuedAt);
        Assert.True(token.ValidTo - token.IssuedAt <= SecurityLimits.HardSignedTokenLifetime);
        Assert.Equal(1, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Sign));

        // One row for the access token, holding no token value; no Application column holds a secret.
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{a.TenantId}' AND type = '{OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.AccessToken}' AND subject = '{client.ClientId}' AND application_id = '{client.ApplicationId}' AND payload IS NULL AND reference_id IS NULL AND status = 'valid'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await RowsHoldingAsync(database, "token", token.EncodedSignature));
        Assert.Equal(0L, await RowsHoldingAsync(database, "token", token.EncodedPayload));
        Assert.Equal(0L, await RowsHoldingAsync(database, "application", client.Secret));
        Assert.Equal(0L, await RowsHoldingAsync(database, "client_secret", client.Secret));
        Assert.Equal(0L, await RowsHoldingAsync(database, "audit_event", client.Secret));
    }

    [Fact]
    public async Task Token_verifies_against_its_own_Tenants_jwks_and_no_other()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret);
        Assert.Equal(HttpStatusCode.OK, response.Status);

        Assert.True(await VerifiesAsync(response.AccessToken, await JwksAsync(host, HostA), a.Issuer), "A's token doesn't verify against A's JWKS.");
        Assert.False(await VerifiesAsync(response.AccessToken, await JwksAsync(host, HostB), a.Issuer), "A's token verifies against B's JWKS.");
        Assert.False(await VerifiesAsync(response.AccessToken, await JwksAsync(host, HostA), b.Issuer), "A's token verifies as B's issuer.");
    }

    [Fact]
    public async Task Discovery_advertises_the_token_endpoint_client_credentials_and_two_secret_methods_only()
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var discovery = await GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        var root = discovery.RootElement;

        Assert.Equal($"{a.Issuer}connect/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal(["client_credentials"], Strings(root.GetProperty("grant_types_supported")));
        Assert.Equal(["client_secret_basic", "client_secret_post"], Strings(root.GetProperty("token_endpoint_auth_methods_supported")).Order(StringComparer.Ordinal));
        Assert.False(root.TryGetProperty("authorization_endpoint", out _));
        Assert.Equal(0, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Sign));
    }

    [Fact]
    public async Task Wrong_secret_and_unknown_client_get_the_same_invalid_client_and_no_Log_event()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        var events = await EventCountAsync(database, a.TenantId);

        var wrong = WithRandomPart(client.Secret);
        using var wrongSecret = await TokenAsync(host, HostA, client.ClientId, wrong);
        using var unknown = await TokenAsync(host, HostA, PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()), client.Secret);
        using var malformed = await TokenAsync(host, HostA, "not-a-client", client.Secret);

        foreach (var refused in new[] { wrongSecret, unknown, malformed })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
            Assert.Equal("invalid_client", refused.Error);
            Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
            Assert.Equal(wrongSecret.Body.RootElement.ToString(), refused.Body.RootElement.ToString());
        }

        Assert.Equal(events, await EventCountAsync(database, a.TenantId));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Sign));
    }

    [Theory]
    [InlineData("post", null)]
    [InlineData("post", "")]
    [InlineData("basic", "")]
    public async Task Missing_or_empty_secret_gets_the_same_invalid_client_as_a_wrong_one(string method, string? secret)
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var wrong = await TokenAsync(host, HostA, client.ClientId, WithRandomPart(client.Secret), method);
        using var missing = await TokenAsync(host, HostA, client.ClientId, secret, method);

        Assert.Equal(HttpStatusCode.Unauthorized, missing.Status);
        Assert.Equal("invalid_client", missing.Error);
        Assert.Equal(wrong.Body.RootElement.ToString(), missing.Body.RootElement.ToString());
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
    }

    [Theory]
    [InlineData("revoked_at = now()")]
    [InlineData("expires_at = now() - interval '1 second'")]
    public async Task Revoked_or_expired_secret_is_invalid_client(string change)
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        await database.ExecuteAsync($"UPDATE client_secret SET {change} WHERE application_id = '{client.ApplicationId}'");
        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret);

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
    }

    [Fact]
    public async Task Secret_expiring_later_still_works()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        await database.ExecuteAsync($"UPDATE client_secret SET expires_at = now() + interval '1 hour' WHERE application_id = '{client.ApplicationId}'");
        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret);

        Assert.Equal(HttpStatusCode.OK, response.Status);
    }

    [Fact]
    public async Task Application_without_the_grant_is_unauthorized_client()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        await database.ExecuteAsync($"UPDATE application SET grant_types = '{{}}' WHERE id = '{client.ApplicationId}'");
        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("unauthorized_client", response.Error);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("authorization_code")]
    [InlineData("refresh_token")]
    [InlineData("urn:ietf:params:oauth:grant-type:device_code")]
    public async Task Any_other_grant_type_is_unsupported(string grant)
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret, grant: grant);

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("unsupported_grant_type", response.Error);
    }

    [Theory]
    [InlineData("resource", "https://api.example.test/")]
    [InlineData("audience", "management")]
    [InlineData("audience", ProtocolContract.PlaceholderAudience)]
    public async Task A_requested_audience_or_resource_is_invalid_target(string name, string value)
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret, extra: (name, value));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_target", response.Error);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Sign));
    }

    [Fact]
    public async Task A_requested_scope_is_invalid_scope()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret, extra: ("scope", "openid"));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal("invalid_scope", response.Error);
    }

    [Fact]
    public async Task Another_Tenants_valid_credential_is_refused_and_always_logged_in_the_probed_Tenant_only()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        var eventsA = await EventCountAsync(database, a.TenantId);

        foreach (var method in new[] { "basic", "post" })
        {
            using var refused = await TokenAsync(host, HostB, client.ClientId, client.Secret, method);
            Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
            Assert.Equal("invalid_client", refused.Error);
        }

        Assert.Equal(2L, await RejectionsAsync(database, b.TenantId));
        Assert.Equal(eventsA, await EventCountAsync(database, a.TenantId));
        await AssertRejectionsNameNothingOfAsync(database, b.TenantId, a.TenantId, client.ClientId);

        // An authenticated attempt is never only counted.
        Assert.Equal(0L, await MismatchesAsync(database, b.TenantId, UnknownSource));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));

        // The same credential still works at its own Tenant.
        using var own = await TokenAsync(host, HostA, client.ClientId, client.Secret);
        Assert.Equal(HttpStatusCode.OK, own.Status);
    }

    [Fact]
    public async Task Another_Tenants_valid_credential_asking_for_a_resource_is_still_logged_in_the_probed_Tenant()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var refused = await TokenAsync(host, HostB, client.ClientId, client.Secret, extra: ("resource", "https://api.example.test/"));

        Assert.True(refused.Error is "invalid_client" or "invalid_target", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(1L, await RejectionsAsync(database, b.TenantId));
        Assert.Equal(0L, await RejectionsAsync(database, a.TenantId));
    }

    [Fact]
    public async Task Another_Tenants_prefix_with_a_wrong_secret_is_counted_and_logged_once_per_source_per_hour()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        var guess = WithRandomPart(client.Secret);

        for (var i = 0; i < 3; i++)
        {
            using var refused = await TokenAsync(host, HostB, client.ClientId, guess, source: "203.0.113.7");
            Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
            Assert.Equal("invalid_client", refused.Error);
        }

        Assert.Equal(1L, await RejectionsAsync(database, b.TenantId));
        Assert.Equal(3L, await MismatchesAsync(database, b.TenantId, "203.0.113.7"));
        Assert.Equal(0L, await RejectionsAsync(database, a.TenantId));
        await AssertRejectionsNameNothingOfAsync(database, b.TenantId, a.TenantId, client.ClientId);

        // Another source is logged on its own first attempt.
        using (var other = await TokenAsync(host, HostB, client.ClientId, guess, source: "198.51.100.9"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, other.Status);
        }

        Assert.Equal(2L, await RejectionsAsync(database, b.TenantId));

        // Once the hour has passed, the first source is logged again.
        await database.BackdateAsync(
            $"UPDATE tenant_attempt SET window_start = window_start - interval '61 minutes' WHERE tenant_id = '{b.TenantId}' AND policy = '{AuthenticationContract.CrossTenantMismatchLogPolicy.Code}'");
        using (var later = await TokenAsync(host, HostB, client.ClientId, guess, source: "203.0.113.7"))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, later.Status);
        }

        Assert.Equal(3L, await RejectionsAsync(database, b.TenantId));
    }

    [Theory]
    [InlineData("no-dot-at-all-but-long-enough-to-look-real")]
    [InlineData("ten_notapublicid.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")]
    [InlineData(".starts-with-a-dot")]
    public async Task Garbage_prefix_is_invalid_client_and_counted_as_unauthenticated(string secret)
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostB, client.ClientId, secret, source: "192.0.2.10");

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("invalid_client", response.Error);
        Assert.Equal(1L, await MismatchesAsync(database, b.TenantId, "192.0.2.10"));
        Assert.Equal(1L, await RejectionsAsync(database, b.TenantId));
    }

    [Fact]
    public async Task Sixty_first_request_from_one_source_is_429_with_Retry_After_and_another_source_still_works()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        // Cheap requests count the same: every request is counted before anything else happens.
        for (var i = 0; i < SecurityLimits.TokenRequestSourceAttempts; i++)
        {
            using var counted = await TokenAsync(host, HostA, client.ClientId, client.Secret, grant: "password", source: "203.0.113.20");
            Assert.Equal("unsupported_grant_type", counted.Error);
        }

        using var limited = await TokenAsync(host, HostA, client.ClientId, client.Secret, source: "203.0.113.20");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
        Assert.Equal("temporarily_unavailable", limited.Error);
        Assert.False(limited.Body.RootElement.TryGetProperty("access_token", out _));
        var retryAfter = Assert.Single(limited.Headers.GetValues("Retry-After"));
        Assert.InRange(int.Parse(retryAfter, System.Globalization.CultureInfo.InvariantCulture), 1, (int)SecurityLimits.TokenRequestWindow.TotalSeconds);

        // The count was committed, and nothing else was written for the refused request.
        Assert.Equal(
            SecurityLimits.TokenRequestSourceAttempts + 1,
            await AttemptsAsync(database, a.TenantId, AuthenticationContract.TokenRequestSourcePolicy.Code, "203.0.113.20"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));

        // An IPv6 source is counted by its /64, and is another source.
        using var other = await TokenAsync(host, HostA, client.ClientId, client.Secret, source: "2001:db8:1:2::5");
        Assert.Equal(HttpStatusCode.OK, other.Status);
        Assert.Equal(1, await AttemptsAsync(database, a.TenantId, AuthenticationContract.TokenRequestSourcePolicy.Code, "2001:db8:1:2::/64"));
    }

    [Fact]
    public async Task IPv4_mapped_IPv6_source_is_counted_as_its_IPv4_address()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using (var plain = await TokenAsync(host, HostA, client.ClientId, client.Secret, source: "203.0.113.20"))
        {
            Assert.Equal(HttpStatusCode.OK, plain.Status);
        }

        using (var mapped = await TokenAsync(host, HostA, client.ClientId, client.Secret, source: "::ffff:203.0.113.20"))
        {
            Assert.Equal(HttpStatusCode.OK, mapped.Status);
        }

        var policy = AuthenticationContract.TokenRequestSourcePolicy.Code;
        Assert.Equal(2, await AttemptsAsync(database, a.TenantId, policy, "203.0.113.20"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{a.TenantId}' AND policy = '{policy}'"));
    }

    [Fact]
    public async Task Tenant_limit_refuses_at_that_Tenant_only()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var clientA = await database.CreateClientAsync(a.TenantId);
        var clientB = await database.CreateClientAsync(b.TenantId);
        var limits = new TokenRequestLimits(
            new RateLimitPolicy(AuthenticationContract.TokenRequestTenantPolicy.Code, 3, SecurityLimits.TokenRequestWindow),
            AuthenticationContract.TokenRequestSourcePolicy);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, limits: limits);

        for (var i = 0; i < 3; i++)
        {
            using var allowed = await TokenAsync(host, HostA, clientA.ClientId, clientA.Secret, source: $"203.0.113.{30 + i}");
            Assert.Equal(HttpStatusCode.OK, allowed.Status);
        }

        using var limited = await TokenAsync(host, HostA, clientA.ClientId, clientA.Secret, source: "203.0.113.40");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
        Assert.Single(limited.Headers.GetValues("Retry-After"));

        using var otherTenant = await TokenAsync(host, HostB, clientB.ClientId, clientB.Secret, source: "203.0.113.40");
        Assert.Equal(HttpStatusCode.OK, otherTenant.Status);
    }

    [Fact]
    public async Task Hosted_in_one_Tenants_scope_cant_read_or_update_anothers_counters()
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using (var host = await ProtocolHost.StartAsync(database.Hosted, bao))
        {
            using var issued = await TokenAsync(host, HostA, client.ClientId, client.Secret);
            Assert.Equal(HttpStatusCode.OK, issued.Status);
        }

        Assert.True(await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{a.TenantId}'") > 0);

        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, b.TenantId, Cancellation);
        var context = scope.CreateCommandContext();
        Assert.Equal(0L, await ScalarAsync(context, "SELECT count(*) FROM tenant_attempt"));
        Assert.Equal(0, await ExecuteAsync(context, "UPDATE tenant_attempt SET attempts = 1000"));
        Assert.Equal(0L, await ScalarAsync(context, "SELECT count(*) FROM application"));
        Assert.Equal(0L, await ScalarAsync(context, "SELECT count(*) FROM client_secret"));
        Assert.Equal(0L, await ScalarAsync(context, "SELECT count(*) FROM token"));
    }

    [Fact]
    public async Task Tenant_with_no_current_key_issues_nothing_and_logs_no_secret()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        using var response = await TokenAsync(host, HostA, client.ClientId, client.Secret);

        Assert.Equal(HttpStatusCode.InternalServerError, response.Status);
        Assert.Equal("server_error", response.Error);
        Assert.False(response.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0, host.Custody.TotalCalls);
        Assert.DoesNotContain(host.Logs.Lines, l => l.Contains(client.Secret, StringComparison.Ordinal));
        Assert.DoesNotContain(host.Logs.Lines, l => l.Contains(client.Secret.Split('.')[1], StringComparison.Ordinal));

        // The runtime that was built is whole: discovery and JWKS still answer.
        using var jwks = await GetJsonAsync(host, HostA, ProtocolContract.JsonWebKeySetPath);
        Assert.Equal(0, jwks.RootElement.GetProperty("keys").GetArrayLength());
    }

    [Fact]
    public async Task Fifty_concurrent_requests_on_a_cold_runtime_all_get_tokens_from_one_build()
    {
        var (database, a, _) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        var responses = await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            TokenAsync(host, HostA, client.ClientId, client.Secret, source: $"198.51.100.{i + 1}")));
        try
        {
            Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.Status));
            Assert.Equal(50, responses.Select(r => r.AccessToken).Distinct(StringComparer.Ordinal).Count());
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        // One build: one public-key read per published key, one unwrap, and one signature per token.
        Assert.Equal((await database.KeyIdsAsync(a.TenantId, "signing")).Count, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.ReadPublicKey));
        Assert.Equal(1, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Decrypt));
        Assert.Equal(50, host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Sign));
        Assert.Equal(50L, await database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{a.TenantId}'"));
    }

    [Fact]
    public async Task A_token_row_for_an_unknown_Application_is_refused()
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, a.TenantId, Cancellation);

        var error = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(
            scope.CreateCommandContext(),
            $"INSERT INTO token (tenant_id, id, application_id, type, status, concurrency_token) VALUES ('{a.TenantId}', gen_random_uuid(), gen_random_uuid(), 'access_token', 'valid', gen_random_uuid())"));

        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, error.SqlState);
    }

    /// <summary>The User and Session an <c>"authorization"</c> row in Tenant <c>{0}</c> anchors to, so only its Application reference can fail.</summary>
    private const string SessionInB =
        """
        INSERT INTO "user" (tenant_id, id) VALUES ('{0}', '01900000-0000-7000-8000-0000000025a1');
        INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
          VALUES ('{0}', '01900000-0000-7000-8000-0000000025a2', '01900000-0000-7000-8000-0000000025a1', sha256('s'::bytea), '{{pwd}}', now(), now() + interval '1 hour', now() + interval '1 hour', now());
        """;

    [Theory]
    [InlineData("signin_transaction", "", "INSERT INTO signin_transaction (tenant_id, id, application_id, binding_hash, parameters, created_at, expires_at) VALUES ('{0}', gen_random_uuid(), '{1}', sha256(gen_random_uuid()::text::bytea), '{{}}', now(), now() + interval '1 minute')")]
    [InlineData("authorization", SessionInB, "INSERT INTO \"authorization\" (tenant_id, id, application_id, user_session_id, status, type, concurrency_token) VALUES ('{0}', gen_random_uuid(), '{1}', '01900000-0000-7000-8000-0000000025a2', 'valid', 'ad-hoc', gen_random_uuid())")]
    [InlineData("token", "", "INSERT INTO token (tenant_id, id, application_id, type, status, concurrency_token) VALUES ('{0}', gen_random_uuid(), '{1}', 'access_token', 'valid', gen_random_uuid())")]
    public async Task A_row_may_not_reference_another_Tenants_Application(string table, string setup, string insert)
    {
        var (database, a, b) = await TwoTenantsAsync();
        var client = await database.CreateClientAsync(a.TenantId);
        if (setup.Length > 0)
        {
            await database.ExecuteAsync(string.Format(System.Globalization.CultureInfo.InvariantCulture, setup, b.TenantId));
        }

        await using var source = NpgsqlDataSource.Create(database.Hosted);
        await using var scope = await TenantScope.BeginAsync(source, b.TenantId, Cancellation);

        var error = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(
            scope.CreateCommandContext(), string.Format(System.Globalization.CultureInfo.InvariantCulture, insert, b.TenantId, client.ApplicationId)));

        Assert.True(error.SqlState == PostgresErrorCodes.ForeignKeyViolation, $"{table}: {error.SqlState}");
        Assert.Equal($"{table}_application_fkey", error.ConstraintName);
    }

    /// <summary>The source TestServer requests have when a test names none.</summary>
    private const string UnknownSource = "unknown";

    private async Task<(ProtocolDatabase Database, ResolvedTenant A, ResolvedTenant B)> TwoTenantsAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        var b = await database.AddTenantAsync(HostB);
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(bao, b.TenantId));
        return (database, a, b);
    }

    /// <summary>The same secret, with a different random part: the right prefix, the wrong secret.</summary>
    private static string WithRandomPart(string secret) =>
        secret[..(secret.IndexOf('.', StringComparison.Ordinal) + 1)] + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    internal static async Task<TokenResponse> TokenAsync(
        ProtocolHost host,
        string tenantHost,
        string clientId,
        string? secret,
        string method = "basic",
        string grant = "client_credentials",
        (string Name, string Value)? extra = null,
        string? source = null)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = grant };
        if (method == "post")
        {
            form["client_id"] = clientId;
            if (secret is not null)
            {
                form["client_secret"] = secret;
            }
        }

        if (extra is { } parameter)
        {
            form[parameter.Name] = parameter.Value;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{tenantHost}{ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };

        if (method == "basic")
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret ?? string.Empty)}")));
        }

        if (source is not null)
        {
            request.Headers.TryAddWithoutValidation(ProtocolHost.SourceHeader, source);
        }

        var response = await host.Http.SendAsync(request, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return new TokenResponse(response, JsonDocument.Parse(body));
    }

    private static async Task<bool> VerifiesAsync(string token, JsonWebKeySet jwks, string issuer)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidIssuer = issuer,
            ValidAudience = ProtocolContract.PlaceholderAudience,
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidTypes = ["at+jwt"],
        });
        return result.IsValid;
    }

    private static async Task<JsonWebKeySet> JwksAsync(ProtocolHost host, string tenantHost)
    {
        using var document = await GetJsonAsync(host, tenantHost, ProtocolContract.JsonWebKeySetPath);
        return new JsonWebKeySet(document.RootElement.GetRawText());
    }

    private static async Task<JsonDocument> GetJsonAsync(ProtocolHost host, string tenantHost, string path)
    {
        using var response = await host.Http.GetAsync(new Uri($"http://{tenantHost}{path}"), Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }

    private static List<string?> Strings(JsonElement array) => [.. array.EnumerateArray().Select(e => e.GetString())];

    private static async Task<string> CurrentKidAsync(ProtocolDatabase database, Guid tenantId) =>
        await database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{tenantId}' AND purpose = 'signing' AND state = 'current'");

    /// <summary>How many of <paramref name="table"/>'s rows hold <paramref name="value"/> anywhere, searched by parameter.</summary>
    private static async Task<long> RowsHoldingAsync(ProtocolDatabase database, string table, string value)
    {
        await using var connection = new NpgsqlConnection(database.Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand($"SELECT count(*) FROM \"{table}\" r WHERE strpos(to_jsonb(r)::text, @value) > 0", connection);
        command.Parameters.AddWithValue("value", value);
        return (long)(await command.ExecuteScalarAsync(Cancellation))!;
    }

    private static Task<long> EventCountAsync(ProtocolDatabase database, Guid tenantId) =>
        database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenantId}'");

    private static Task<long> RejectionsAsync(ProtocolDatabase database, Guid tenantId) =>
        database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenantId}' AND type_code = '{Rejected}'");

    /// <summary>The probed Tenant's rejections are anonymous and name nothing of the Tenant that issued the credential.</summary>
    private static async Task AssertRejectionsNameNothingOfAsync(ProtocolDatabase database, Guid probed, Guid issuer, string clientId)
    {
        Assert.Equal(0L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{probed}' AND type_code = '{Rejected}' AND (actor_kind <> 'anonymous' OR actor_id IS NOT NULL OR target_kind IS NOT NULL OR target_id IS NOT NULL)"));
        foreach (var name in new[] { issuer.ToString(), PublicId.Format(PublicIdType.Tenant, issuer), clientId })
        {
            Assert.Equal(0L, await database.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event r WHERE tenant_id = '{probed}' AND strpos(to_jsonb(r)::text, '{name}') > 0"));
            Assert.Equal(0L, await database.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_detail r WHERE tenant_id = '{probed}' AND strpos(to_jsonb(r)::text, '{name}') > 0"));
        }
    }

    private static async Task<long> MismatchesAsync(ProtocolDatabase database, Guid tenantId, string source) =>
        await AttemptsAsync(database, tenantId, AuthenticationContract.CrossTenantMismatchPolicy.Code, source);

    private static async Task<int> AttemptsAsync(ProtocolDatabase database, Guid tenantId, string policy, string subject)
    {
        await using var connection = new NpgsqlConnection(database.Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT coalesce(max(attempts), 0) FROM tenant_attempt WHERE tenant_id = @tenant AND policy = @policy AND subject_hash = sha256(convert_to(@subject, 'UTF8'))",
            connection);
        command.Parameters.AddWithValue("tenant", tenantId);
        command.Parameters.AddWithValue("policy", policy);
        command.Parameters.AddWithValue("subject", subject);
        return (int)(await command.ExecuteScalarAsync(Cancellation))!;
    }

    private static async Task<long> ScalarAsync(CommandContext context, string sql)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        return (long)(await command.ExecuteScalarAsync(Cancellation))!;
    }

    private static async Task<int> ExecuteAsync(CommandContext context, string sql)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteNonQueryAsync(Cancellation);
    }
}

/// <summary>A token endpoint response, read once: its status, headers and JSON body.</summary>
internal sealed class TokenResponse(HttpResponseMessage response, JsonDocument body) : IDisposable
{
    public HttpStatusCode Status => response.StatusCode;

    public HttpResponseHeaders Headers => response.Headers;

    public JsonDocument Body { get; } = body;

    public string? Error => Body.RootElement.TryGetProperty("error", out var error) ? error.GetString() : null;

    public string AccessToken => Body.RootElement.GetProperty("access_token").GetString()!;

    public void Dispose()
    {
        Body.Dispose();
        response.Dispose();
    }
}
