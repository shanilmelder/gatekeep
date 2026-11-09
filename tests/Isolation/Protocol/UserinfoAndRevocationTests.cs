using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 2.11 (FR-23, RFC 7009, AD-9, AD-13): each Tenant's userinfo and revocation endpoints, through the
/// real Tenant resolution and Protocol registration, against the real PostgreSQL as <c>gk_hosted</c> and the
/// real OpenBao through the <c>host-hosted</c> login, with the test-only sign-in. One test or more per row of
/// the story's I/O matrix (the <c>prompt=login</c> and <c>max_age</c> rows are in <see cref="AuthorizationCodeTests"/>).
/// No assertion prints a code, verifier, secret or token: values are compared with <c>Assert.True(a == b, …)</c>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class UserinfoAndRevocationTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.userinfo.test";
    private const string HostB = "beta.userinfo.test";
    private const string Callback = CodeFlowSetup.Callback;
    private const string Offline = "openid offline_access";
    private const string RefreshType = "urn:ietf:params:oauth:token-type:refresh_token";
    private const string Revoked = "sessions.access.revoked";
    private const string CrossTenantRejected = "protocol.client.cross_tenant_rejected";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Userinfo_answers_exactly_the_Users_sub_for_a_code_flow_access_token()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);
        Assert.Contains("openid", new JsonWebToken(tokens.Access).GetClaim("scope").Value.Split(' '));

        var tokenRows = await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token");
        var events = await flow.Database.ScalarAsync<long>("SELECT count(*) FROM audit_event");

        using var response = await UserinfoAsync(host, HostA, tokens.Access);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.Equal("application/json", response.ContentType);
        AssertOnlySub(response.Body, flow.UserA);

        // It reads the token alone: nothing is written.
        Assert.Equal(tokenRows, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(events, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM audit_event"));
    }

    [Fact]
    public async Task Userinfo_by_POST_answers_the_same()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using var response = await UserinfoAsync(host, HostA, tokens.Access, post: true);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        AssertOnlySub(response.Body, flow.UserA);
    }

    [Fact]
    public async Task Userinfo_takes_the_bearer_from_the_header_only()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        foreach (var post in new[] { false, true })
        {
            using var response = await UserinfoAsync(host, HostA, bearer: null, post: post, parameter: tokens.Access);
            Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
            Assert.StartsWith("Bearer", response.WwwAuthenticate, StringComparison.Ordinal);
            Assert.DoesNotContain("usr_", response.Body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Userinfo_refuses_an_ID_token_as_invalid_token()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using var response = await UserinfoAsync(host, HostA, tokens.Id);

        AssertInvalidToken(response);
    }

    [Fact]
    public async Task Userinfo_refuses_an_unsigned_alg_none_token()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        // The real token's claims, with a header naming no algorithm and no signature at all.
        var payload = tokens.Access.Split('.')[1];
        foreach (var unsigned in new[] { $"{Header("{\"alg\":\"none\",\"typ\":\"at+jwt\"}")}.{payload}.", $"{Header("{\"alg\":\"none\",\"typ\":\"at+jwt\"}")}.{payload}" })
        {
            using var response = await UserinfoAsync(host, HostA, unsigned);
            AssertInvalidToken(response);
        }
    }

    [Fact]
    public async Task Userinfo_refuses_an_HS256_token_even_one_keyed_with_the_Tenants_public_key()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);
        var access = new JsonWebToken(tokens.Access);
        var jwks = await CodeFlow.JwksAsync(host, HostA);
        var modulus = Base64UrlEncoder.DecodeBytes(jwks.Keys.Single(k => k.Kid == access.Kid).N);

        // The real claims, MACed with a random key and with the RSA public key's modulus as the HMAC key.
        foreach (var key in new[] { RandomNumberGenerator.GetBytes(32), modulus })
        {
            var signed = $"{Header($"{{\"alg\":\"HS256\",\"typ\":\"at+jwt\",\"kid\":\"{access.Kid}\"}}")}.{tokens.Access.Split('.')[1]}";
            var mac = Base64UrlEncoder.Encode(HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(signed)));
            using var response = await UserinfoAsync(host, HostA, $"{signed}.{mac}");
            AssertInvalidToken(response);
        }
    }

    [Fact]
    public async Task Userinfo_refuses_another_Tenants_access_token()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using var atB = await UserinfoAsync(host, HostB, tokens.Access);
        AssertInvalidToken(atB);

        // The same token still answers at its own Tenant.
        using var atA = await UserinfoAsync(host, HostA, tokens.Access);
        Assert.Equal(HttpStatusCode.OK, atA.Status);
    }

    [Fact]
    public async Task Userinfo_refuses_a_Client_Credentials_token_which_has_no_User()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var machine = await flow.Database.CreateClientAsync(flow.A.TenantId);
        await using var host = await flow.StartHostAsync();

        using var issued = await ClientCredentialsTests.TokenAsync(host, HostA, machine.ClientId, machine.Secret);
        Assert.Equal(HttpStatusCode.OK, issued.Status);

        using var response = await UserinfoAsync(host, HostA, issued.AccessToken);
        AssertInvalidToken(response);
    }

    [Fact]
    public async Task Userinfo_refuses_an_access_token_past_its_15_minutes()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);
        var tokens = await TokensAsync(host, flow);

        time.Advance(SecurityLimits.DefaultAccessTokenLifetime + TimeSpan.FromSeconds(1));

        using var response = await UserinfoAsync(host, HostA, tokens.Access);
        AssertInvalidToken(response);
    }

    [Fact]
    public async Task Userinfo_with_no_token_is_401_with_a_bare_Bearer_challenge()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var response = await UserinfoAsync(host, HostA, bearer: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.StartsWith("Bearer", response.WwwAuthenticate, StringComparison.Ordinal);

        // RFC 6750 §3.1: a request with no token gets no error code.
        Assert.DoesNotContain("invalid_token", response.WwwAuthenticate, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("a.b.c")]
    public async Task Userinfo_refuses_a_garbage_token_as_invalid_token(string garbage)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var response = await UserinfoAsync(host, HostA, garbage);

        AssertInvalidToken(response);
    }

    /// <summary>
    /// No token Gatekeep issues today lacks <c>openid</c> (a code flow requires it), so a test handler drops
    /// the verified token's scopes before Gatekeep's check, as a token for an API scope only (Story 3.7) would be.
    /// </summary>
    [Fact]
    public async Task Userinfo_refuses_a_token_without_openid_as_insufficient_scope()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync(configure: services =>
            services.AddOpenIddict().AddServer(server => server.AddEventHandler<ValidateUserInfoRequestContext>(handler => handler
                .UseInlineHandler(context =>
                {
                    context.AccessTokenPrincipal?.RemoveClaims(OpenIddictConstants.Claims.Private.Scope);
                    return ValueTask.CompletedTask;
                })
                .SetOrder(OpenIddictServerHandlers.UserInfo.ValidateAuthentication.Descriptor.Order + 100))));
        var tokens = await TokensAsync(host, flow);

        using var response = await UserinfoAsync(host, HostA, tokens.Access);

        Assert.Equal(HttpStatusCode.Forbidden, response.Status);
        Assert.StartsWith("Bearer", response.WwwAuthenticate, StringComparison.Ordinal);
        Assert.Contains("error=\"insufficient_scope\"", response.WwwAuthenticate, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Userinfo_still_answers_for_an_unexpired_access_token_after_its_family_is_revoked()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        // A logout, through the one revocation path: the access token's row reads revoked.
        await RevokeSessionAsync(flow);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));

        // Access tokens aren't revocable (AD-13): it answers until it expires.
        using var response = await UserinfoAsync(host, HostA, tokens.Access);
        Assert.Equal(HttpStatusCode.OK, response.Status);
        AssertOnlySub(response.Body, flow.UserA);
    }

    [Theory]
    [InlineData("basic")]
    [InlineData("post")]
    public async Task The_owning_client_revokes_its_refresh_token_and_its_whole_family(string method)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using (var revoked = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh, method: method))
        {
            Assert.Equal(HttpStatusCode.OK, revoked.Status);
            Assert.Equal(string.Empty, revoked.Body);
            Assert.True(revoked.NoStore, "The revocation response isn't no-store.");
        }

        // The family and every token of it are revoked, by one event naming the client as Actor; the Session lives.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked' AND type <> 'urn:openiddict:params:oauth:token-type:authorization_code'"));
        Assert.Equal(1L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}' AND actor_kind = 'client' AND actor_id = '{flow.ClientA.ApplicationId}'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));

        // The refresh token no longer refreshes.
        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
    }

    [Fact]
    public async Task Revoking_a_rotated_family_member_revokes_it_and_the_family()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);
        var r2 = await RefreshOkAsync(host, flow, tokens.Refresh);

        using (var revoked = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r2))
        {
            Assert.Equal(HttpStatusCode.OK, revoked.Status);
        }

        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(0L, await RefreshRowsAsync(flow, "status = 'valid'"));
        Assert.Equal(1L, await RevocationEventsAsync(flow));

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r2);
        Assert.Equal("invalid_grant", refused.Error);
    }

    [Fact]
    public async Task Revoking_twice_answers_200_and_writes_nothing_the_second_time()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        foreach (var _ in new[] { 1, 2 })
        {
            using var revoked = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh);
            Assert.Equal(HttpStatusCode.OK, revoked.Status);
            Assert.Equal(string.Empty, revoked.Body);
        }

        Assert.Equal(1L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task Another_client_of_the_Tenant_revokes_nothing_and_gets_200()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var other = await flow.Database.CreateWebClientAsync(flow.A.TenantId, [Callback], "Other web client");
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using (var byOther = await RevokeAsync(host, HostA, other.ClientId, other.Secret, tokens.Refresh))
        {
            Assert.Equal(HttpStatusCode.OK, byOther.Status);
            Assert.Equal(string.Empty, byOther.Body);
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        await RefreshOkAsync(host, flow, tokens.Refresh);
    }

    [Theory]
    [InlineData("wrong")]
    [InlineData("missing")]
    [InlineData("unknown-client")]
    public async Task Bad_client_authentication_is_invalid_client_as_at_the_token_endpoint(string how)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        var clientId = how == "unknown-client" ? "no-such-client" : flow.ClientA.ClientId;
        var secret = how switch
        {
            "wrong" => flow.ClientA.Secret[..(flow.ClientA.Secret.IndexOf('.', StringComparison.Ordinal) + 1)] + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)),
            "missing" => null,
            _ => flow.ClientA.Secret,
        };

        using var refused = await RevokeAsync(host, HostA, clientId, secret, tokens.Refresh, method: "post");

        Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
        Assert.Equal("invalid_client", refused.Error);
        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
    }

    [Fact]
    public async Task Another_Tenants_client_credential_at_revocation_is_classified_and_logged_as_at_the_token_endpoint()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        // A's real credential at B: authenticated at A, so always logged in B's Log, anonymous.
        using var refused = await RevokeAsync(host, HostB, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
        Assert.Equal("invalid_client", refused.Error);
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.B.TenantId}' AND type_code = '{CrossTenantRejected}' AND actor_kind = 'anonymous' AND target_id IS NULL"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
    }

    /// <summary>The Story 1.31 cross-Tenant case for a refresh token presented for revocation (FR-8, AD-9).</summary>
    [Fact]
    public async Task Tenant_As_refresh_token_revoked_at_Tenant_B_is_200_refused_before_lookup_and_revokes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientB = await flow.Database.CreateWebClientAsync(flow.B.TenantId, [Callback]);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using (var byB = await RevokeAsync(host, HostB, clientB.ClientId, clientB.Secret, tokens.Refresh))
        {
            Assert.Equal(HttpStatusCode.OK, byB.Status);
            Assert.Equal(string.Empty, byB.Body);
        }

        // An unauthenticated cross-Tenant mismatch: one event in B's Log, anonymous, naming nothing of A, and none in A's.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.B.TenantId}' AND type_code = '{CrossTenantRejected}' AND actor_kind = 'anonymous' AND target_id IS NULL"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{CrossTenantRejected}'"));
        foreach (var name in new[] { flow.A.TenantId.ToString(), PublicId.Format(PublicIdType.Tenant, flow.A.TenantId), flow.ClientA.ClientId })
        {
            Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event r WHERE tenant_id = '{flow.B.TenantId}' AND strpos(to_jsonb(r)::text, '{name}') > 0"));
        }

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Revoked}'"));

        // A's refresh token is untouched, and still refreshes at A.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        await RefreshOkAsync(host, flow, tokens.Refresh);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData(".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task A_garbage_or_foreign_prefixed_token_is_200_counted_as_a_mismatch_and_revokes_nothing(string garbage)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using (var response = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, garbage, source: "192.0.2.30"))
        {
            Assert.Equal(HttpStatusCode.OK, response.Status);
            Assert.Equal(string.Empty, response.Body);
        }

        Assert.Equal(1, await AttemptsAsync(flow.Database, flow.A.TenantId, AuthenticationContract.CrossTenantMismatchPolicy.Code, "192.0.2.30"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{CrossTenantRejected}' AND actor_kind = 'anonymous'"));
        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
    }

    [Fact]
    public async Task An_unknown_refresh_token_of_the_Tenant_is_200_and_revokes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);
        var unknown = PublicId.Format(PublicIdType.Tenant, flow.A.TenantId) + "." + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        using (var response = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, unknown))
        {
            Assert.Equal(HttpStatusCode.OK, response.Status);
            Assert.Equal(string.Empty, response.Body);
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{CrossTenantRejected}'"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
    }

    [Fact]
    public async Task A_redeemed_refresh_token_is_200_and_is_never_taken_for_reuse()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);
        var r2 = await RefreshOkAsync(host, flow, tokens.Refresh);

        // R1 now reads redeemed: revoking it revokes nothing, and its family isn't revoked as reuse.
        using (var response = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh))
        {
            Assert.Equal(HttpStatusCode.OK, response.Status);
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        await RefreshOkAsync(host, flow, r2);
    }

    [Fact]
    public async Task An_expired_refresh_token_is_200_and_revokes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);
        var tokens = await TokensAsync(host, flow);

        time.Advance(SecurityLimits.RefreshTokenInactivityLifetime + TimeSpan.FromSeconds(1));

        using (var response = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh))
        {
            Assert.Equal(HttpStatusCode.OK, response.Status);
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
    }

    [Fact]
    public async Task An_access_or_ID_token_is_unsupported_token_type_and_stays_valid()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        foreach (var (token, hint) in new[] { (tokens.Access, "access_token"), (tokens.Access, (string?)null), (tokens.Id, null) })
        {
            using var refused = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, token, hint: hint);
            Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
            Assert.Equal("unsupported_token_type", refused.Error);
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));

        // Access tokens aren't revocable (AD-13): it still answers at userinfo.
        using var userinfo = await UserinfoAsync(host, HostA, tokens.Access);
        Assert.Equal(HttpStatusCode.OK, userinfo.Status);
    }

    [Theory]
    [InlineData("access_token")]
    [InlineData("refresh_token")]
    [InlineData("something_else")]
    public async Task The_token_type_hint_is_only_a_hint_and_a_wrong_one_still_revokes(string hint)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using (var revoked = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh, hint: hint))
        {
            Assert.Equal(HttpStatusCode.OK, revoked.Status);
        }

        Assert.Equal(1L, await RevocationEventsAsync(flow));
        Assert.Equal(0L, await RefreshRowsAsync(flow, "status = 'valid'"));
    }

    [Fact]
    public async Task The_sixty_first_revocation_from_one_source_is_429_with_Retry_After_and_another_source_still_revokes()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        // Every revocation is counted before anything else happens, under the token endpoint's limits.
        for (var i = 0; i < SecurityLimits.TokenRequestSourceAttempts; i++)
        {
            using var counted = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, "garbage", source: "203.0.113.70");
            Assert.Equal(HttpStatusCode.OK, counted.Status);
        }

        using (var limited = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh, source: "203.0.113.70"))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
            Assert.Equal("temporarily_unavailable", limited.Error);
            var retryAfter = Assert.Single(limited.Headers.GetValues("Retry-After"));
            Assert.InRange(int.Parse(retryAfter, System.Globalization.CultureInfo.InvariantCulture), 1, (int)SecurityLimits.TokenRequestWindow.TotalSeconds);
        }

        // Refused before its transaction: nothing revoked; another source revokes.
        Assert.Equal(
            SecurityLimits.TokenRequestSourceAttempts + 1,
            await AttemptsAsync(flow.Database, flow.A.TenantId, AuthenticationContract.TokenRequestSourcePolicy.Code, "203.0.113.70"));
        Assert.Equal(0L, await RevocationEventsAsync(flow));
        using var other = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh, source: "203.0.113.71");
        Assert.Equal(HttpStatusCode.OK, other.Status);
        Assert.Equal(1L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task No_log_line_holds_a_revoked_refresh_token_or_a_userinfo_bearer()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var tokens = await TokensAsync(host, flow);

        using (var userinfo = await UserinfoAsync(host, HostA, tokens.Access))
        {
            Assert.Equal(HttpStatusCode.OK, userinfo.Status);
        }

        using (var revoked = await RevokeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh))
        {
            Assert.Equal(HttpStatusCode.OK, revoked.Status);
        }

        foreach (var value in new[] { tokens.Refresh, RandomPart(tokens.Refresh) })
        {
            Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "token", value));
            Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "audit_event", value));
        }

        Assert.DoesNotContain(host.Logs.Lines, line => line.Contains(RandomPart(tokens.Refresh), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Discovery_advertises_userinfo_and_revocation_with_the_two_secret_methods()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var document = await CodeFlow.GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        var root = document.RootElement;

        Assert.Equal($"{flow.A.Issuer}connect/userinfo", root.GetProperty("userinfo_endpoint").GetString());
        Assert.Equal($"{flow.A.Issuer}connect/revoke", root.GetProperty("revocation_endpoint").GetString());
        Assert.Equal(
            ["client_secret_basic", "client_secret_post"],
            root.GetProperty("revocation_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()).Order(StringComparer.Ordinal));
        Assert.False(root.TryGetProperty("introspection_endpoint", out _));
        Assert.False(root.TryGetProperty("end_session_endpoint", out _));
    }

    /// <summary>A code flow with <paramref name="scope"/> for the setup's User and web client in Tenant A, exchanged.</summary>
    internal static async Task<(string Access, string Id, string Refresh)> TokensAsync(ProtocolHost host, CodeFlowSetup flow, string tenantHost = HostA, string scope = Offline)
    {
        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, tenantHost, flow.ClientA.ClientId, Callback, pkce, flow.UserA, scope: scope);
        using var issued = await CodeFlow.ExchangeAsync(host, tenantHost, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        return (issued.AccessToken, issued.Body.RootElement.GetProperty("id_token").GetString()!, issued.RefreshToken);
    }

    /// <summary>
    /// Calls userinfo on <paramref name="tenantHost"/>: <paramref name="bearer"/> in the <c>Authorization</c>
    /// header, and <paramref name="parameter"/> as an <c>access_token</c> in the query or form.
    /// </summary>
    internal static async Task<EndpointResponse> UserinfoAsync(
        ProtocolHost host, string tenantHost, string? bearer, bool post = false, string? parameter = null)
    {
        var uri = $"http://{tenantHost}{ProtocolContract.UserinfoPath}";
        using var request = post
            ? new HttpRequestMessage(HttpMethod.Post, new Uri(uri))
            {
                Content = new FormUrlEncodedContent(parameter is null ? [] : new Dictionary<string, string> { ["access_token"] = parameter }),
            }
            : new HttpRequestMessage(HttpMethod.Get, new Uri(parameter is null ? uri : $"{uri}?access_token={Uri.EscapeDataString(parameter)}"));
        if (bearer is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {bearer}");
        }

        return await EndpointResponse.ReadAsync(await host.Http.SendAsync(request, Cancellation));
    }

    /// <summary>Revokes <paramref name="token"/> at <paramref name="tenantHost"/>, authenticating the client by Basic or in the form.</summary>
    internal static async Task<EndpointResponse> RevokeAsync(
        ProtocolHost host,
        string tenantHost,
        string clientId,
        string? secret,
        string token,
        string? hint = null,
        string method = "basic",
        string? source = null)
    {
        var form = new Dictionary<string, string> { ["token"] = token };
        if (hint is not null)
        {
            form["token_type_hint"] = hint;
        }

        if (method == "post")
        {
            form["client_id"] = clientId;
            if (secret is not null)
            {
                form["client_secret"] = secret;
            }
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{tenantHost}{ProtocolContract.RevocationPath}"))
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

        return await EndpointResponse.ReadAsync(await host.Http.SendAsync(request, Cancellation));
    }

    private static void AssertOnlySub(string body, Guid userId)
    {
        using var document = JsonDocument.Parse(body);
        var properties = document.RootElement.EnumerateObject().Select(p => p.Name).ToList();
        Assert.Equal(["sub"], properties);
        Assert.Equal(PublicId.Format(PublicIdType.User, userId), document.RootElement.GetProperty("sub").GetString());
    }

    private static void AssertInvalidToken(EndpointResponse response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.StartsWith("Bearer", response.WwwAuthenticate, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", response.WwwAuthenticate, StringComparison.Ordinal);
        Assert.DoesNotContain("usr_", response.Body, StringComparison.Ordinal);
    }

    private static string Header(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));

    private static async Task<string> RefreshOkAsync(ProtocolHost host, CodeFlowSetup flow, string refreshToken)
    {
        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        return refreshed.RefreshToken;
    }

    /// <summary>Ends the setup's one Session through the one revocation path, as a logout would.</summary>
    private static async Task RevokeSessionAsync(CodeFlowSetup flow)
    {
        var sessionId = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM user_session WHERE tenant_id = '{flow.A.TenantId}'");
        await using var source = NpgsqlDataSource.Create(flow.Database.Hosted);
        await using var scope = await Gatekeep.Kernel.Persistence.TenantScope.BeginAsync(source, flow.A.TenantId, Cancellation);
        await SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System).RevokeAccessAsync(
            scope.CreateCommandContext(), new RevocationScope.Session(sessionId), null, RevocationReason.Logout, Actor.User(flow.UserA), Cancellation);
        await scope.CommitAsync(Cancellation);
    }

    private static string RandomPart(string referenceId) => referenceId[(referenceId.IndexOf('.', StringComparison.Ordinal) + 1)..];

    private static Task<long> RefreshRowsAsync(CodeFlowSetup flow, string condition) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND type = '{RefreshType}' AND ({condition})");

    private static Task<long> RevocationEventsAsync(CodeFlowSetup flow) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}'");

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
}

/// <summary>A userinfo or revocation response, read once: its status, headers and body, which may be empty.</summary>
internal sealed class EndpointResponse : IDisposable
{
    private readonly HttpResponseMessage _response;

    private EndpointResponse(HttpResponseMessage response, string body)
    {
        _response = response;
        Body = body;
    }

    public HttpStatusCode Status => _response.StatusCode;

    public HttpResponseHeaders Headers => _response.Headers;

    public string Body { get; }

    public string? ContentType => _response.Content.Headers.ContentType?.MediaType;

    public bool NoStore => _response.Headers.CacheControl?.NoStore == true;

    /// <summary>The <c>WWW-Authenticate</c> header as sent, unparsed; empty when there is none.</summary>
    public string WwwAuthenticate =>
        _response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out var values) ? string.Join(", ", values) : string.Empty;

    public string? Error
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Body))
            {
                return null;
            }

            using var document = JsonDocument.Parse(Body);
            return document.RootElement.TryGetProperty("error", out var error) ? error.GetString() : null;
        }
    }

    public static async Task<EndpointResponse> ReadAsync(HttpResponseMessage response) =>
        new(response, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

    public void Dispose() => _response.Dispose();
}
