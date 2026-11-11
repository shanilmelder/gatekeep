using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using OpenIddict.Abstractions;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 2.9 (FR-13, FR-23, FR-47, AD-8, AD-9, AD-13): the authorization code flow with S256 PKCE on each
/// Tenant's authorization and token endpoints, through the real Tenant resolution and Protocol
/// registration, against the real PostgreSQL as <c>gk_hosted</c> and the real OpenBao through the
/// <c>host-hosted</c> login. The test host signs Users in with the test-only authenticator; the release
/// build's sign-in completes nothing. One test or more per row of the story's I/O matrix. No assertion
/// prints a code, verifier, secret or token: values are compared with <c>Assert.True(a == b, …)</c>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class AuthorizationCodeTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.code.test";
    private const string HostB = "beta.code.test";
    private const string HostC = "bare.code.test";
    private const string Callback = "https://client.code.test/callback";
    private const string OtherCallback = "https://client.code.test/other-callback";
    private const string Revoked = "sessions.access.revoked";
    private const string CrossTenantRejected = "protocol.client.cross_tenant_rejected";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Web_client_gets_a_code_with_iss_and_exchanges_it_for_tokens_that_verify_only_with_its_Tenants_JWKS()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA, state: "state-1", nonce: "nonce-1");

        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = authorize.Headers.Location!;
        Assert.Equal(Callback, location.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("state-1", query["state"].ToString());
        Assert.Equal(flow.A.Issuer, query["iss"].ToString());
        Assert.False(query.ContainsKey("error"));

        var code = query["code"].ToString();
        Assert.True(code.StartsWith(PublicId.Format(PublicIdType.Tenant, flow.A.TenantId) + ".", StringComparison.Ordinal), "The code isn't Tenant A's reference ID.");
        Assert.True(Base64UrlEncoder.DecodeBytes(code[(code.IndexOf('.', StringComparison.Ordinal) + 1)..]).Length == 32, "The code's random part isn't 256 bits.");

        // One Token Family, anchored to the Session the sign-in started, and the code held only as its hash.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM \"authorization\" a JOIN user_session s ON s.tenant_id = a.tenant_id AND s.id = a.user_session_id WHERE a.tenant_id = '{flow.A.TenantId}' AND s.user_id = '{flow.UserA}' AND a.type = 'ad-hoc' AND a.status = 'valid'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND type = 'urn:openiddict:params:oauth:token-type:authorization_code' AND reference_id IS NOT NULL AND strpos(reference_id, '.') = 0"));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "token", code));

        using var token = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, token.Status);
        Assert.Equal((int)SecurityLimits.DefaultAccessTokenLifetime.TotalSeconds, token.Body.RootElement.GetProperty("expires_in").GetInt32());
        Assert.False(token.Body.RootElement.TryGetProperty("refresh_token", out _));

        var subject = PublicId.Format(PublicIdType.User, flow.UserA);
        var access = new JsonWebToken(token.AccessToken);
        Assert.Equal("at+jwt", access.Typ);
        Assert.Equal(SecurityAlgorithms.RsaSha256, access.Alg);
        Assert.Equal(await CodeFlow.CurrentKidAsync(flow.Database, flow.A.TenantId), access.Kid);
        Assert.Equal(subject, access.Subject);
        Assert.Equal([ProtocolContract.PlaceholderAudience], access.Audiences);

        var idToken = token.Body.RootElement.GetProperty("id_token").GetString()!;
        var id = new JsonWebToken(idToken);
        Assert.Equal(SecurityAlgorithms.RsaSha256, id.Alg);
        Assert.Equal(subject, id.Subject);
        Assert.Equal("nonce-1", id.GetClaim("nonce").Value);
        Assert.Equal(SecurityLimits.DefaultIdentityTokenLifetime, id.ValidTo - id.IssuedAt);
        Assert.Equal([flow.ClientA.ClientId], id.Audiences);
        var sessionId = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND user_id = '{flow.UserA}'");
        Assert.Equal(PublicId.Format(PublicIdType.Session, sessionId), id.GetClaim("sid").Value);
        var authTime = await flow.Database.ScalarAsync<DateTime>($"SELECT auth_time FROM user_session WHERE id = '{sessionId}'");
        Assert.Equal(new DateTimeOffset(authTime, TimeSpan.Zero).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), id.GetClaim("auth_time").Value);
        Assert.Contains("\"amr\":[\"test\"]", Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(idToken.Split('.')[1])), StringComparison.Ordinal);
        Assert.False(access.TryGetClaim("sid", out _));

        var jwksA = await CodeFlow.JwksAsync(host, HostA);
        var jwksB = await CodeFlow.JwksAsync(host, HostB);
        Assert.True(await CodeFlow.VerifiesAsync(token.AccessToken, jwksA, flow.A.Issuer, ProtocolContract.PlaceholderAudience, "at+jwt"), "A's access token doesn't verify with A's JWKS.");
        Assert.False(await CodeFlow.VerifiesAsync(token.AccessToken, jwksB, flow.A.Issuer, ProtocolContract.PlaceholderAudience, "at+jwt"), "A's access token verifies with B's JWKS.");
        Assert.True(await CodeFlow.VerifiesAsync(idToken, jwksA, flow.A.Issuer, flow.ClientA.ClientId, null), "A's ID token doesn't verify with A's JWKS.");
        Assert.False(await CodeFlow.VerifiesAsync(idToken, jwksB, flow.A.Issuer, flow.ClientA.ClientId, null), "A's ID token verifies with B's JWKS.");

        // The code is redeemed, and every token of the flow belongs to the one family.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND type = 'urn:openiddict:params:oauth:token-type:authorization_code' AND status = 'redeemed'"));
        Assert.Equal(3L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token t JOIN \"authorization\" a ON a.tenant_id = t.tenant_id AND a.id = t.authorization_id WHERE t.tenant_id = '{flow.A.TenantId}'"));
        Assert.True(host.Custody.Calls(Gatekeep.Kernel.Secrets.KeyOperation.Sign) > 0, "Nothing was signed through Transit.");
    }

    [Fact]
    public async Task Form_post_answers_an_auto_post_form_carrying_the_code_state_and_iss()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-2", extra: [("response_mode", "form_post")]);

        Assert.Equal(HttpStatusCode.OK, authorize.StatusCode);
        Assert.Equal("text/html", authorize.Content.Headers.ContentType?.MediaType);
        var body = await authorize.Content.ReadAsStringAsync(Cancellation);
        Assert.Contains($"action=\"{Callback}\"", body, StringComparison.Ordinal);
        Assert.Contains("name=\"code\"", body, StringComparison.Ordinal);
        Assert.Contains("name=\"state\" value=\"state-2\"", body, StringComparison.Ordinal);
        Assert.Contains($"name=\"iss\" value=\"{flow.A.Issuer}\"", body, StringComparison.Ordinal);
        Assert.Null(authorize.Headers.Location);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("plain", "same")]
    public async Task Missing_or_plain_PKCE_is_an_invalid_request_redirect_with_iss_and_begins_no_sign_in(string? method, string? challenge)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var withChallenge = challenge is null ? null : pkce with { Challenge = pkce.Verifier, Method = method! };
        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, Callback, withChallenge, flow.UserA, state: "state-3");

        AssertErrorRedirect(authorize, flow.A, "invalid_request", "state-3");
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task A_wrong_code_verifier_is_invalid_grant_and_issues_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);

        using var refused = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, Pkce.New().Verifier);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'valid'"));
    }

    [Theory]
    [InlineData(OtherCallback + "-unregistered")]
    [InlineData("https://client.code.test:8443/callback")]
    [InlineData("https://client.code.test/callback/")]
    [InlineData("https://client.code.test/callback#fragment")]
    [InlineData("not a uri")]
    [InlineData("")]
    public async Task An_unregistered_or_malformed_redirect_uri_gets_the_static_page_and_never_a_redirect(string redirectUri)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var response = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, redirectUri.Length == 0 ? null : redirectUri, Pkce.New(), flow.UserA, state: "echo-me-not");

        await AssertStaticPageAsync(response, "echo-me-not", redirectUri);
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task An_unknown_client_or_the_system_Application_gets_the_static_page()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var system = await flow.Database.EnsureSystemApplicationAsync(flow.A.TenantId);
        await using var host = await flow.StartHostAsync();

        foreach (var clientId in new[] { PublicId.Format(PublicIdType.Application, Guid.CreateVersion7()), PublicId.Format(PublicIdType.Application, system), "not-a-client" })
        {
            using var response = await CodeFlow.AuthorizeAsync(host, HostA, clientId, Callback, Pkce.New(), flow.UserA, state: "echo-me-not");
            await AssertStaticPageAsync(response, "echo-me-not", clientId);
        }

        await AssertNothingBegunAsync(flow);
    }

    [Theory]
    [InlineData("openid email")]
    [InlineData("email")]
    [InlineData(null)]
    public async Task A_scope_other_than_openid_alone_is_an_invalid_scope_redirect(string? scope)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-4", scope: scope);

        AssertErrorRedirect(authorize, flow.A, "invalid_scope", "state-4");
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task Prompt_none_is_a_login_required_redirect()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-5", extra: [("prompt", "none")]);

        AssertErrorRedirect(authorize, flow.A, "login_required", "state-5");
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task Prompt_login_with_a_fresh_sign_in_issues_a_code_whose_ID_token_carries_its_auth_time_and_amr()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var before = DateTimeOffset.UtcNow;

        // The test sign-in authenticates now, after the request started.
        var pkce = Pkce.New();
        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA, state: "state-f1", extra: [("prompt", "login")]);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.False(query.ContainsKey("error"));

        // The sign-in was asked for an authentication at or after the request's start.
        var since = ((TestAuthorizationSignIn)host.Services.GetRequiredService<IAuthorizationSignIn>()).LastAuthenticatedSince;
        Assert.NotNull(since);
        Assert.InRange(since.Value, before, DateTimeOffset.UtcNow);

        using var token = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, query["code"].ToString(), Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, token.Status);
        await AssertIdTokenAuthAsync(flow, token.Body.RootElement.GetProperty("id_token").GetString()!);
    }

    [Fact]
    public async Task Prompt_login_with_a_sign_in_older_than_the_request_is_a_login_required_redirect_and_commits_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-f2", extra: [("prompt", "login")],
            authTime: DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5));

        AssertErrorRedirect(authorize, flow.A, "login_required", "state-f2");
        await AssertNothingBegunAsync(flow);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
    }

    [Fact]
    public async Task Prompt_login_with_a_sign_in_half_a_second_before_the_request_is_a_login_required_redirect()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        // Earlier than the request's start, possibly in the same second: prompt=login is compared exactly.
        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-f6", extra: [("prompt", "login")],
            authTime: DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(500));

        AssertErrorRedirect(authorize, flow.A, "login_required", "state-f6");
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task A_max_age_too_large_for_a_long_demands_nothing_and_issues_a_code()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-f7", extra: [("max_age", "99999999999999999999")],
            authTime: DateTimeOffset.UtcNow - TimeSpan.FromDays(30));

        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.False(query.ContainsKey("error"));
        Assert.True(query.ContainsKey("code"), "No code was issued.");
    }

    [Fact]
    public async Task Max_age_longer_than_the_sign_ins_age_issues_a_code_whose_ID_token_carries_that_auth_time()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var authTime = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5);

        var pkce = Pkce.New();
        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA, state: "state-f3", extra: [("max_age", "600")], authTime: authTime);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.False(query.ContainsKey("error"));

        using var token = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, query["code"].ToString(), Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, token.Status);
        var idToken = token.Body.RootElement.GetProperty("id_token").GetString()!;
        await AssertIdTokenAuthAsync(flow, idToken);
        Assert.Equal(
            authTime.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            new JsonWebToken(idToken).GetClaim("auth_time").Value);
    }

    [Theory]
    [InlineData("60", 300)]
    [InlineData("0", 1)]
    public async Task Max_age_shorter_than_the_sign_ins_age_is_a_login_required_redirect(string maxAge, int ageSeconds)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-f4", extra: [("max_age", maxAge)],
            authTime: DateTimeOffset.UtcNow - TimeSpan.FromSeconds(ageSeconds));

        AssertErrorRedirect(authorize, flow.A, "login_required", "state-f4");
        await AssertNothingBegunAsync(flow);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("abc")]
    [InlineData("1.5")]
    public async Task A_malformed_max_age_is_an_invalid_request_redirect(string maxAge)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-f5", extra: [("max_age", maxAge)]);

        AssertErrorRedirect(authorize, flow.A, "invalid_request", "state-f5");
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public void Prompt_login_and_max_age_demand_the_later_of_their_two_times()
    {
        var started = new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
        static OpenIddictRequest Request(params (string Name, string Value)[] parameters)
        {
            var request = new OpenIddictRequest();
            foreach (var (name, value) in parameters)
            {
                request.SetParameter(name, value);
            }

            return request;
        }

        var since = typeof(ProtocolContract).Assembly
            .GetType("Gatekeep.Modules.Protocol.Core.AuthorizeEndpoint", throwOnError: true)!
            .GetMethod("AuthenticatedSince")!;
        DateTimeOffset? At(OpenIddictRequest request) => (DateTimeOffset?)since.Invoke(null, [request, started]);

        Assert.Null(At(Request()));
        Assert.Equal(started, At(Request(("prompt", "login"))));
        Assert.Equal(started.AddSeconds(-600), At(Request(("max_age", "600"))));
        Assert.Equal(started, At(Request(("max_age", "0"))));
        Assert.Equal(started, At(Request(("prompt", "login"), ("max_age", "600"))));
        Assert.Equal(started.AddSeconds(-60), At(Request(("prompt", "consent"), ("max_age", "60"))));
        Assert.Equal(DateTimeOffset.UnixEpoch, At(Request(("max_age", long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture)))));
        Assert.Equal(DateTimeOffset.UnixEpoch, At(Request(("max_age", "99999999999999999999"))));
    }

    [Theory]
    [InlineData("token")]
    [InlineData("code id_token")]
    [InlineData("id_token")]
    public async Task Implicit_and_hybrid_response_types_are_unsupported_response_type_redirects(string responseType)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(
            host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-6", responseType: responseType, nonce: "n");

        AssertErrorRedirect(authorize, flow.A, "unsupported_response_type", "state-6");
        Assert.Empty(authorize.Headers.Location!.Fragment);
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task The_password_grant_is_unsupported_grant_type()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var refused = await ClientCredentialsTests.TokenAsync(
            host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, grant: "password", extra: ("username", "someone"));

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("unsupported_grant_type", refused.Error);
    }

    [Fact]
    public async Task The_release_sign_in_completes_nothing_so_no_code_is_issued_and_the_transaction_rolls_back()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await ProtocolHost.StartAsync(flow.Database.Hosted, bao);

        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-7");

        AssertErrorRedirect(authorize, flow.A, "temporarily_unavailable", "state-7");
        await AssertNothingBegunAsync(flow);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
    }

    [Fact]
    public async Task A_replayed_code_is_invalid_grant_and_revokes_its_family_in_a_committed_revocation()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);
        using (var first = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier))
        {
            Assert.Equal(HttpStatusCode.OK, first.Status);
        }

        var eventsBefore = await RevocationEventsAsync(flow.Database, flow.A.TenantId);
        Assert.Equal(0L, eventsBefore);

        using var replay = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.BadRequest, replay.Status);
        Assert.Equal("invalid_grant", replay.Error);
        Assert.False(replay.Body.RootElement.TryGetProperty("access_token", out _));

        // The access and ID token rows the first exchange issued, and the code's, are revoked with their family.
        Assert.Equal(3L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(1L, await RevocationEventsAsync(flow.Database, flow.A.TenantId));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}' AND actor_kind = 'anonymous'"));

        // The Session itself isn't ended: a replay revokes the family only.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));
    }

    [Fact]
    public async Task Two_exchanges_of_one_code_racing_get_one_token_and_the_family_is_revoked()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);

        var results = await Task.WhenAll(
            CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier),
            CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier));
        try
        {
            Assert.Single(results, r => r.Status == HttpStatusCode.OK);
            Assert.Single(results, r => r.Status == HttpStatusCode.BadRequest && r.Error == "invalid_grant");
        }
        finally
        {
            foreach (var result in results)
            {
                result.Dispose();
            }
        }

        // Whichever way the loser lost, the code was replayed: the winner's tokens are revoked with their family.
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));
        Assert.Equal(3L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
    }

    [Fact]
    public async Task A_code_exchange_may_name_openid_and_no_other_scope()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var refusedPkce = Pkce.New();
        var refusedCode = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, refusedPkce, flow.UserA);
        using (var refused = await CodeFlow.ExchangeAsync(
            host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refusedCode, Callback, refusedPkce.Verifier, scope: "openid email"))
        {
            Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
            Assert.Equal("invalid_scope", refused.Error);
            Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        }

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier, scope: "openid");
        Assert.Equal(HttpStatusCode.OK, issued.Status);
    }

    [Fact]
    public async Task A_Tenant_with_no_Signing_Key_refuses_with_a_server_error_redirect_and_begins_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var bare = await flow.Database.AddTenantAsync(HostC);
        var client = await flow.Database.CreateWebClientAsync(bare.TenantId, [Callback]);
        var user = await flow.Database.AddUserAsync(bare.TenantId);
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(host, HostC, client.ClientId, Callback, Pkce.New(), user, state: "state-8");

        AssertErrorRedirect(authorize, bare, "server_error", "state-8");
        await AssertNothingBegunAsync(flow);
    }

    [Fact]
    public async Task A_state_too_large_to_keep_is_an_invalid_request_redirect_and_writes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var state = new string('s', 17_000);

        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: state);

        AssertErrorRedirect(authorize, flow.A, "invalid_request", state);
        await AssertNothingBegunAsync(flow);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
    }

    [Fact]
    public async Task A_store_statement_that_fails_and_is_swallowed_ends_as_server_error_and_commits_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var failing = new FailingTokenStore.Switch();
        await using var host = await flow.StartHostAsync(configure: services => FailingTokenStore.Wrap(services, failing));

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);
        var tokensBefore = await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'");

        failing.On = true;
        using var refused = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);

        Assert.Equal(1, failing.Failures);
        Assert.Equal(HttpStatusCode.InternalServerError, refused.Status);
        Assert.Equal("server_error", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.False(refused.Body.RootElement.TryGetProperty("id_token", out _));

        // Nothing the exchange wrote was kept: no new token row, and the code is still unredeemed.
        Assert.Equal(tokensBefore, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'valid' AND redemption_date IS NULL"));
    }

    [Fact]
    public async Task A_code_redeemed_by_another_client_or_to_another_redirect_uri_is_invalid_grant()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var other = await flow.Database.CreateWebClientAsync(flow.A.TenantId, [Callback, OtherCallback], "Other web client");
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);

        using (var byOther = await CodeFlow.ExchangeAsync(host, HostA, other.ClientId, other.Secret, code, Callback, pkce.Verifier))
        {
            Assert.Equal(HttpStatusCode.BadRequest, byOther.Status);
            Assert.Equal("invalid_grant", byOther.Error);
        }

        using (var toOther = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, OtherCallback, pkce.Verifier))
        {
            Assert.Equal(HttpStatusCode.BadRequest, toOther.Status);
            Assert.Equal("invalid_grant", toOther.Error);
        }

        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'"));
    }

    /// <summary>The Story 1.31 cross-Tenant case for the "authorization code" artifact type (FR-8, AD-9).</summary>
    [Fact]
    public async Task Tenant_As_code_presented_at_Tenant_B_is_invalid_grant_and_refused_before_any_lookup()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientB = await flow.Database.CreateWebClientAsync(flow.B.TenantId, [Callback]);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);

        // With B's own client: the code's prefix names A, so B looks nothing up and redeems nothing.
        using (var byB = await CodeFlow.ExchangeAsync(host, HostB, clientB.ClientId, clientB.Secret, code, Callback, pkce.Verifier))
        {
            Assert.Equal(HttpStatusCode.BadRequest, byB.Status);
            Assert.Equal("invalid_grant", byB.Error);
            Assert.False(byB.Body.RootElement.TryGetProperty("access_token", out _));
        }

        // An unauthenticated cross-Tenant mismatch: counted and logged once in B's Log, anonymous, and none in A's.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.B.TenantId}' AND type_code = '{CrossTenantRejected}' AND actor_kind = 'anonymous' AND target_id IS NULL"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{CrossTenantRejected}'"));
        foreach (var name in new[] { flow.A.TenantId.ToString(), PublicId.Format(PublicIdType.Tenant, flow.A.TenantId), flow.ClientA.ClientId })
        {
            Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event r WHERE tenant_id = '{flow.B.TenantId}' AND strpos(to_jsonb(r)::text, '{name}') > 0"));
        }

        // With A's client too: its credential isn't B's, so B refuses the client before the code.
        using (var byA = await CodeFlow.ExchangeAsync(host, HostB, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier))
        {
            Assert.Equal("invalid_client", byA.Error);
            Assert.False(byA.Body.RootElement.TryGetProperty("access_token", out _));
        }

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.B.TenantId}'"));

        // A's code is untouched, and still redeems at A.
        using var atA = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, atA.Status);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData(".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task A_code_with_no_or_another_Tenant_prefix_is_invalid_grant(string code)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var refused = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, Pkce.New().Verifier);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
    }

    [Fact]
    public async Task A_code_redeemed_after_its_60_seconds_is_invalid_grant()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);
        time.Advance(SecurityLimits.AuthorizationCodeLifetime + TimeSpan.FromSeconds(1));

        using var refused = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.Equal(TimeSpan.FromSeconds(60), SecurityLimits.AuthorizationCodeLifetime);
    }

    [Fact]
    public async Task A_recorded_revocation_is_committed_when_the_request_never_reaches_its_end()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);
        using (var first = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier))
        {
            Assert.Equal(HttpStatusCode.OK, first.Status);
        }

        var authorizationId = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}'");

        // The request's own transaction, as Protocol opens it, with the real token store on it: the store
        // records the family's revocation and runs it, then the request fails before its end.
        await using var source = NpgsqlDataSource.Create(flow.Database.Hosted);
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var transactionType = typeof(ProtocolContract).Assembly.GetType("Gatekeep.Modules.Protocol.Core.TokenRequestTransaction", throwOnError: true)!;
            var transaction = scope.ServiceProvider.GetRequiredService(transactionType);
            await (Task)transactionType.GetMethod("BeginAsync")!.Invoke(transaction, [source, flow.A.TenantId, Cancellation])!;

            var store = (StoreRequest)transactionType.GetProperty("Store")!.GetValue(transaction)!;
            var tokens = SessionsContract.CreateTokenStore(store, SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System));
            Assert.Equal(3L, await tokens.RevokeByAuthorizationIdAsync(authorizationId.ToString(), Cancellation));

            // Nothing committed it yet, and the request then throws.
            Assert.Equal(0L, await RevocationEventsAsync(flow.Database, flow.A.TenantId));
            await Assert.ThrowsAsync<NotSupportedException>(async () => await tokens.PruneAsync(DateTimeOffset.UtcNow, Cancellation));
        }

        Assert.Equal(1L, await RevocationEventsAsync(flow.Database, flow.A.TenantId));
        Assert.Equal(3L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
    }

    [Fact]
    public async Task Discovery_advertises_the_code_flow_with_S256_and_iss_and_the_three_grants_only()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var document = await CodeFlow.GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        var root = document.RootElement;

        Assert.Equal($"{flow.A.Issuer}connect/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal(["authorization_code", "client_credentials", "refresh_token"], Strings(root.GetProperty("grant_types_supported")).Order(StringComparer.Ordinal));
        Assert.Equal(["code"], Strings(root.GetProperty("response_types_supported")));
        Assert.Equal(["S256"], Strings(root.GetProperty("code_challenge_methods_supported")));
        Assert.Equal(["form_post", "query"], Strings(root.GetProperty("response_modes_supported")).Order(StringComparer.Ordinal));
        Assert.True(root.GetProperty("authorization_response_iss_parameter_supported").GetBoolean());
    }

    [Fact]
    public async Task The_test_sign_in_lives_only_in_the_tests_and_is_no_src_type()
    {
        Assert.Equal(typeof(AuthorizationCodeTests).Assembly, typeof(TestAuthorizationSignIn).Assembly);
        Assert.Equal(typeof(ProtocolContract).Assembly, typeof(UnavailableSignIn).Assembly);
        Assert.Null(await new UnavailableSignIn().CompleteAsync(null!, null!, null, new DefaultHttpContext(), Cancellation));
    }

    private static void AssertErrorRedirect(HttpResponseMessage response, ResolvedTenant tenant, string error, string state)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(Callback, location.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(error, query["error"].ToString());
        Assert.Equal(tenant.Issuer, query["iss"].ToString());
        Assert.Equal(state, query["state"].ToString());
        Assert.False(query.ContainsKey("code"));
    }

    private static async Task AssertStaticPageAsync(HttpResponseMessage response, params string[] notEchoed)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.True(response.Headers.CacheControl?.NoStore, "The page isn't no-store.");
        Assert.Equal([SecurityHeaders.ContentSecurityPolicy], response.Headers.GetValues("Content-Security-Policy"));
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.Contains("<h1>Something went wrong</h1>", body, StringComparison.Ordinal);
        Assert.Contains("This sign-in link isn't valid. Go back to the app and try again.", body, StringComparison.Ordinal);
        foreach (var value in notEchoed.Where(v => v.Length > 0))
        {
            Assert.DoesNotContain(value, body, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("client.code.test", body, StringComparison.Ordinal);
    }

    /// <summary>The ID token's <c>auth_time</c> is the Session's, to the second, and its <c>amr</c> the result's (Story 2.11).</summary>
    private static async Task AssertIdTokenAuthAsync(CodeFlowSetup flow, string idToken)
    {
        var id = new JsonWebToken(idToken);
        var authTime = await flow.Database.ScalarAsync<DateTime>($"SELECT auth_time FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND user_id = '{flow.UserA}'");
        Assert.Equal(
            new DateTimeOffset(authTime, TimeSpan.Zero).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            id.GetClaim("auth_time").Value);
        Assert.Equal(
            Gatekeep.Tests.Isolation.Sessions.TestOnlyAuthenticator.Method,
            await flow.Database.ScalarAsync<string>($"SELECT array_to_string(amr, ' ') FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND user_id = '{flow.UserA}'"));
        Assert.Contains($"\"amr\":[\"{Gatekeep.Tests.Isolation.Sessions.TestOnlyAuthenticator.Method}\"]", Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(idToken.Split('.')[1])), StringComparison.Ordinal);
    }

    private static async Task AssertNothingBegunAsync(CodeFlowSetup flow)
    {
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM \"authorization\""));
    }

    private static Task<long> RevocationEventsAsync(ProtocolDatabase database, Guid tenantId) =>
        database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenantId}' AND type_code = '{Revoked}'");

    private static List<string?> Strings(System.Text.Json.JsonElement array) => [.. array.EnumerateArray().Select(e => e.GetString())];
}

/// <summary>Two provisioned Tenants, a web client and a User in Tenant A, for a code flow test.</summary>
internal sealed record CodeFlowSetup(
    ProtocolDatabase Database,
    ResolvedTenant A,
    ResolvedTenant B,
    (Guid ApplicationId, string ClientId, string Secret) ClientA,
    Guid UserA,
    OpenBaoFixture Bao)
{
    public const string Callback = "https://client.code.test/callback";

    public const string OtherCallback = "https://client.code.test/other-callback";

    public static async Task<CodeFlowSetup> CreateAsync(PostgresFixture postgres, OpenBaoFixture bao, string hostA, string hostB)
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(hostA);
        var b = await database.AddTenantAsync(hostB);
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(bao, b.TenantId));
        var client = await database.CreateWebClientAsync(a.TenantId, [Callback, OtherCallback]);
        var user = await database.AddUserAsync(a.TenantId);
        return new CodeFlowSetup(database, a, b, client, user, bao);
    }

    /// <summary>The Hosted pipeline with the test-only sign-in plugged into Protocol's port.</summary>
    public Task<ProtocolHost> StartHostAsync(
        TimeProvider? time = null,
        Action<Microsoft.Extensions.Logging.ILoggingBuilder>? logging = null,
        Action<IServiceCollection>? configure = null) =>
        ProtocolHost.StartAsync(
            Database.Hosted,
            Bao,
            time: time,
            logging: logging,
            signIn: provider => new TestAuthorizationSignIn(provider.GetRequiredService<TimeProvider>()),
            configure: configure);
}

/// <summary>A PKCE pair: a 256-bit verifier, and its S256 challenge.</summary>
internal sealed record Pkce(string Verifier, string Challenge, string Method)
{
    public static Pkce New()
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        return new Pkce(verifier, Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))), "S256");
    }
}

/// <summary>The code flow's requests, as a relying party sends them, and what the tests read back.</summary>
internal static class CodeFlow
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>
    /// GETs the authorization endpoint on <paramref name="tenantHost"/>. A null <paramref name="pkce"/>
    /// sends no challenge; a null <paramref name="user"/> names no User to the test sign-in, and
    /// <paramref name="authTime"/>, when given, is the authentication time it returns (Story 2.11).
    /// </summary>
    public static async Task<HttpResponseMessage> AuthorizeAsync(
        ProtocolHost host,
        string tenantHost,
        string clientId,
        string? redirectUri,
        Pkce? pkce,
        Guid? user,
        string state = "state",
        string? nonce = null,
        string? scope = "openid",
        string responseType = "code",
        (string Name, string Value)[]? extra = null,
        DateTimeOffset? authTime = null)
    {
        var query = new List<KeyValuePair<string, string?>>
        {
            new("client_id", clientId),
            new("response_type", responseType),
            new("state", state),
        };

        if (redirectUri is not null)
        {
            query.Add(new("redirect_uri", redirectUri));
        }

        if (scope is not null)
        {
            query.Add(new("scope", scope));
        }

        if (nonce is not null)
        {
            query.Add(new("nonce", nonce));
        }

        if (pkce is not null)
        {
            query.Add(new("code_challenge", pkce.Challenge));
            query.Add(new("code_challenge_method", pkce.Method));
        }

        foreach (var (name, value) in extra ?? [])
        {
            query.Add(new(name, value));
        }

        using var request = new HttpRequestMessage(
            HttpMethod.Get, new Uri($"http://{tenantHost}{ProtocolContract.AuthorizePath}{QueryString.Create(query)}"));
        if (user is { } id)
        {
            request.Headers.TryAddWithoutValidation(TestAuthorizationSignIn.UserHeader, id.ToString());
        }

        if (authTime is { } at)
        {
            request.Headers.TryAddWithoutValidation(TestAuthorizationSignIn.AuthTimeHeader, at.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        }

        return await host.Http.SendAsync(request, Cancellation);
    }

    /// <summary>A code, from a successful authorization request.</summary>
    public static async Task<string> CodeAsync(
        ProtocolHost host, string tenantHost, string clientId, string redirectUri, Pkce pkce, Guid user, string scope = "openid")
    {
        using var response = await AuthorizeAsync(host, tenantHost, clientId, redirectUri, pkce, user, scope: scope);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.False(query.TryGetValue("error", out var error), $"The authorization request failed: {error}.");
        return query["code"].ToString();
    }

    /// <summary>Redeems <paramref name="code"/> at the token endpoint, authenticating the client by Basic.</summary>
    public static async Task<TokenResponse> ExchangeAsync(
        ProtocolHost host, string tenantHost, string clientId, string secret, string code, string redirectUri, string verifier, string? scope = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier,
        };
        if (scope is not null)
        {
            form["scope"] = scope;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{tenantHost}{ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}")));

        var response = await host.Http.SendAsync(request, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return new TokenResponse(response, System.Text.Json.JsonDocument.Parse(body));
    }

    /// <summary>
    /// Refreshes with <paramref name="refreshToken"/> at the token endpoint (Story 2.10), authenticating the
    /// client by Basic, from <paramref name="source"/> when one is named.
    /// </summary>
    public static async Task<TokenResponse> RefreshAsync(
        ProtocolHost host, string tenantHost, string clientId, string secret, string refreshToken, string? scope = null, string? source = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        };
        if (scope is not null)
        {
            form["scope"] = scope;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{tenantHost}{ProtocolContract.TokenPath}"))
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}")));
        if (source is not null)
        {
            request.Headers.TryAddWithoutValidation(ProtocolHost.SourceHeader, source);
        }

        var response = await host.Http.SendAsync(request, Cancellation);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        return new TokenResponse(response, System.Text.Json.JsonDocument.Parse(body));
    }

    public static async Task<bool> VerifiesAsync(string token, JsonWebKeySet jwks, string issuer, string audience, string? type)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidIssuer = issuer,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidTypes = type is null ? null : [type],
        });
        return result.IsValid;
    }

    public static async Task<JsonWebKeySet> JwksAsync(ProtocolHost host, string tenantHost)
    {
        using var document = await GetJsonAsync(host, tenantHost, ProtocolContract.JsonWebKeySetPath);
        return new JsonWebKeySet(document.RootElement.GetRawText());
    }

    public static async Task<System.Text.Json.JsonDocument> GetJsonAsync(ProtocolHost host, string tenantHost, string path)
    {
        using var response = await host.Http.GetAsync(new Uri($"http://{tenantHost}{path}"), Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
    }

    public static async Task<string> CurrentKidAsync(ProtocolDatabase database, Guid tenantId) =>
        await database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{tenantId}' AND purpose = 'signing' AND state = 'current'");

    /// <summary>How many of <paramref name="table"/>'s rows hold <paramref name="value"/> anywhere, searched by parameter.</summary>
    public static async Task<long> RowsHoldingAsync(ProtocolDatabase database, string table, string value)
    {
        await using var connection = new NpgsqlConnection(database.Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand($"SELECT count(*) FROM \"{table}\" r WHERE strpos(to_jsonb(r)::text, @value) > 0", connection);
        command.Parameters.AddWithValue("value", value);
        return (long)(await command.ExecuteScalarAsync(Cancellation))!;
    }
}

/// <summary>
/// Protocol's token store, wrapped (Story 2.9): while its switch is on, once the ID token's row is
/// written, the last store write of a code exchange, it runs one statement that fails in the request's
/// own transaction and swallows the failure, as OpenIddict swallows some store failures, after marking
/// the request failed through its <see cref="StoreRequest"/>, as the real store does.
/// </summary>
public class FailingTokenStore : DispatchProxy
{
    private IOpenIddictTokenStore<SessionsToken> _inner = null!;
    private StoreRequest _request = null!;
    private Switch _switch = null!;

    /// <summary>Replaces Protocol's token store registration with this wrapper around it.</summary>
    internal static void Wrap(IServiceCollection services, Switch failing)
    {
        var registered = services.Last(d => d.ServiceType == typeof(IOpenIddictTokenStore<SessionsToken>));
        var transactionType = typeof(ProtocolContract).Assembly.GetType("Gatekeep.Modules.Protocol.Core.TokenRequestTransaction", throwOnError: true)!;
        services.Remove(registered);
        services.AddScoped(provider =>
        {
            var proxy = Create<IOpenIddictTokenStore<SessionsToken>, FailingTokenStore>();
            var wrapper = (FailingTokenStore)(object)proxy;
            wrapper._inner = (IOpenIddictTokenStore<SessionsToken>)registered.ImplementationFactory!(provider);
            wrapper._request = (StoreRequest)transactionType.GetProperty("Store")!.GetValue(provider.GetRequiredService(transactionType))!;
            wrapper._switch = failing;
            return proxy;
        });
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        var result = targetMethod!.Invoke(_inner, args);
        if (targetMethod.Name == nameof(IOpenIddictTokenStore<SessionsToken>.CreateAsync) && _switch.On && result is ValueTask created)
        {
            return new ValueTask(FailAfterAsync(created, (SessionsToken)args![0]!));
        }

        return result;
    }

    private async Task FailAfterAsync(ValueTask created, SessionsToken token)
    {
        await created;
        if (await _inner.GetTypeAsync(token, CancellationToken.None) != OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.IdentityToken)
        {
            return;
        }

        try
        {
            await using var command = _request.Context().CreateCommand();
            command.CommandText = "SELECT 1 / 0";
            await command.ExecuteScalarAsync(CancellationToken.None);
        }
        catch (PostgresException)
        {
            _request.MarkFailed();
            Interlocked.Increment(ref _switch.FailureCount);
        }
    }

    /// <summary>Turns the failure on, and counts the failures made.</summary>
    internal sealed class Switch
    {
        public int FailureCount;

        public volatile bool On;

        public int Failures => Volatile.Read(ref FailureCount);
    }
}
