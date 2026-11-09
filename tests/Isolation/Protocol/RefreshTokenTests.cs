using System.Net;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore.WebUtilities;
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
/// Story 2.10 (FR-15, FR-13, NFR-3, AD-13, AD-5): rotating refresh tokens with reuse detection on each
/// Tenant's token endpoint, through the real Tenant resolution and Protocol registration, against the real
/// PostgreSQL as <c>gk_hosted</c> and the real OpenBao through the <c>host-hosted</c> login, with the
/// test-only sign-in. One test or more per row of the story's I/O matrix (the web client CHECK row is in
/// <c>DirectoryTests</c>). No assertion prints a code, verifier, secret or token: values are compared with
/// <c>Assert.True(a == b, …)</c>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class RefreshTokenTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.refresh.test";
    private const string HostB = "beta.refresh.test";
    private const string Callback = CodeFlowSetup.Callback;
    private const string Offline = "openid offline_access";
    private const string RefreshType = "urn:ietf:params:oauth:token-type:refresh_token";
    private const string Revoked = "sessions.access.revoked";
    private const string CrossTenantRejected = "protocol.client.cross_tenant_rejected";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_code_flow_with_offline_access_also_returns_a_Tenant_prefixed_refresh_token_held_only_as_a_hash()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var refresh = await OfflineAsync(host, flow);

        Assert.True(refresh.StartsWith(PublicId.Format(PublicIdType.Tenant, flow.A.TenantId) + ".", StringComparison.Ordinal), "The refresh token isn't Tenant A's reference ID.");
        Assert.True(Base64UrlEncoder.DecodeBytes(refresh[(refresh.IndexOf('.', StringComparison.Ordinal) + 1)..]).Length == 32, "The refresh token's random part isn't 256 bits.");

        // One refresh row, in the one family, valid, held only as the hash, for the 7-day inactivity lifetime.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid' AND reference_id IS NOT NULL AND strpos(reference_id, '.') = 0 AND payload IS NOT NULL"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token t JOIN \"authorization\" a ON a.tenant_id = t.tenant_id AND a.id = t.authorization_id WHERE t.tenant_id = '{flow.A.TenantId}' AND t.type = '{RefreshType}' AND t.expiration_date - t.creation_date BETWEEN interval '6 days 23 hours 59 minutes' AND interval '7 days'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND scopes @> ARRAY['openid', 'offline_access'] AND cardinality(scopes) = 2"));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "token", refresh));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "token", RandomPart(refresh)));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "authorization", RandomPart(refresh)));
    }

    [Fact]
    public async Task A_code_flow_without_offline_access_returns_no_refresh_token()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA);
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);

        Assert.Equal(HttpStatusCode.OK, issued.Status);
        Assert.False(issued.Body.RootElement.TryGetProperty("refresh_token", out _));
        Assert.True(issued.Body.RootElement.TryGetProperty("id_token", out _));
        Assert.Equal(0L, await RefreshRowsAsync(flow, "true"));
    }

    [Fact]
    public async Task Offline_access_for_an_Application_not_allowed_refresh_tokens_is_an_invalid_scope_redirect()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await flow.Database.ExecuteAsync($"UPDATE application SET grant_types = ARRAY['authorization_code'] WHERE id = '{flow.ClientA.ApplicationId}'");
        await using var host = await flow.StartHostAsync();

        using var authorize = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA, state: "state-r1", scope: Offline);

        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var query = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query);
        Assert.Equal("invalid_scope", query["error"].ToString());
        Assert.Equal(flow.A.Issuer, query["iss"].ToString());
        Assert.Equal("state-r1", query["state"].ToString());
        Assert.False(query.ContainsKey("code"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM \"authorization\""));

        // openid alone still signs the User in.
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, Pkce.New(), flow.UserA);
        Assert.False(string.IsNullOrEmpty(code));
    }

    [Fact]
    public async Task A_refresh_rotates_the_token_and_issues_new_access_and_ID_tokens_from_the_anchored_Session()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1);

        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        var r2 = refreshed.RefreshToken;
        Assert.True(r1 != r2, "The refresh didn't rotate the refresh token.");
        Assert.True(r2.StartsWith(PublicId.Format(PublicIdType.Tenant, flow.A.TenantId) + ".", StringComparison.Ordinal), "The new refresh token isn't Tenant A's reference ID.");
        Assert.Equal((int)SecurityLimits.DefaultAccessTokenLifetime.TotalSeconds, refreshed.Body.RootElement.GetProperty("expires_in").GetInt32());

        // R1 is redeemed, R2 valid, both in the one family.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'redeemed' AND redemption_date IS NOT NULL"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(DISTINCT authorization_id) FROM token WHERE tenant_id = '{flow.A.TenantId}'"));

        // The new tokens say what the family's Session says, and verify only with A's JWKS.
        var subject = PublicId.Format(PublicIdType.User, flow.UserA);
        var access = new JsonWebToken(refreshed.AccessToken);
        Assert.Equal("at+jwt", access.Typ);
        Assert.Equal(subject, access.Subject);
        Assert.Equal(await CodeFlow.CurrentKidAsync(flow.Database, flow.A.TenantId), access.Kid);

        var idToken = refreshed.Body.RootElement.GetProperty("id_token").GetString()!;
        var id = new JsonWebToken(idToken);
        Assert.Equal(subject, id.Subject);
        Assert.Equal([flow.ClientA.ClientId], id.Audiences);
        var sessionId = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND user_id = '{flow.UserA}'");
        Assert.Equal(PublicId.Format(PublicIdType.Session, sessionId), id.GetClaim("sid").Value);
        var authTime = await flow.Database.ScalarAsync<DateTime>($"SELECT auth_time FROM user_session WHERE id = '{sessionId}'");
        Assert.Equal(new DateTimeOffset(authTime, TimeSpan.Zero).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), id.GetClaim("auth_time").Value);
        Assert.Contains("\"amr\":[\"test\"]", Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(idToken.Split('.')[1])), StringComparison.Ordinal);
        Assert.False(access.TryGetClaim("sid", out _));

        var jwksA = await CodeFlow.JwksAsync(host, HostA);
        var jwksB = await CodeFlow.JwksAsync(host, HostB);
        Assert.True(await CodeFlow.VerifiesAsync(refreshed.AccessToken, jwksA, flow.A.Issuer, ProtocolContract.PlaceholderAudience, "at+jwt"), "The refreshed access token doesn't verify with A's JWKS.");
        Assert.False(await CodeFlow.VerifiesAsync(refreshed.AccessToken, jwksB, flow.A.Issuer, ProtocolContract.PlaceholderAudience, "at+jwt"), "The refreshed access token verifies with B's JWKS.");
        Assert.True(await CodeFlow.VerifiesAsync(idToken, jwksA, flow.A.Issuer, flow.ClientA.ClientId, null), "The refreshed ID token doesn't verify with A's JWKS.");
    }

    [Fact]
    public async Task A_rotated_refresh_token_presented_again_is_invalid_grant_and_revokes_its_family_in_a_committed_revocation()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        string r2;
        using (var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1))
        {
            Assert.Equal(HttpStatusCode.OK, refreshed.Status);
            r2 = refreshed.RefreshToken;
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));

        using (var reused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1))
        {
            Assert.Equal(HttpStatusCode.BadRequest, reused.Status);
            Assert.Equal("invalid_grant", reused.Error);
            Assert.False(reused.Body.RootElement.TryGetProperty("access_token", out _));
            Assert.False(reused.Body.RootElement.TryGetProperty("refresh_token", out _));
        }

        // The whole family, its authorization and every token, R2 and the newest access token included.
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(1L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}' AND actor_kind = 'anonymous'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));

        // R2 is refused now too, and that refusal revokes nothing more.
        using (var newest = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r2))
        {
            Assert.Equal(HttpStatusCode.BadRequest, newest.Status);
            Assert.Equal("invalid_grant", newest.Error);
        }

        Assert.Equal(1L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task A_chain_of_refreshes_works_each_token_once_and_leaves_the_last_valid()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        var r2 = await RefreshOkAsync(host, flow, r1);
        var r3 = await RefreshOkAsync(host, flow, r2);

        Assert.True(r1 != r3 && r2 != r3, "A refresh token repeated in the chain.");
        Assert.Equal(2L, await RefreshRowsAsync(flow, "status = 'redeemed'"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        Assert.Equal(0L, await RevocationEventsAsync(flow));

        // R3 is the one that works.
        var r4 = await RefreshOkAsync(host, flow, r3);
        Assert.True(r4 != r3, "R3 didn't rotate.");
    }

    [Fact]
    public async Task Two_refreshes_of_one_token_racing_get_one_token_and_the_family_is_revoked()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        var results = await Task.WhenAll(
            CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1),
            CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1));
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

        // Whichever way the loser lost, R1 was reused: the winner's tokens are revoked with their family.
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.True(await RevocationEventsAsync(flow) >= 1, "The family's revocation wasn't committed.");
    }

    [Fact]
    public async Task A_refresh_token_unused_for_its_inactivity_lifetime_is_invalid_grant_and_revokes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);
        var r1 = await OfflineAsync(host, flow);

        time.Advance(SecurityLimits.RefreshTokenInactivityLifetime + TimeSpan.FromSeconds(1));

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status = 'revoked'"));
        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        Assert.Equal(TimeSpan.FromDays(7), SecurityLimits.RefreshTokenInactivityLifetime);
        Assert.Equal(TimeSpan.FromDays(30), SecurityLimits.HardRefreshTokenInactivityLifetime);
    }

    [Fact]
    public async Task A_chain_refreshed_every_six_days_ends_at_the_familys_absolute_lifetime()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);
        var token = await OfflineAsync(host, flow);

        // Days 6, 12, 18 and 24: each works, and none outlives the family's 30-day end.
        for (var i = 0; i < 4; i++)
        {
            time.Advance(TimeSpan.FromDays(6));
            token = await RefreshOkAsync(host, flow, token);
        }

        var familyEnd = "a.creation_date + interval '30 days'";
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token t JOIN \"authorization\" a ON a.tenant_id = t.tenant_id AND a.id = t.authorization_id WHERE t.tenant_id = '{flow.A.TenantId}' AND t.type = '{RefreshType}' AND t.expiration_date > {familyEnd}"));

        // The day-24 token's 7 days were cut to the family's end, to the second.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM token t JOIN \"authorization\" a ON a.tenant_id = t.tenant_id AND a.id = t.authorization_id WHERE t.tenant_id = '{flow.A.TenantId}' AND t.type = '{RefreshType}' AND t.status = 'valid' AND t.expiration_date > {familyEnd} - interval '1 second'"));

        // Day 30 and a second: past the family's end, the last token is refused, and nothing is revoked.
        time.Advance(TimeSpan.FromDays(6) + TimeSpan.FromSeconds(1));
        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, token);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(TimeSpan.FromDays(30), SecurityLimits.RefreshTokenAbsoluteLifetime);
        Assert.Equal(TimeSpan.FromDays(90), SecurityLimits.HardRefreshTokenAbsoluteLifetime);
    }

    [Fact]
    public async Task A_refresh_past_the_familys_absolute_end_is_invalid_grant_whatever_its_own_expiry_says()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        // The family is made 30 days and a minute old, while R1 itself still has 7 days to run.
        await flow.Database.BackdateAsync(
            $"UPDATE \"authorization\" SET creation_date = creation_date - interval '30 days 1 minute' WHERE tenant_id = '{flow.A.TenantId}'");

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));

        // Refused before its redemption: nothing is burnt, revoked or issued.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid' AND redemption_date IS NULL"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "true"));
        Assert.Equal(0L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task A_refresh_in_a_family_revoked_through_the_one_revocation_path_is_invalid_grant()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        var sessionId = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM user_session WHERE tenant_id = '{flow.A.TenantId}'");
        await using (var source = NpgsqlDataSource.Create(flow.Database.Hosted))
        await using (var scope = await TenantScope.BeginAsync(source, flow.A.TenantId, Cancellation))
        {
            await SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System).RevokeAccessAsync(
                scope.CreateCommandContext(), new RevocationScope.Session(sessionId), null, RevocationReason.Logout, Actor.User(flow.UserA), Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1);
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));
    }

    [Fact]
    public async Task A_refresh_whose_family_is_revoked_after_its_redemption_is_refused_and_its_token_stays_burnt()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var revokeMidRequest = new MidRequestSwitch();
        await using var host = await flow.StartHostAsync(configure: services => services.AddOpenIddict().AddServer(server =>
            server.AddEventHandler<ProcessSignInContext>(handler => handler
                .UseInlineHandler(async context =>
                {
                    // Between OpenIddict's redemption and Gatekeep's late refusals: the family is revoked
                    // by another request that commits while this one runs.
                    if (revokeMidRequest.On && context.Request.IsRefreshTokenGrantType())
                    {
                        await flow.Database.BackdateAsync(
                            $"UPDATE \"authorization\" SET status = 'revoked', concurrency_token = gen_random_uuid() WHERE tenant_id = '{flow.A.TenantId}'");
                        Interlocked.Increment(ref revokeMidRequest.Runs);
                    }
                })
                .SetOrder(OpenIddictServerHandlers.RedeemTokenEntry.Descriptor.Order + 250))));
        var r1 = await OfflineAsync(host, flow);
        var tokensBefore = await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'");

        revokeMidRequest.On = true;
        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1);

        Assert.Equal(1, Volatile.Read(ref revokeMidRequest.Runs));
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.False(refused.Body.RootElement.TryGetProperty("refresh_token", out _));

        // The request rolled back, but R1's redemption was committed: it can't come back to life.
        Assert.Equal(tokensBefore, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}'"));
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'redeemed' AND redemption_date IS NOT NULL"));
        Assert.Equal(0L, await RefreshRowsAsync(flow, "status = 'valid'"));
    }

    [Fact]
    public async Task A_refresh_token_presented_by_another_client_of_the_Tenant_is_invalid_grant()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var other = await flow.Database.CreateWebClientAsync(flow.A.TenantId, [Callback], "Other web client");
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        using (var byOther = await CodeFlow.RefreshAsync(host, HostA, other.ClientId, other.Secret, r1))
        {
            Assert.Equal(HttpStatusCode.BadRequest, byOther.Status);
            Assert.Equal("invalid_grant", byOther.Error);
            Assert.False(byOther.Body.RootElement.TryGetProperty("access_token", out _));
        }

        // R1 is untouched, and still refreshes for its own client.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        await RefreshOkAsync(host, flow, r1);
    }

    /// <summary>The Story 1.31 cross-Tenant case for the "refresh token" artifact type (FR-8, AD-9).</summary>
    [Fact]
    public async Task Tenant_As_refresh_token_presented_at_Tenant_B_is_invalid_grant_and_refused_before_any_lookup()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var clientB = await flow.Database.CreateWebClientAsync(flow.B.TenantId, [Callback]);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        // With B's own client: the token's prefix names A, so B looks nothing up and redeems nothing.
        using (var byB = await CodeFlow.RefreshAsync(host, HostB, clientB.ClientId, clientB.Secret, r1))
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

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.B.TenantId}'"));

        // A's refresh token is untouched, and still refreshes at A.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid'"));
        await RefreshOkAsync(host, flow, r1);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("ten_aaaaaaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData(".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task A_refresh_token_with_no_or_another_Tenant_prefix_is_invalid_grant(string refreshToken)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refreshToken);

        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", refused.Error);
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{CrossTenantRejected}' AND actor_kind = 'anonymous'"));
    }

    [Theory]
    [InlineData("openid email")]
    [InlineData("email")]
    [InlineData("openid offline_access profile")]
    public async Task A_refresh_naming_a_scope_its_family_wasnt_granted_is_invalid_scope_and_redeems_nothing(string scope)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        using (var refused = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1, scope: scope))
        {
            Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
            Assert.Equal("invalid_scope", refused.Error);
            Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        }

        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid' AND redemption_date IS NULL"));

        // A granted scope may be named.
        using var narrowed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1, scope: Offline);
        Assert.Equal(HttpStatusCode.OK, narrowed.Status);
    }

    [Fact]
    public async Task The_sixty_first_refresh_from_one_source_is_429_with_Retry_After_and_another_source_still_refreshes()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);

        // Every refresh is counted before anything else happens, a refused one too.
        for (var i = 0; i < SecurityLimits.TokenRequestSourceAttempts; i++)
        {
            using var counted = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, "garbage", source: "203.0.113.50");
            Assert.Equal("invalid_grant", counted.Error);
        }

        using (var limited = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1, source: "203.0.113.50"))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
            Assert.Equal("temporarily_unavailable", limited.Error);
            Assert.False(limited.Body.RootElement.TryGetProperty("access_token", out _));
            var retryAfter = Assert.Single(limited.Headers.GetValues("Retry-After"));
            Assert.InRange(int.Parse(retryAfter, System.Globalization.CultureInfo.InvariantCulture), 1, (int)SecurityLimits.TokenRequestWindow.TotalSeconds);
        }

        // Refused before its transaction: R1 is untouched, and refreshes from another source.
        Assert.Equal(1L, await RefreshRowsAsync(flow, "status = 'valid' AND redemption_date IS NULL"));
        using var other = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r1, source: "203.0.113.51");
        Assert.Equal(HttpStatusCode.OK, other.Status);
    }

    [Fact]
    public async Task The_Tenant_limit_counts_refreshes_too()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        var limits = new TokenRequestLimits(
            new Gatekeep.Kernel.RateLimiting.RateLimitPolicy(AuthenticationContract.TokenRequestTenantPolicy.Code, 2, SecurityLimits.TokenRequestWindow),
            AuthenticationContract.TokenRequestSourcePolicy);
        await using var host = await ProtocolHost.StartAsync(
            flow.Database.Hosted,
            bao,
            limits: limits,
            signIn: provider => new TestAuthorizationSignIn(provider.GetRequiredService<TimeProvider>()));

        // The code exchange is the first token request, the refresh the second; the third is over the limit.
        var r1 = await OfflineAsync(host, flow);
        var r2 = await RefreshOkAsync(host, flow, r1);

        using var limited = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, r2, source: "203.0.113.60");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
        Assert.Single(limited.Headers.GetValues("Retry-After"));
        Assert.Equal("temporarily_unavailable", limited.Error);
    }

    [Fact]
    public async Task No_column_of_any_token_row_holds_an_issued_or_rotated_refresh_token()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var r1 = await OfflineAsync(host, flow);
        var r2 = await RefreshOkAsync(host, flow, r1);

        foreach (var value in new[] { r1, r2, RandomPart(r1), RandomPart(r2) })
        {
            Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "token", value));
            Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "authorization", value));
            Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "audit_event", value));
        }

        Assert.Equal(2L, await RefreshRowsAsync(flow, "reference_id IS NOT NULL AND strpos(reference_id, '.') = 0"));
        Assert.DoesNotContain(host.Logs.Lines, line => line.Contains(RandomPart(r1), StringComparison.Ordinal) || line.Contains(RandomPart(r2), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Discovery_advertises_the_refresh_grant_and_offline_access()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        using var document = await CodeFlow.GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        var root = document.RootElement;

        Assert.Equal(
            ["authorization_code", "client_credentials", "refresh_token"],
            root.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()).Order(StringComparer.Ordinal));
        Assert.Contains("offline_access", root.GetProperty("scopes_supported").EnumerateArray().Select(e => e.GetString()));
        Assert.Contains("openid", root.GetProperty("scopes_supported").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public async Task Refresh_tokens_are_rolling_reference_tokens_with_no_reuse_leeway_on_every_Tenants_options()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var tenant = await host.TenantOptions.GetAsync(flow.A, Cancellation);
        foreach (var options in new[] { host.GlobalOptions, tenant })
        {
            Assert.Contains("refresh_token", options.GrantTypes);
            Assert.Contains("offline_access", options.Scopes);
            Assert.True(options.UseReferenceRefreshTokens);
            Assert.False(options.DisableRollingRefreshTokens);
            Assert.Equal(TimeSpan.Zero, options.RefreshTokenReuseLeeway);
            Assert.Equal(SecurityLimits.RefreshTokenInactivityLifetime, options.RefreshTokenLifetime);
        }
    }

    /// <summary>A code flow with <c>offline_access</c> for the setup's User and web client in Tenant A, exchanged: its refresh token.</summary>
    internal static async Task<string> OfflineAsync(ProtocolHost host, CodeFlowSetup flow)
    {
        var pkce = Pkce.New();
        var code = await CodeFlow.CodeAsync(host, HostA, flow.ClientA.ClientId, Callback, pkce, flow.UserA, scope: Offline);
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        Assert.True(issued.Body.RootElement.TryGetProperty("id_token", out _));
        return issued.RefreshToken;
    }

    /// <summary>A refresh at Tenant A that must succeed: the new refresh token.</summary>
    private static async Task<string> RefreshOkAsync(ProtocolHost host, CodeFlowSetup flow, string refreshToken)
    {
        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        return refreshed.RefreshToken;
    }

    private static string RandomPart(string referenceId) => referenceId[(referenceId.IndexOf('.', StringComparison.Ordinal) + 1)..];

    private static Task<long> RefreshRowsAsync(CodeFlowSetup flow, string condition) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND type = '{RefreshType}' AND ({condition})");

    private static Task<long> RevocationEventsAsync(CodeFlowSetup flow) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}'");

    /// <summary>Turns the mid-request revocation on, and counts its runs.</summary>
    private sealed class MidRequestSwitch
    {
        public int Runs;

        public volatile bool On;
    }
}
