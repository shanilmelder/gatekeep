using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 4.13 (FR-24, OpenID Connect RP-Initiated Logout 1.0): the end-session endpoint and Hosted Login's logout
/// confirmation, through the real Tenant resolution and Protocol registration, against the real PostgreSQL as
/// <c>gk_hosted</c> and the real OpenBao, with the test-only sign-in. One test or more per row of the story's I/O matrix,
/// each asserting the Session row, the Token Families and the cookie. No assertion prints a token or a cookie.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class LogoutTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.logout.test";
    private const string HostB = "beta.logout.test";
    private const string Callback = CodeFlowSetup.Callback;
    private const string LogoutUrl = "https://client.code.test/signed-out";
    private const string RefreshType = "urn:ietf:params:oauth:token-type:refresh_token";
    private const string Revoked = "sessions.access.revoked";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Discovery_advertises_the_end_session_endpoint()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();

        using var document = await CodeFlow.GetJsonAsync(host, HostA, ProtocolContract.ConfigurationPath);
        Assert.Equal($"{flow.A.Issuer}connect/endsession", document.RootElement.GetProperty("end_session_endpoint").GetString());
    }

    [Fact]
    public async Task Confirming_ends_the_Session_and_its_families_clears_the_cookie_and_redirects_with_state()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        // The confirmation: its step carries the request's own parameters and the Session-bound CSRF token, and it ends nothing.
        using var page = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", flow.ClientA.ClientId));
        var confirmation = await LogoutFlow.PageStepAsync(page);
        Assert.Equal(StepNames.Logout, confirmation.Step);
        var data = confirmation.Data;
        Assert.Equal(ProtocolDatabase.TestTenantName, data.GetProperty("tenant").GetString());
        Assert.True(data.GetProperty("idTokenHint").GetString() == signedIn.IdToken, "The confirmation doesn't carry the hint as sent.");
        Assert.Equal(LogoutUrl, data.GetProperty("postLogoutRedirectUri").GetString());
        Assert.Equal("xyz", data.GetProperty("state").GetString());
        Assert.Equal(flow.ClientA.ClientId, data.GetProperty("clientId").GetString());
        Assert.False(string.IsNullOrEmpty(confirmation.Csrf));
        Assert.Equal("live", await SessionStateAsync(flow, sessionId));
        Assert.Equal(0L, await RevocationEventsAsync(flow));

        using var confirmed = await LogoutFlow.ConfirmAsync(signedIn.Browser, confirmation);
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        using var step = await HostedBrowser.StepAsync(confirmed);
        Assert.Equal(StepNames.LoggedOut, step.RootElement.GetProperty("step").GetString());
        Assert.Equal($"{LogoutUrl}?state=xyz", step.RootElement.GetProperty("data").GetProperty("redirectTo").GetString());
        Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("csrfToken").ValueKind);

        // The Session ended for logout, its family and its refresh token revoked, through the one revocation path by the User.
        Assert.Equal("ended logout", await SessionStateAsync(flow, sessionId));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{flow.A.TenantId}' AND status <> 'revoked'"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{flow.A.TenantId}' AND type = '{RefreshType}' AND status <> 'revoked'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}' AND actor_kind = 'user' AND actor_id = '{flow.UserA}'"));
        LogoutFlow.AssertSessionCookieCleared(confirmed, signedIn.Browser);
    }

    [Fact]
    public async Task After_logout_the_familys_refresh_token_is_invalid_grant()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, null, null));

        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, signedIn.Refresh!);
        Assert.Equal("invalid_grant", refreshed.Error);
    }

    [Fact]
    public async Task A_tampered_hint_logs_out_with_no_redirect()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(Tampered(signedIn.IdToken), LogoutUrl, "xyz", null));

        Assert.Null(redirectTo);
        Assert.Equal("ended logout", await SessionStateAsync(flow, sessionId));
        Assert.False(signedIn.Browser.Cookies.ContainsKey(ProtocolContract.SessionCookie));
    }

    [Fact]
    public async Task Another_Tenants_hint_logs_out_with_no_redirect()
    {
        var flow = await SetupAsync();
        var clientB = await flow.Database.CreateWebClientAsync(flow.B.TenantId, [Callback]);
        var userB = await flow.Database.AddUserAsync(flow.B.TenantId);
        await SetLogoutUrlsAsync(flow, clientB.ApplicationId, LogoutUrl);
        await using var host = await flow.StartHostAsync();
        var atB = await LogoutFlow.SignInAsync(host, HostB, clientB.ClientId, clientB.Secret, userB);
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        // B's own ID token, at A, with a URL both register: A's keys don't verify it.
        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(atB.IdToken, LogoutUrl, "xyz", null));

        Assert.Null(redirectTo);
        Assert.Equal("ended logout", await SessionStateAsync(flow, sessionId));

        // B's Session is untouched.
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.B.TenantId}' AND ended_at IS NULL"));
    }

    [Fact]
    public async Task An_unregistered_URL_logs_out_with_no_redirect()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        foreach (var url in new[] { "https://evil.example/signed-out", LogoutUrl + "/", "https://client.code.test:443/signed-out", Callback })
        {
            using var page = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, url, "xyz", null));
            var confirmation = await LogoutFlow.PageStepAsync(page);
            Assert.Equal(StepNames.Logout, confirmation.Step);
            using var confirmed = await LogoutFlow.ConfirmAsync(signedIn.Browser, confirmation);
            using var step = await HostedBrowser.StepAsync(confirmed);
            Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("data").GetProperty("redirectTo").ValueKind);

            // Signed in again for the next URL.
            if (url != Callback)
            {
                signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA, signedIn.Browser);
            }
        }

        Assert.Equal("ended logout", await SessionStateAsync(flow, sessionId));
    }

    [Fact]
    public async Task A_client_id_that_isnt_the_hints_Application_gets_no_redirect()
    {
        var flow = await SetupAsync();
        var other = await flow.Database.CreateWebClientAsync(flow.A.TenantId, [Callback], "Other web client");
        await SetLogoutUrlsAsync(flow, other.ApplicationId, LogoutUrl);
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", other.ClientId));

        Assert.Null(redirectTo);
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND end_reason = 'logout'"));
    }

    [Fact]
    public async Task A_deleted_Application_gets_no_redirect()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        await flow.Database.ExecuteAsync($"UPDATE application SET deleted_at = now() WHERE id = '{flow.ClientA.ApplicationId}'");

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null));

        Assert.Null(redirectTo);
    }

    [Fact]
    public async Task An_expired_hint_with_a_registered_URL_still_redirects()
    {
        var flow = await SetupAsync();
        var time = new ShiftedTimeProvider();
        await using var host = await flow.StartHostAsync(time);
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        time.Advance(Gatekeep.Kernel.Limits.SecurityLimits.DefaultIdentityTokenLifetime + TimeSpan.FromMinutes(1));

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", flow.ClientA.ClientId));

        Assert.Equal($"{LogoutUrl}?state=xyz", redirectTo);
    }

    [Fact]
    public async Task With_no_live_Session_the_logout_is_complete_at_once_with_its_target_and_nothing_revoked()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        // No cookie at all: a fresh browser.
        var fresh = new HostedBrowser(host, HostA);
        using (var page = await fresh.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null)))
        {
            var step = await LogoutFlow.PageStepAsync(page);
            Assert.Equal(StepNames.LoggedOut, step.Step);
            Assert.Equal($"{LogoutUrl}?state=xyz", step.Data.GetProperty("redirectTo").GetString());
            Assert.Null(step.Csrf);
        }

        Assert.Equal("live", await SessionStateAsync(flow, sessionId));
        Assert.Equal(0L, await RevocationEventsAsync(flow));

        // An ended cookie: the logout again with the cookie it ended presented, which is cleared, and nothing more revoked.
        var ended = signedIn.Browser.Cookies[ProtocolContract.SessionCookie];
        await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(null, null, null, null));
        Assert.Equal(1L, await RevocationEventsAsync(flow));
        signedIn.Browser.Cookies[ProtocolContract.SessionCookie] = ended;
        using (var again = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, null, null)))
        {
            var step = await LogoutFlow.PageStepAsync(again);
            Assert.Equal(StepNames.LoggedOut, step.Step);
            Assert.Equal(LogoutUrl, step.Data.GetProperty("redirectTo").GetString());
            LogoutFlow.AssertSessionCookieCleared(again, signedIn.Browser);
        }

        Assert.Equal(1L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task With_no_parameters_the_confirmation_logs_out_with_no_redirect()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        using var page = await signedIn.Browser.GetAsync(ProtocolContract.EndSessionPath);
        var confirmation = await LogoutFlow.PageStepAsync(page);
        Assert.Equal(StepNames.Logout, confirmation.Step);
        foreach (var name in new[] { "idTokenHint", "postLogoutRedirectUri", "state", "clientId" })
        {
            Assert.Equal(JsonValueKind.Null, confirmation.Data.GetProperty(name).ValueKind);
        }

        using var confirmed = await LogoutFlow.ConfirmAsync(signedIn.Browser, confirmation);
        using var step = await HostedBrowser.StepAsync(confirmed);
        Assert.Equal(StepNames.LoggedOut, step.RootElement.GetProperty("step").GetString());
        Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("data").GetProperty("redirectTo").ValueKind);
        Assert.Equal("ended logout", await SessionStateAsync(flow, sessionId));
    }

    [Fact]
    public async Task A_form_POST_to_the_end_session_endpoint_is_answered_as_its_GET()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        using var page = await signedIn.Browser.PostFormAsync(
            ProtocolContract.EndSessionPath,
            [new("id_token_hint", signedIn.IdToken), new("post_logout_redirect_uri", LogoutUrl), new("state", "xyz")]);
        var confirmation = await LogoutFlow.PageStepAsync(page);
        Assert.Equal(StepNames.Logout, confirmation.Step);
        Assert.Equal(LogoutUrl, confirmation.Data.GetProperty("postLogoutRedirectUri").GetString());

        using var confirmed = await LogoutFlow.ConfirmAsync(signedIn.Browser, confirmation);
        using var step = await HostedBrowser.StepAsync(confirmed);
        Assert.Equal($"{LogoutUrl}?state=xyz", step.RootElement.GetProperty("data").GetProperty("redirectTo").GetString());
    }

    [Fact]
    public async Task An_end_session_request_OpenIddict_cant_read_still_gets_the_logout_page_and_never_an_error()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        // A POST that isn't a form, and a method the endpoint doesn't take: the confirmation, with no parameters kept.
        using var json = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{HostA}{ProtocolContract.EndSessionPath}"))
        {
            Content = new StringContent($$"""{"post_logout_redirect_uri":"{{LogoutUrl}}"}""", Encoding.UTF8, "application/json"),
        };
        json.Headers.TryAddWithoutValidation("Cookie", $"{ProtocolContract.SessionCookie}={signedIn.Browser.Cookies[ProtocolContract.SessionCookie]}");
        using (var response = await host.Http.SendAsync(json, Cancellation))
        {
            var step = await LogoutFlow.PageStepAsync(response);
            Assert.Equal(StepNames.Logout, step.Step);
            Assert.Equal(JsonValueKind.Null, step.Data.GetProperty("postLogoutRedirectUri").ValueKind);
        }

        // Without a Session, a redirect URI OpenIddict would have refused as malformed is a logout with no redirect.
        var fresh = new HostedBrowser(host, HostA);
        using (var response = await fresh.GetAsync($"{ProtocolContract.EndSessionPath}?post_logout_redirect_uri=not-a-url&id_token_hint=nope"))
        {
            var step = await LogoutFlow.PageStepAsync(response);
            Assert.Equal(StepNames.LoggedOut, step.Step);
            Assert.Equal(JsonValueKind.Null, step.Data.GetProperty("redirectTo").ValueKind);
        }
    }

    [Fact]
    public async Task Log_out_without_the_CSRF_token_or_from_another_Origin_is_403_and_ends_nothing()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);
        using var page = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null));
        var confirmation = await LogoutFlow.PageStepAsync(page);
        var body = LogoutFlow.Body(confirmation);

        var refusals = new (string? Csrf, string? Origin, string Code)[]
        {
            (null, null, "csrf_mismatch"),
            ("not-the-token", null, "csrf_mismatch"),
            (confirmation.Csrf, "https://evil.example", "origin_mismatch"),
            (confirmation.Csrf, HostedBrowser.NoOrigin, "origin_mismatch"),
        };
        foreach (var (csrf, origin, code) in refusals)
        {
            using var refused = await signedIn.Browser.PostAsync(ProtocolContract.LogoutPath, body, csrf, origin);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            using var step = await HostedBrowser.StepAsync(refused);
            Assert.Equal(code, step.RootElement.GetProperty("data").GetProperty("code").GetString());
            Assert.DoesNotContain(SetCookie.Of(refused), c => SetCookie.Name(c) == ProtocolContract.SessionCookie);
        }

        // Another browser's Session cookie makes another token: this one's doesn't post for it.
        var other = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        using (var crossed = await other.Browser.PostAsync(ProtocolContract.LogoutPath, body, confirmation.Csrf))
        {
            Assert.Equal(HttpStatusCode.Forbidden, crossed.StatusCode);
        }

        Assert.Equal("live", await SessionStateAsync(flow, sessionId));
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));
        Assert.Equal(0L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task Only_the_browsers_own_Session_ends_whatever_the_hint_names()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var first = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var second = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        // The second browser logs out with the first browser's ID token, whose sid names the first Session.
        var redirectTo = await LogoutFlow.LogOutAsync(second.Browser, LogoutFlow.EndSessionUrl(first.IdToken, LogoutUrl, null, null));

        Assert.Equal(LogoutUrl, redirectTo);
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));
        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, first.Refresh!);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
    }

    [Theory]
    [InlineData("http://127.0.0.1/cb", "http://127.0.0.1:51004/cb", true)]
    [InlineData("http://[::1]:8080/cb", "http://[::1]:51004/cb", true)]
    [InlineData("http://127.0.0.1/cb", "http://localhost:51004/cb", false)]
    public async Task A_native_Applications_loopback_logout_URL_may_differ_in_port(string registered, string requested, bool redirects)
    {
        var flow = await SetupAsync();
        var (applicationId, clientId) = await flow.Database.CreateApplicationAsync(flow.A.TenantId, "native");
        await flow.Database.ExecuteAsync(
            $"UPDATE application SET redirect_uris = ARRAY['{Callback}'], post_logout_redirect_uris = ARRAY['{registered}'], grant_types = ARRAY['authorization_code'] WHERE id = '{applicationId}'");
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, clientId, secret: null, flow.UserA, scope: "openid");

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, requested, null, clientId));

        Assert.Equal(redirects ? requested : null, redirectTo);
    }

    [Fact]
    public async Task A_web_Applications_logout_URL_gets_no_loopback_port_exception()
    {
        var flow = await SetupAsync();
        await SetLogoutUrlsAsync(flow, flow.ClientA.ApplicationId, "http://127.0.0.1/cb");
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, "http://127.0.0.1:51004/cb", null, null));

        Assert.Null(redirectTo);
    }

    [Fact]
    public async Task Tenant_As_Session_cookie_at_Tenant_B_ends_nothing_in_A()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        using var page = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null));
        var confirmation = await LogoutFlow.PageStepAsync(page);

        var atB = new HostedBrowser(host, HostB);
        atB.Cookies[ProtocolContract.SessionCookie] = signedIn.Browser.Cookies[ProtocolContract.SessionCookie];
        using (var endSession = await atB.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null)))
        {
            var step = await LogoutFlow.PageStepAsync(endSession);
            Assert.Equal(StepNames.LoggedOut, step.Step);
            Assert.Equal(JsonValueKind.Null, step.Data.GetProperty("redirectTo").ValueKind);
        }

        atB.Cookies[ProtocolContract.SessionCookie] = signedIn.Browser.Cookies[ProtocolContract.SessionCookie];
        using (var confirmed = await atB.PostAsync(ProtocolContract.LogoutPath, LogoutFlow.Body(confirmation), confirmation.Csrf))
        {
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
            using var step = await HostedBrowser.StepAsync(confirmed);
            Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("data").GetProperty("redirectTo").ValueKind);
        }

        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Revoked}'"));
        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, signedIn.Refresh!);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
    }

    [Fact]
    public async Task Every_end_session_page_is_no_store_with_the_Hosted_headers_and_no_referrer()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        using var confirmation = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null));
        using var complete = await new HostedBrowser(host, HostA).GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null));
        foreach (var response in new[] { confirmation, complete })
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.True(response.Headers.CacheControl?.NoStore, "The page isn't no-store.");
            Assert.Equal(["no-referrer"], response.Headers.GetValues("Referrer-Policy"));
            Assert.Equal(["DENY"], response.Headers.GetValues("X-Frame-Options"));
            Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        }
    }

    [Fact]
    public async Task A_form_POST_without_the_Session_cookie_is_sent_to_the_GET_form_which_carries_it()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var sessionId = await SessionIdAsync(flow);

        // A relying party's cross-site form POST: SameSite=Lax keeps the Session cookie off it.
        var crossSite = new HostedBrowser(host, HostA);
        using var posted = await crossSite.PostFormAsync(
            ProtocolContract.EndSessionPath,
            [new("id_token_hint", signedIn.IdToken), new("post_logout_redirect_uri", LogoutUrl), new("state", "a&b=c d"), new("client_id", flow.ClientA.ClientId)]);

        Assert.Equal(HttpStatusCode.SeeOther, posted.StatusCode);
        Assert.True(posted.Headers.CacheControl?.NoStore, "The 303 isn't no-store.");
        var location = posted.Headers.Location!.OriginalString;
        Assert.StartsWith(ProtocolContract.EndSessionPath + "?", location, StringComparison.Ordinal);
        var query = QueryHelpers.ParseQuery(new Uri("https://x" + location).Query);
        Assert.True(query["id_token_hint"].ToString() == signedIn.IdToken, "The 303 doesn't carry the hint as posted.");
        Assert.Equal(LogoutUrl, query["post_logout_redirect_uri"].ToString());
        Assert.Equal("a&b=c d", query["state"].ToString());
        Assert.Equal(flow.ClientA.ClientId, query["client_id"].ToString());
        Assert.Empty(SetCookie.Of(posted));
        Assert.Equal("live", await SessionStateAsync(flow, sessionId));

        // The top-level GET it leads to carries the cookie, and shows the confirmation.
        using var page = await signedIn.Browser.GetAsync(location);
        var confirmation = await LogoutFlow.PageStepAsync(page);
        Assert.Equal(StepNames.Logout, confirmation.Step);
        Assert.Equal("a&b=c d", confirmation.Data.GetProperty("state").GetString());
        Assert.Equal("live", await SessionStateAsync(flow, sessionId));
    }

    [Fact]
    public async Task Log_out_with_no_Session_cookie_needs_no_CSRF_token_and_completes_with_its_target()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        using var page = await signedIn.Browser.GetAsync(LogoutFlow.EndSessionUrl(signedIn.IdToken, LogoutUrl, "xyz", null));
        var confirmation = await LogoutFlow.PageStepAsync(page);

        // The cookie is gone meanwhile (expired, or logged out in another tab): nothing to end, so no token is checked.
        signedIn.Browser.Cookies.Remove(ProtocolContract.SessionCookie);
        foreach (var csrf in new[] { null, "stale-or-anything" })
        {
            using var confirmed = await signedIn.Browser.PostAsync(ProtocolContract.LogoutPath, LogoutFlow.Body(confirmation), csrf);
            Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
            using var step = await HostedBrowser.StepAsync(confirmed);
            Assert.Equal(StepNames.LoggedOut, step.RootElement.GetProperty("step").GetString());
            Assert.Equal($"{LogoutUrl}?state=xyz", step.RootElement.GetProperty("data").GetProperty("redirectTo").GetString());
            LogoutFlow.AssertSessionCookieCleared(confirmed, signedIn.Browser);
        }

        // The Origin is still checked.
        using (var foreign = await signedIn.Browser.PostAsync(ProtocolContract.LogoutPath, LogoutFlow.Body(confirmation), null, "https://evil.example"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        }

        Assert.Equal(0L, await RevocationEventsAsync(flow));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND ended_at IS NULL"));
    }

    [Fact]
    public async Task Log_out_reads_a_body_of_four_parameters_at_their_limit_and_refuses_one_past_its_own()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        using var page = await signedIn.Browser.GetAsync(ProtocolContract.EndSessionPath);
        var confirmation = await LogoutFlow.PageStepAsync(page);
        const int max = 8 * 1024;

        // Each value at the kept limit, written entirely in \uXXXX escapes: the largest body a rendered confirmation can post.
        var escaped = string.Concat(Enumerable.Repeat("\\u0061", max));
        var atLimit = $$"""{"idTokenHint":"{{escaped}}","postLogoutRedirectUri":"{{escaped}}","state":"{{escaped}}","clientId":"{{escaped}}"}""";
        using (var refused = await RawLogoutAsync(host, signedIn.Browser, atLimit + new string(' ', (4 * max * 6) + 1024 - Encoding.UTF8.GetByteCount(atLimit) + 1), confirmation.Csrf!))
        {
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        }

        Assert.Equal("live", await SessionStateAsync(flow, await SessionIdAsync(flow)));
        using var accepted = await RawLogoutAsync(host, signedIn.Browser, atLimit, confirmation.Csrf!);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        using var step = await HostedBrowser.StepAsync(accepted);
        Assert.Equal(StepNames.LoggedOut, step.RootElement.GetProperty("step").GetString());
        Assert.Equal(1L, await RevocationEventsAsync(flow));
    }

    [Fact]
    public async Task The_state_is_encoded_into_a_logout_URL_that_already_has_a_query()
    {
        var flow = await SetupAsync();
        await SetLogoutUrlsAsync(flow, flow.ClientA.ApplicationId, "https://client.code.test/signed-out?from=app");
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        var redirectTo = await LogoutFlow.LogOutAsync(
            signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.IdToken, "https://client.code.test/signed-out?from=app", "a&b=c d", null));

        Assert.Equal("https://client.code.test/signed-out?from=app&state=a%26b%3Dc%20d", redirectTo);
        var query = QueryHelpers.ParseQuery(new Uri(redirectTo!).Query);
        Assert.Equal("app", query["from"].ToString());
        Assert.Equal("a&b=c d", query["state"].ToString());
    }

    [Fact]
    public async Task An_access_token_as_the_hint_gets_no_redirect()
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);

        // The access token's own aud is the userinfo URL; a forged one of the access token type naming the client is refused too.
        var forged = await ForgeAsync(flow, "at+jwt", [flow.ClientA.ClientId]);
        Assert.Null(await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(signedIn.AccessToken, LogoutUrl, null, null)));
        signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA, signedIn.Browser);
        Assert.Null(await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(forged, LogoutUrl, null, null)));
    }

    [Theory]
    [InlineData("JWT", true)]
    [InlineData(null, true)]
    [InlineData("oi_reft+jwt", false)]
    [InlineData("oi_auc+jwt", false)]
    public async Task Only_an_ID_tokens_own_type_or_none_is_a_hint(string? type, bool redirects)
    {
        var flow = await SetupAsync();
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var forged = await ForgeAsync(flow, type, [flow.ClientA.ClientId]);

        var redirectTo = await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(forged, LogoutUrl, null, null));

        Assert.Equal(redirects ? LogoutUrl : null, redirectTo);
    }

    [Fact]
    public async Task A_hint_with_several_audiences_gets_no_redirect()
    {
        var flow = await SetupAsync();
        var other = await flow.Database.CreateWebClientAsync(flow.A.TenantId, [Callback], "Other web client");
        await SetLogoutUrlsAsync(flow, other.ApplicationId, LogoutUrl);
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var forged = await ForgeAsync(flow, "JWT", [flow.ClientA.ClientId, other.ClientId]);

        Assert.Null(await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(forged, LogoutUrl, null, flow.ClientA.ClientId)));
    }

    [Fact]
    public async Task A_hint_whose_audience_is_the_system_Application_gets_no_redirect()
    {
        var flow = await SetupAsync();
        var system = await flow.Database.EnsureSystemApplicationAsync(flow.A.TenantId);
        await using var host = await flow.StartHostAsync();
        var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
        var forged = await ForgeAsync(flow, "JWT", [Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.Application, system)]);

        Assert.Null(await LogoutFlow.LogOutAsync(signedIn.Browser, LogoutFlow.EndSessionUrl(forged, LogoutUrl, null, null)));
    }

    /// <summary>
    /// A JWT the Tenant's current Signing Key signs through Transit, as OpenIddict's would be, with this Tenant's issuer and
    /// <paramref name="audiences"/>, of <paramref name="type"/> (none when null): only its type or audience is wrong.
    /// </summary>
    private async Task<string> ForgeAsync(CodeFlowSetup flow, string? type, string[] audiences)
    {
        var (keyId, version) = (
            await flow.Database.ScalarAsync<Guid>($"SELECT id FROM signing_key WHERE tenant_id = '{flow.A.TenantId}' AND purpose = 'signing' AND state = 'current'"),
            await flow.Database.ScalarAsync<int>($"SELECT transit_version FROM signing_key WHERE tenant_id = '{flow.A.TenantId}' AND purpose = 'signing' AND state = 'current'"));
        var kid = await CodeFlow.CurrentKidAsync(flow.Database, flow.A.TenantId);
        var header = new Dictionary<string, object> { ["alg"] = "RS256", ["kid"] = kid };
        if (type is not null)
        {
            header["typ"] = type;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object>
        {
            ["iss"] = flow.A.Issuer,
            ["sub"] = Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.User, flow.UserA),
            ["aud"] = audiences.Length == 1 ? audiences[0] : audiences,
            ["iat"] = now,
            ["exp"] = now + 900,
        };
        var input = $"{Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(JsonSerializer.Serialize(header))}.{Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload))}";
        using var custody = bao.Custody(OpenBaoFixture.Hosted);
        var signature = await custody.SignAsync(Gatekeep.Kernel.Secrets.KeyName.Signing(flow.A.TenantId, keyId), Encoding.ASCII.GetBytes(input), Cancellation);
        Assert.Equal(version, signature.KeyVersion);
        return $"{input}.{Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(signature.Value)}";
    }

    /// <summary>"Log out" with <paramref name="body"/> exactly as given, the browser's cookies, its Origin and <paramref name="csrf"/>.</summary>
    private static async Task<HttpResponseMessage> RawLogoutAsync(ProtocolHost host, HostedBrowser browser, string body, string csrf)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{HostA}{ProtocolContract.LogoutPath}"))
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation(ProtocolContract.CsrfHeader, csrf);
        request.Headers.TryAddWithoutValidation("Origin", browser.Origin);
        request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", browser.Cookies.Select(c => $"{c.Key}={c.Value}")));
        return await host.Http.SendAsync(request, Cancellation);
    }

    private async Task<CodeFlowSetup> SetupAsync()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await SetLogoutUrlsAsync(flow, flow.ClientA.ApplicationId, LogoutUrl);
        return flow;
    }

    private static Task SetLogoutUrlsAsync(CodeFlowSetup flow, Guid applicationId, params string[] urls) =>
        flow.Database.ExecuteAsync(
            $"UPDATE application SET post_logout_redirect_uris = ARRAY[{string.Join(", ", urls.Select(u => $"'{u}'"))}]::text[] WHERE id = '{applicationId}'");

    private static Task<Guid> SessionIdAsync(CodeFlowSetup flow) =>
        flow.Database.ScalarAsync<Guid>($"SELECT id FROM user_session WHERE tenant_id = '{flow.A.TenantId}' AND user_id = '{flow.UserA}' AND ended_at IS NULL");

    /// <summary>"live", or "ended" and its reason.</summary>
    private static Task<string> SessionStateAsync(CodeFlowSetup flow, Guid sessionId) =>
        flow.Database.ScalarAsync<string>(
            $"SELECT CASE WHEN ended_at IS NULL THEN 'live' ELSE 'ended ' || coalesce(end_reason, '') END FROM user_session WHERE id = '{sessionId}'");

    private static Task<long> RevocationEventsAsync(CodeFlowSetup flow) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{Revoked}'");

    /// <summary>The ID token with one character of its signature changed.</summary>
    private static string Tampered(string idToken)
    {
        var dot = idToken.LastIndexOf('.') + 10;
        return idToken[..dot] + (idToken[dot] == 'A' ? 'B' : 'A') + idToken[(dot + 1)..];
    }
}

/// <summary>Story 4.13's steps as a browser and a relying party take them, for the logout, cross-Tenant and canary tests.</summary>
internal static class LogoutFlow
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>A browser signed in at <paramref name="tenantHost"/>, and the ID and refresh tokens its code flow got.</summary>
    internal sealed record SignedIn(HostedBrowser Browser, string IdToken, string? Refresh, string AccessToken);

    /// <summary>A step page's step: its name, data and CSRF token.</summary>
    internal sealed record PageStep(string Step, JsonElement Data, string? Csrf);

    /// <summary>
    /// Signs <paramref name="user"/> in through Hosted Login in <paramref name="browser"/> (a new one by default), then
    /// exchanges the code: by Basic with <paramref name="secret"/>, or, for a public client, with its client_id alone.
    /// </summary>
    public static async Task<SignedIn> SignInAsync(
        ProtocolHost host,
        string tenantHost,
        string clientId,
        string? secret,
        Guid user,
        HostedBrowser? browser = null,
        string scope = "openid offline_access")
    {
        browser ??= new HostedBrowser(host, tenantHost);
        var pkce = Pkce.New();
        using var authorize = await browser.SignInAsync(CodeFlow.AuthorizeUrl(clientId, CodeFlowSetup.Callback, pkce, scope: scope), user);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var code = QueryHelpers.ParseQuery(authorize.Headers.Location!.Query)["code"].ToString();
        Assert.False(string.IsNullOrEmpty(code));

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = CodeFlowSetup.Callback,
            ["code_verifier"] = pkce.Verifier,
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://{tenantHost}{ProtocolContract.TokenPath}"));
        if (secret is null)
        {
            form["client_id"] = clientId;
        }
        else
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(clientId)}:{Uri.EscapeDataString(secret)}")));
        }

        request.Content = new FormUrlEncodedContent(form);
        using var response = await host.Http.SendAsync(request, Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var refresh = body.RootElement.TryGetProperty("refresh_token", out var r) ? r.GetString() : null;
        Assert.True(browser.Cookies.ContainsKey(ProtocolContract.SessionCookie), "The sign-in set no Session cookie.");
        return new SignedIn(
            browser, body.RootElement.GetProperty("id_token").GetString()!, refresh, body.RootElement.GetProperty("access_token").GetString()!);
    }

    /// <summary>The end-session endpoint's path and query, with each parameter that isn't null.</summary>
    public static string EndSessionUrl(string? idTokenHint, string? postLogoutRedirectUri, string? state, string? clientId)
    {
        var query = new List<KeyValuePair<string, string?>>();
        foreach (var (name, value) in new[] { ("id_token_hint", idTokenHint), ("post_logout_redirect_uri", postLogoutRedirectUri), ("state", state), ("client_id", clientId) })
        {
            if (value is not null)
            {
                query.Add(new(name, value));
            }
        }

        return ProtocolContract.EndSessionPath + QueryString.Create(query);
    }

    /// <summary>The step of an end-session page: 200, HTML, never a redirect.</summary>
    public static async Task<PageStep> PageStepAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        using var step = StepPage.Read(await response.Content.ReadAsStringAsync(Cancellation));
        var root = step.RootElement;
        var csrf = root.GetProperty("csrfToken");
        return new PageStep(
            root.GetProperty("step").GetString()!,
            root.GetProperty("data").Clone(),
            csrf.ValueKind == JsonValueKind.Null ? null : csrf.GetString());
    }

    /// <summary>The body "Log out" posts: the confirmation's parameters, unchanged.</summary>
    public static object Body(PageStep confirmation) => new
    {
        idTokenHint = Text(confirmation.Data, "idTokenHint"),
        postLogoutRedirectUri = Text(confirmation.Data, "postLogoutRedirectUri"),
        state = Text(confirmation.Data, "state"),
        clientId = Text(confirmation.Data, "clientId"),
    };

    /// <summary>"Log out" on <paramref name="confirmation"/>, as the client posts it.</summary>
    public static Task<HttpResponseMessage> ConfirmAsync(HostedBrowser browser, PageStep confirmation) =>
        browser.PostAsync(ProtocolContract.LogoutPath, Body(confirmation), confirmation.Csrf);

    /// <summary>Opens <paramref name="endSessionUrl"/>, confirms, and returns the completed logout's redirect target.</summary>
    public static async Task<string?> LogOutAsync(HostedBrowser browser, string endSessionUrl)
    {
        using var page = await browser.GetAsync(endSessionUrl);
        var confirmation = await PageStepAsync(page);
        Assert.Equal(StepNames.Logout, confirmation.Step);
        using var confirmed = await ConfirmAsync(browser, confirmation);
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        using var step = await HostedBrowser.StepAsync(confirmed);
        Assert.Equal(StepNames.LoggedOut, step.RootElement.GetProperty("step").GetString());
        AssertSessionCookieCleared(confirmed, browser);
        var target = step.RootElement.GetProperty("data").GetProperty("redirectTo");
        return target.ValueKind == JsonValueKind.Null ? null : target.GetString();
    }

    /// <summary>The response cleared the Session cookie, host-only, and the browser holds none.</summary>
    public static void AssertSessionCookieCleared(HttpResponseMessage response, HostedBrowser browser)
    {
        var cleared = Assert.Single(SetCookie.Of(response), c => SetCookie.Name(c) == ProtocolContract.SessionCookie);
        Assert.Equal(string.Empty, SetCookie.Value(cleared));
        Assert.Contains("Max-Age=0", SetCookie.Attributes(cleared));
        Assert.Contains("Path=/", SetCookie.Attributes(cleared));
        Assert.DoesNotContain(SetCookie.Attributes(cleared), a => a.StartsWith("Domain", StringComparison.OrdinalIgnoreCase));
        Assert.False(browser.Cookies.ContainsKey(ProtocolContract.SessionCookie));
    }

    private static string? Text(JsonElement data, string name) =>
        data.GetProperty(name) is { ValueKind: JsonValueKind.String } value ? value.GetString() : null;
}
