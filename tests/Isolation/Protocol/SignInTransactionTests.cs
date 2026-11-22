using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Stack;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 4.2 (FR-47, FR-8, NFR-3, NFR-4, AD-12): bound sign-in transactions and Sessions, at the HTTP level, through
/// the real Tenant resolution, Protocol registration and Hosted Login surface, against the real PostgreSQL as
/// <c>gk_hosted</c> and the real OpenBao. One test or more per row of the story's I/O matrix. The test host's credential
/// step is the test-only one, which authenticates only an identifier of its own form, so any other email gets the
/// release build's answer. No assertion prints a cookie, CSRF token or code: values are compared with
/// <c>Assert.True(a == b, …)</c>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed partial class SignInTransactionTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.signin.test";
    private const string HostB = "beta.signin.test";
    private const string Callback = CodeFlowSetup.Callback;
    private const string Release = "someone@example.com";

    private static readonly string[] CookieAttributes = ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Login_starts_with_a_bound_committed_transaction_and_a_host_only_cookie()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new HostedBrowser(host, HostA);

        using var authorize = await browser.GetAsync(Url(flow, state: "state-s1"));

        Assert.True(HostedBrowser.IsLoginRedirect(authorize), $"The request answered {(int)authorize.StatusCode}.");
        Assert.True(authorize.Headers.CacheControl?.NoStore, "The redirect to Login isn't no-store.");
        var cookie = Assert.Single(SetCookie.Of(authorize));
        Assert.Equal(ProtocolContract.TransactionCookie, SetCookie.Name(cookie));
        Assert.Equal(CookieAttributes, SetCookie.Attributes(cookie));
        var binding = SetCookie.Value(cookie);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", binding);

        // Committed though no code was issued, bound to Tenant A and the client, held only as its hash.
        Assert.Equal(
            $"{flow.A.TenantId}|{flow.ClientA.ApplicationId}|1||1800",
            await flow.Database.ScalarAsync<string>(
                $"SELECT tenant_id || '|' || application_id || '|' || step_version || '|' || array_to_string(completed_steps, ',') || '|' || extract(epoch FROM expires_at - created_at)::int FROM signin_transaction WHERE binding_hash = '\\x{HashHex(binding)}'"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM signin_transaction WHERE parameters::text LIKE '%{binding}%'"));
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.started"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
    }

    [Fact]
    public async Task Login_page_is_the_Login_step_with_its_life_its_CSRF_token_and_an_extension()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);

        using var page = await browser.GetAsync(ProtocolContract.LoginPath);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.True(page.Headers.CacheControl?.NoStore, "The step page isn't no-store.");
        Assert.Equal(["DENY"], page.Headers.GetValues("X-Frame-Options"));
        Assert.Equal(["no-referrer"], page.Headers.GetValues("Referrer-Policy"));
        using var step = StepPage.Read(await page.Content.ReadAsStringAsync(Cancellation));
        var root = step.RootElement;
        Assert.Equal("login", root.GetProperty("step").GetString());
        Assert.Equal(1, root.GetProperty("stepVersion").GetInt32());
        Assert.InRange(root.GetProperty("expiresInSeconds").GetInt32(), 1790, 1800);
        Assert.True(root.GetProperty("csrfToken").GetString() == Csrf(browser), "The CSRF token isn't the one derived from the cookie.");
        Assert.Equal(["tenant", "email", "error", "signupEnabled"], root.GetProperty("data").EnumerateObject().Select(p => p.Name));
        Assert.Equal(ProtocolDatabase.TestTenantName, root.GetProperty("data").GetProperty("tenant").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("data").GetProperty("email").ValueKind);
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.extended"));
    }

    [Fact]
    public async Task Continue_in_a_release_build_records_the_email_and_answers_the_Password_step()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await AddDatabaseConnectionAsync(flow);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var login = await browser.LoginStepAsync();

        using var continued = await browser.PostAsync(
            ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email = $"  {Release} " }, login.Csrf);

        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        Assert.True(continued.Headers.CacheControl?.NoStore, "The API answer isn't no-store.");
        Assert.Equal([SecurityHeadersPolicy], continued.Headers.GetValues("Content-Security-Policy"));
        using var step = await HostedBrowser.StepAsync(continued);
        // Story 4.9: the Password step, its email the one recorded, with no error.
        Assert.Equal("password", step.RootElement.GetProperty("step").GetString());
        Assert.Equal(2, step.RootElement.GetProperty("stepVersion").GetInt32());
        Assert.Equal(["tenant", "email", "error"], step.RootElement.GetProperty("data").EnumerateObject().Select(p => p.Name));
        Assert.Equal(Release, step.RootElement.GetProperty("data").GetProperty("email").GetString());
        Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("data").GetProperty("error").ValueKind);
        Assert.True(step.RootElement.GetProperty("csrfToken").GetString() == Csrf(browser), "The CSRF token isn't the one derived from the cookie.");
        Assert.Equal($"{Release}|2|identifier", await TransactionAsync(flow, "identifier || '|' || step_version || '|' || array_to_string(completed_steps, ',')"));
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.identified"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
    }

    [Fact]
    public async Task The_step_after_Continue_is_the_same_for_a_known_and_an_unknown_account()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await AddDatabaseConnectionAsync(flow);
        await using var host = await ProtocolHost.StartAsync(flow.Database.Hosted, bao, releaseSignIn: true);

        // Story 4.9: the same Password step for both, its body equal but for the email typed.
        var answers = new List<string>();
        foreach (var email in new[] { TestOnlyCredentialStep.Email(flow.UserA), Release })
        {
            var browser = await BeginAsync(host, flow);
            var login = await browser.LoginStepAsync();
            using var continued = await browser.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email }, login.Csrf);
            Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
            using var step = await HostedBrowser.StepAsync(continued);
            var root = step.RootElement;
            answers.Add($"{root.GetProperty("step").GetString()} {root.GetProperty("stepVersion").GetInt32()} {root.GetProperty("data").GetProperty("error").ValueKind}");
        }

        Assert.Equal(["password 2 Null", "password 2 Null"], answers);
    }

    /// <summary>Story 4.9: the Tenant A database Connection Login's email needs to lead to the Password step.</summary>
    private static Task AddDatabaseConnectionAsync(CodeFlowSetup flow) =>
        flow.Database.ExecuteAsync(TestTenants.DatabaseConnectionSql(flow.A.TenantId));

    [Theory]
    [InlineData("nope")]
    [InlineData("")]
    [InlineData("a@b")]
    [InlineData("two@@example.com")]
    [InlineData("spa ce@example.com")]
    public async Task A_bad_email_is_Login_with_its_field_error_and_writes_nothing(string email)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var login = await browser.LoginStepAsync();
        var before = await StateAsync(flow);

        using var continued = await browser.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email }, login.Csrf);

        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        using var step = await HostedBrowser.StepAsync(continued);
        Assert.Equal("login", step.RootElement.GetProperty("step").GetString());
        Assert.Equal(1, step.RootElement.GetProperty("stepVersion").GetInt32());
        Assert.Equal("email_invalid", step.RootElement.GetProperty("data").GetProperty("error").GetString());
        Assert.Equal(before, await StateAsync(flow));
    }

    [Fact]
    public async Task A_stale_step_version_gets_the_current_step_and_writes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var login = await browser.LoginStepAsync();
        using (var first = await browser.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = 1, email = Release }, login.Csrf))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await StateAsync(flow);
        using var stale = await browser.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = 1, email = "other@example.com" }, login.Csrf);

        Assert.Equal(HttpStatusCode.OK, stale.StatusCode);
        using var step = await HostedBrowser.StepAsync(stale);
        Assert.Equal("generic_error", step.RootElement.GetProperty("step").GetString());
        Assert.Equal("temporarily_unavailable", step.RootElement.GetProperty("data").GetProperty("code").GetString());
        Assert.Equal(before, await StateAsync(flow));
        Assert.Equal(Release, await TransactionAsync(flow, "identifier"));

        // A version from the future is stale too.
        var fresh = await BeginAsync(host, flow);
        var freshLogin = await fresh.LoginStepAsync();
        using var ahead = await fresh.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = 7, email = Release }, freshLogin.Csrf);
        using var current = await HostedBrowser.StepAsync(ahead);
        Assert.Equal("login", current.RootElement.GetProperty("step").GetString());
        Assert.Equal(1, current.RootElement.GetProperty("stepVersion").GetInt32());
    }

    [Theory]
    [InlineData("wrong-csrf", null, "csrf_mismatch")]
    [InlineData("no-csrf", null, "csrf_mismatch")]
    [InlineData("csrf-of-another-transaction", null, "csrf_mismatch")]
    [InlineData("right", "https://evil.signin.test", "origin_mismatch")]
    [InlineData("right", "http://acme.signin.test", "origin_mismatch")]
    [InlineData("right", "https://acme.signin.test:8443", "origin_mismatch")]
    [InlineData("right", "null", "origin_mismatch")]
    [InlineData("right", HostedBrowser.NoOrigin, "origin_mismatch")]
    public async Task A_wrong_CSRF_token_or_Origin_is_refused_with_403_writing_only_the_refusal(string csrf, string? origin, string code)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var login = await browser.LoginStepAsync();
        var other = await BeginAsync(host, flow);
        var before = await StateAsync(flow);

        var token = csrf switch
        {
            "right" => login.Csrf,
            "wrong-csrf" => login.Csrf[..^2] + (login.Csrf.EndsWith("AA", StringComparison.Ordinal) ? "BB" : "AA"),
            "csrf-of-another-transaction" => Csrf(other),
            _ => null,
        };

        foreach (var path in new[] { ProtocolContract.LoginIdentifierPath, ProtocolContract.LoginExtendPath })
        {
            using var refused = await browser.PostAsync(path, new { stepVersion = login.StepVersion, email = Release }, token, origin);

            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.True(refused.Headers.CacheControl?.NoStore, "The refusal isn't no-store.");
            using var step = await HostedBrowser.StepAsync(refused);
            Assert.Equal("generic_error", step.RootElement.GetProperty("step").GetString());
            Assert.Equal(code, step.RootElement.GetProperty("data").GetProperty("code").GetString());
        }

        Assert.Equal(before, await StateAsync(flow, exceptRefusals: true));
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = 'authentication.signin_transaction.refused' AND actor_kind = 'anonymous' AND target_id IS NULL"));
    }

    [Fact]
    public async Task The_test_credential_step_issues_a_Session_and_the_resume_issues_a_code_completing_the_transaction()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow, state: "state-s7");
        var login = await browser.LoginStepAsync();

        using var continued = await browser.PostAsync(
            ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email = TestOnlyCredentialStep.Email(flow.UserA) }, login.Csrf);

        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        var sessionCookie = Assert.Single(SetCookie.Of(continued));
        Assert.Equal(ProtocolContract.SessionCookie, SetCookie.Name(sessionCookie));
        var attributes = SetCookie.Attributes(sessionCookie);
        Assert.Equal(CookieAttributes, attributes.Take(4));
        var maxAge = long.Parse(Assert.Single(attributes.Skip(4)).Split('=')[1], System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(maxAge, (long)SecurityLimits.UserSessionAbsoluteDefault.TotalSeconds - 30, (long)SecurityLimits.UserSessionAbsoluteDefault.TotalSeconds);
        Assert.DoesNotContain(attributes, a => a.StartsWith("Domain", StringComparison.OrdinalIgnoreCase));

        // A new 256-bit identifier, held only as its SHA-256.
        var session = SetCookie.Value(sessionCookie);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", session);
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE id_hash = '\\x{HashHex(session)}' AND user_id = '{flow.UserA}'"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
        Assert.Equal(1L, await EventsAsync(flow, "sessions.session.started"));
        Assert.Equal(
            "identifier,authenticated|3|true",
            await TransactionAsync(flow, "array_to_string(completed_steps, ',') || '|' || step_version || '|' || (authenticated_session_id = (SELECT id FROM user_session))::text"));

        using var step = await HostedBrowser.StepAsync(continued);
        Assert.Equal("redirect", step.RootElement.GetProperty("step").GetString());
        Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("csrfToken").ValueKind);
        var location = step.RootElement.GetProperty("data").GetProperty("location").GetString()!;
        Assert.StartsWith(ProtocolContract.AuthorizePath + "?", location, StringComparison.Ordinal);
        var resume = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..]);
        Assert.Equal("1", resume["gk_resume"].ToString());
        Assert.Equal(flow.ClientA.ClientId, resume["client_id"].ToString());
        Assert.Equal("state-s7", resume["state"].ToString());

        using var resumed = await browser.GetAsync(location);

        Assert.Equal(HttpStatusCode.Found, resumed.StatusCode);
        var redirect = resumed.Headers.Location!;
        Assert.Equal(Callback, redirect.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(redirect.Query);
        Assert.True(query.ContainsKey("code"), "No code was issued.");
        Assert.Equal("state-s7", query["state"].ToString());
        Assert.DoesNotContain("gk_resume", redirect.OriginalString, StringComparison.Ordinal);
        var cleared = Assert.Single(SetCookie.Of(resumed));
        Assert.Equal($"{ProtocolContract.TransactionCookie}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0", cleared);
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction WHERE completed_at IS NOT NULL"));
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.completed"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>(
            "SELECT count(*) FROM \"authorization\" a JOIN user_session s ON s.tenant_id = a.tenant_id AND s.id = a.user_session_id"));
    }

    [Fact]
    public async Task Signing_in_again_with_a_live_Session_rotates_its_identifier_so_the_old_one_stops_working()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new HostedBrowser(host, HostA);
        using (var first = await browser.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(first);
        }

        var old = browser.Cookies[ProtocolContract.SessionCookie];
        var sessionId = await flow.Database.ScalarAsync<Guid>("SELECT id FROM user_session");

        // prompt=login doesn't reuse it, so the User authenticates again in the same browser.
        using (var again = await browser.SignInAsync(Url(flow, extra: [("prompt", "login")]), flow.UserA))
        {
            AssertCode(again);
        }

        var rotated = browser.Cookies[ProtocolContract.SessionCookie];
        Assert.False(rotated == old, "The Session identifier wasn't replaced.");
        Assert.Equal(sessionId, await flow.Database.ScalarAsync<Guid>("SELECT id FROM user_session"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE id_hash = '\\x{HashHex(rotated)}'"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE id_hash = '\\x{HashHex(old)}'"));
        Assert.Equal(1L, await EventsAsync(flow, "sessions.session.rotated"));
        Assert.Equal(1L, await EventsAsync(flow, "sessions.session.started"));

        // The old value no longer reuses anything; the new one does.
        var stale = new HostedBrowser(host, HostA);
        stale.Cookies[ProtocolContract.SessionCookie] = old;
        using (var refused = await stale.GetAsync(Url(flow)))
        {
            Assert.True(HostedBrowser.IsLoginRedirect(refused), "The old Session identifier was reused.");
        }

        var current = new HostedBrowser(host, HostA);
        current.Cookies[ProtocolContract.SessionCookie] = rotated;
        using var reused = await current.GetAsync(Url(flow));
        AssertCode(reused);
    }

    [Fact]
    public async Task Another_Users_Session_cookie_is_never_rotated_into_this_Users_sign_in()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var userB = await flow.Database.AddUserAsync(flow.A.TenantId);
        var browser = new HostedBrowser(host, HostA);
        using (var first = await browser.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(first);
        }

        var userAsSession = browser.Cookies[ProtocolContract.SessionCookie];
        using (var other = await browser.SignInAsync(Url(flow, extra: [("prompt", "login")]), userB))
        {
            AssertCode(other);
        }

        Assert.Equal(2L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE id_hash = '\\x{HashHex(userAsSession)}' AND user_id = '{flow.UserA}'"));
        Assert.Equal(0L, await EventsAsync(flow, "sessions.session.rotated"));
    }

    [Fact]
    public async Task A_live_Session_is_reused_with_no_Login_and_touched_but_prompt_login_goes_to_Login()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new HostedBrowser(host, HostA);
        using (var first = await browser.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(first);
        }

        await flow.Database.BackdateAsync("UPDATE user_session SET idle_expires_at = now() + interval '1 hour'");
        var transactions = await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction");
        var events = await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}'");

        using (var reused = await browser.GetAsync(Url(flow, state: "state-reuse")))
        {
            AssertCode(reused);
            Assert.Equal("state-reuse", QueryHelpers.ParseQuery(reused.Headers.Location!.Query)["state"].ToString());
            Assert.Empty(SetCookie.Of(reused));
        }

        Assert.Equal(transactions, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
        Assert.Equal(events, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}'"));
        Assert.True(await flow.Database.ScalarAsync<bool>("SELECT idle_expires_at > now() + interval '2 days' FROM user_session"), "The reused Session's idle expiry wasn't touched.");
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM \"authorization\""));

        using var login = await browser.GetAsync(Url(flow, extra: [("prompt", "login")]));
        Assert.True(HostedBrowser.IsLoginRedirect(login), "prompt=login reused the Session.");

        // An ended or expired Session is never reused.
        await flow.Database.BackdateAsync("UPDATE user_session SET idle_expires_at = now() - interval '1 second'");
        using var expired = await browser.GetAsync(Url(flow));
        Assert.True(HostedBrowser.IsLoginRedirect(expired), "An expired Session was reused.");
    }

    [Fact]
    public async Task Prompt_none_keeps_login_required_even_with_a_live_Session()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new HostedBrowser(host, HostA);
        using (var first = await browser.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(first);
        }

        using var none = await browser.GetAsync(Url(flow, extra: [("prompt", "none")]));

        Assert.Equal(HttpStatusCode.Found, none.StatusCode);
        Assert.Equal("login_required", QueryHelpers.ParseQuery(none.Headers.Location!.Query)["error"].ToString());
    }

    [Fact]
    public async Task A_resume_before_authentication_or_with_no_cookie_is_refused_and_writes_only_the_refusal()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);

        // Login hasn't passed: the cookie's transaction has no authentication.
        using (var early = await browser.GetAsync(Url(flow, extra: [(ProtocolContract.ResumeParameter, "1")])))
        {
            await AssertRefusedAsync(early);
        }

        // After Continue, still not authenticated.
        var continuing = await BeginAsync(host, flow);
        var login = await continuing.LoginStepAsync();
        using (await continuing.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email = Release }, login.Csrf))
        {
        }

        using (var identified = await continuing.GetAsync(Url(flow, extra: [(ProtocolContract.ResumeParameter, "1")])))
        {
            await AssertRefusedAsync(identified);
        }

        // No cookie at all.
        using (var none = await new HostedBrowser(host, HostA).GetAsync(Url(flow, extra: [(ProtocolContract.ResumeParameter, "1")])))
        {
            await AssertRefusedAsync(none);
        }

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction WHERE completed_at IS NOT NULL"));
        Assert.Equal(3L, await EventsAsync(flow, "authentication.signin_transaction.refused"));
        Assert.Equal(0L, await EventsAsync(flow, "authentication.signin_transaction.completed"));
    }

    [Fact]
    public async Task A_replayed_resume_or_one_for_another_client_is_refused()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var other = await flow.Database.CreateWebClientAsync(flow.A.TenantId, [Callback], "Other web client");

        // Authenticated, then resumed for another Application with the same cookie: refused, and the transaction is untouched.
        var browser = await BeginAsync(host, flow);
        var location = await AuthenticateAsync(browser, flow.UserA);
        var cookie = browser.Cookies[ProtocolContract.TransactionCookie];
        using (var elsewhere = await browser.GetAsync(location.Replace(flow.ClientA.ClientId, other.ClientId, StringComparison.Ordinal)))
        {
            await AssertRefusedAsync(elsewhere);
        }

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction WHERE completed_at IS NOT NULL"));

        // The refusal cleared the cookie; the same browser presenting it again completes, once.
        browser.Cookies[ProtocolContract.TransactionCookie] = cookie;
        using (var resumed = await browser.GetAsync(location))
        {
            AssertCode(resumed);
        }

        browser.Cookies[ProtocolContract.TransactionCookie] = cookie;
        using (var replayed = await browser.GetAsync(location))
        {
            await AssertRefusedAsync(replayed);
        }

        // And Login refuses a completed transaction too.
        browser.Cookies[ProtocolContract.TransactionCookie] = cookie;
        using (var page = await browser.GetAsync(ProtocolContract.LoginPath))
        {
            await StepPage.AssertGenericErrorAsync(page, ProtocolDatabase.TestTenantName, "invalid_transaction");
            Assert.Contains($"{ProtocolContract.TransactionCookie}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0", SetCookie.Of(page));
        }

        Assert.Equal(1L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM \"authorization\""));
        Assert.Equal(3L, await EventsAsync(flow, "authentication.signin_transaction.refused"));
    }

    [Fact]
    public async Task Tenant_As_cookies_find_nothing_at_Tenant_B_and_B_s_nothing_at_A()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var clientB = await flow.Database.CreateWebClientAsync(flow.B.TenantId, [Callback]);
        var userB = await flow.Database.AddUserAsync(flow.B.TenantId);

        // Each Tenant's browser signs in and holds a live Session, then begins another transaction.
        var atA = new HostedBrowser(host, HostA);
        using (var signedIn = await atA.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(signedIn);
        }

        var atB = new HostedBrowser(host, HostB);
        using (var signedIn = await atB.SignInAsync(CodeFlow.AuthorizeUrl(clientB.ClientId, Callback, Pkce.New()), userB))
        {
            AssertCode(signedIn);
        }

        using (await atA.GetAsync(Url(flow, extra: [("prompt", "login")])))
        {
        }

        using (await atB.GetAsync(CodeFlow.AuthorizeUrl(clientB.ClientId, Callback, Pkce.New(), extra: [("prompt", "login")])))
        {
        }

        Assert.All(atA.SetCookies.Concat(atB.SetCookies), c => Assert.DoesNotContain(SetCookie.Attributes(c), a => a.StartsWith("Domain", StringComparison.OrdinalIgnoreCase)));
        const string Rows = "SELECT string_agg(id || '/' || expires_at::text || '/' || step_version, ',' ORDER BY id) FROM signin_transaction";
        var ids = await flow.Database.ScalarAsync<string>("SELECT string_agg(id::text, ',') FROM signin_transaction");
        var stateBefore = await flow.Database.ScalarAsync<string>(Rows);

        foreach (var (from, to, toHost, toClient) in new[]
        {
            (atA, atB, HostB, clientB.ClientId),
            (atB, atA, HostA, flow.ClientA.ClientId),
        })
        {
            // The other Tenant's transaction cookie: not found, refused at Login and at the API.
            var crossed = new HostedBrowser(host, toHost);
            crossed.Cookies[ProtocolContract.TransactionCookie] = from.Cookies[ProtocolContract.TransactionCookie];
            using (var page = await crossed.GetAsync(ProtocolContract.LoginPath))
            {
                await StepPage.AssertGenericErrorAsync(page, ProtocolDatabase.TestTenantName, "invalid_transaction");
            }

            crossed.Cookies[ProtocolContract.TransactionCookie] = from.Cookies[ProtocolContract.TransactionCookie];
            using (var api = await crossed.PostAsync(ProtocolContract.LoginExtendPath, new { }, Csrf(crossed)))
            {
                Assert.Equal(HttpStatusCode.BadRequest, api.StatusCode);
                using var step = await HostedBrowser.StepAsync(api);
                Assert.Equal("invalid_transaction", step.RootElement.GetProperty("data").GetProperty("code").GetString());
            }

            // The other Tenant's Session cookie: never reused, so the request goes to Login.
            var session = new HostedBrowser(host, toHost);
            session.Cookies[ProtocolContract.SessionCookie] = from.Cookies[ProtocolContract.SessionCookie];
            using var authorize = await session.GetAsync(CodeFlow.AuthorizeUrl(toClient, Callback, Pkce.New()));
            Assert.True(HostedBrowser.IsLoginRedirect(authorize), $"A Session cookie was reused at {toHost}.");
        }

        // Neither Tenant's transactions moved, and no Session was reused or started.
        Assert.Equal(stateBefore, await flow.Database.ScalarAsync<string>($"{Rows} WHERE id::text = ANY (string_to_array('{ids}', ','))"));
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = 'authentication.signin_transaction.refused'"));
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.B.TenantId}' AND type_code = 'authentication.signin_transaction.refused'"));
    }

    [Fact]
    public async Task An_expired_transaction_restarts_at_Login_with_the_email_kept_under_a_new_cookie()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow, state: "state-expired");
        var login = await browser.LoginStepAsync();
        using (await browser.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email = Release }, login.Csrf))
        {
        }

        var old = browser.Cookies[ProtocolContract.TransactionCookie];
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '40 minutes', expires_at = now() - interval '10 minutes'");

        // The API on an expired transaction sends the client to Login, writing nothing.
        using (var extend = await browser.PostAsync(ProtocolContract.LoginExtendPath, new { }, Csrf(browser)))
        {
            Assert.Equal(HttpStatusCode.OK, extend.StatusCode);
            using var step = await HostedBrowser.StepAsync(extend);
            Assert.Equal("redirect", step.RootElement.GetProperty("step").GetString());
            Assert.Equal(ProtocolContract.LoginPath, step.RootElement.GetProperty("data").GetProperty("location").GetString());
        }

        using var page = await browser.GetAsync(ProtocolContract.LoginPath);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var cookie = Assert.Single(SetCookie.Of(page));
        Assert.Equal(CookieAttributes, SetCookie.Attributes(cookie));
        var renewed = SetCookie.Value(cookie);
        Assert.False(renewed == old, "The restart kept the old binding.");
        using var restarted = StepPage.Read(await page.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("login", restarted.RootElement.GetProperty("step").GetString());
        Assert.Equal(1, restarted.RootElement.GetProperty("stepVersion").GetInt32());
        Assert.InRange(restarted.RootElement.GetProperty("expiresInSeconds").GetInt32(), 1790, 1800);
        Assert.Equal(Release, restarted.RootElement.GetProperty("data").GetProperty("email").GetString());
        Assert.True(restarted.RootElement.GetProperty("csrfToken").GetString() == Csrf(browser), "The CSRF token isn't the new cookie's.");

        // The same Application and parameters, the email kept, and nothing passed yet.
        Assert.Equal(
            $"{flow.ClientA.ApplicationId}|{Release}||1|true",
            await flow.Database.ScalarAsync<string>(
                $"SELECT application_id || '|' || identifier || '|' || array_to_string(completed_steps, ',') || '|' || step_version || '|' || (parameters = (SELECT parameters FROM signin_transaction WHERE binding_hash <> '\\x{HashHex(renewed)}'))::text FROM signin_transaction WHERE binding_hash = '\\x{HashHex(renewed)}'"));
        Assert.Equal(2L, await EventsAsync(flow, "authentication.signin_transaction.started"));

        // Continue on the restarted transaction, and the resume carries the original request's state.
        var next = await browser.LoginStepAsync();
        using var continued = await browser.PostAsync(
            ProtocolContract.LoginIdentifierPath, new { stepVersion = next.StepVersion, email = TestOnlyCredentialStep.Email(flow.UserA) }, next.Csrf);
        using var redirect = await HostedBrowser.StepAsync(continued);
        using var resumed = await browser.GetAsync(redirect.RootElement.GetProperty("data").GetProperty("location").GetString()!);
        AssertCode(resumed);
        Assert.Equal("state-expired", QueryHelpers.ParseQuery(resumed.Headers.Location!.Query)["state"].ToString());
    }

    [Fact]
    public async Task A_restarted_Login_keeps_Sign_up_while_the_database_Connection_lets_users_sign_up()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await flow.Database.ExecuteAsync(TestTenants.DatabaseConnectionSql(flow.A.TenantId));
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow, state: "state-restart-signup");
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '40 minutes', expires_at = now() - interval '10 minutes'");

        using var page = await browser.GetAsync(ProtocolContract.LoginPath);

        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Single(SetCookie.Of(page));
        using var restarted = StepPage.Read(await page.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("login", restarted.RootElement.GetProperty("step").GetString());
        Assert.True(restarted.RootElement.GetProperty("data").GetProperty("signupEnabled").GetBoolean());
    }

    [Fact]
    public async Task A_transaction_expired_past_the_restart_retention_is_refused()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '3 hours', expires_at = now() - interval '61 minutes'");

        using var page = await browser.GetAsync(ProtocolContract.LoginPath);

        await StepPage.AssertGenericErrorAsync(page, ProtocolDatabase.TestTenantName, "invalid_transaction");
        Assert.Equal(1L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.refused"));
    }

    [Fact]
    public async Task Keep_going_slides_the_life_back_to_30_minutes_with_an_extension_event()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '28 minutes', expires_at = now() + interval '2 minutes'");

        using var extended = await browser.PostAsync(ProtocolContract.LoginExtendPath, new { }, Csrf(browser));

        Assert.Equal(HttpStatusCode.OK, extended.StatusCode);
        using var step = await HostedBrowser.StepAsync(extended);
        Assert.Equal("login", step.RootElement.GetProperty("step").GetString());
        Assert.InRange(step.RootElement.GetProperty("expiresInSeconds").GetInt32(), 1790, 1800);
        Assert.True(await flow.Database.ScalarAsync<bool>("SELECT expires_at > now() + interval '29 minutes' FROM signin_transaction"), "The life wasn't slid.");
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.extended"));
    }

    [Fact]
    public async Task A_body_that_isnt_the_identifier_steps_is_invalid_request_and_writes_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var login = await browser.LoginStepAsync();
        var before = await StateAsync(flow);

        foreach (object body in new object[] { new { email = Release }, new { stepVersion = "1", email = Release }, new { stepVersion = 1, email = 5 }, new[] { 1 } })
        {
            using var refused = await browser.PostAsync(ProtocolContract.LoginIdentifierPath, body, login.Csrf);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            using var step = await HostedBrowser.StepAsync(refused);
            Assert.Equal("invalid_request", step.RootElement.GetProperty("data").GetProperty("code").GetString());
        }

        Assert.Equal(before, await StateAsync(flow));
    }

    [Theory]
    [InlineData("redirect_uri")]
    [InlineData("code_challenge")]
    [InlineData("state")]
    public async Task A_resume_whose_parameters_differ_from_the_transactions_is_refused_and_issues_no_code(string tampered)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow, state: "state-genuine");
        var location = await AuthenticateAsync(browser, flow.UserA);
        var cookie = browser.Cookies[ProtocolContract.TransactionCookie];

        var query = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])
            .ToDictionary(p => p.Key, p => (string?)p.Value.ToString(), StringComparer.Ordinal);
        query[tampered] = tampered switch
        {
            "redirect_uri" => CodeFlowSetup.OtherCallback,
            "code_challenge" => Pkce.New().Challenge,
            _ => "state-swapped",
        };

        using (var swapped = await browser.GetAsync(ProtocolContract.AuthorizePath + QueryString.Create(query)))
        {
            await AssertRefusedAsync(swapped);
        }

        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction WHERE completed_at IS NOT NULL"));
        Assert.Equal(0L, await EventsAsync(flow, "authentication.signin_transaction.completed"));
        Assert.Equal(1L, await EventsAsync(flow, "authentication.signin_transaction.refused"));

        // The transaction is untouched: the genuine resume still completes it.
        browser.Cookies[ProtocolContract.TransactionCookie] = cookie;
        using var genuine = await browser.GetAsync(location);
        AssertCode(genuine);
        Assert.Equal("state-genuine", QueryHelpers.ParseQuery(genuine.Headers.Location!.Query)["state"].ToString());
    }

    [Fact]
    public async Task A_resume_of_an_authenticated_transaction_since_expired_is_refused()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var location = await AuthenticateAsync(browser, flow.UserA);
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '40 minutes', expires_at = now() - interval '1 second'");

        using var resumed = await browser.GetAsync(location);

        await AssertRefusedAsync(resumed);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await EventsAsync(flow, "authentication.signin_transaction.completed"));
    }

    [Theory]
    [InlineData("UPDATE user_session SET ended_at = now(), end_reason = 'logout'")]
    [InlineData("UPDATE user_session SET idle_expires_at = now() - interval '1 second'")]
    public async Task A_resume_whose_Session_has_ended_or_expired_is_refused(string endSession)
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var location = await AuthenticateAsync(browser, flow.UserA);
        await flow.Database.BackdateAsync(endSession);

        using var resumed = await browser.GetAsync(location);

        await AssertRefusedAsync(resumed);
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM token"));
        Assert.Equal(0L, await EventsAsync(flow, "authentication.signin_transaction.completed"));
    }

    [Fact]
    public async Task Signing_in_again_after_the_Session_expired_starts_a_new_Session_and_rotates_nothing()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new HostedBrowser(host, HostA);
        using (var first = await browser.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(first);
        }

        var old = browser.Cookies[ProtocolContract.SessionCookie];
        await flow.Database.BackdateAsync("UPDATE user_session SET idle_expires_at = now() - interval '1 second'");
        const string Row = "SELECT id || '/' || encode(id_hash, 'hex') || '/' || auth_time::text || '/' || idle_expires_at::text FROM user_session";
        var before = await flow.Database.ScalarAsync<string>(Row);

        using (var again = await browser.SignInAsync(Url(flow), flow.UserA))
        {
            AssertCode(again);
        }

        Assert.False(browser.Cookies[ProtocolContract.SessionCookie] == old, "The expired Session's identifier was kept.");
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM user_session"));
        Assert.Equal(before, await flow.Database.ScalarAsync<string>($"{Row} WHERE id_hash = '\\x{HashHex(old)}'"));
        Assert.Equal(2L, await EventsAsync(flow, "sessions.session.started"));
        Assert.Equal(0L, await EventsAsync(flow, "sessions.session.rotated"));
    }

    [Fact]
    public async Task A_restarted_transactions_old_cookie_is_refused_at_Login()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await BeginAsync(host, flow);
        var old = browser.Cookies[ProtocolContract.TransactionCookie];
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '40 minutes', expires_at = now() - interval '10 minutes'");

        using (var restarted = await browser.GetAsync(ProtocolContract.LoginPath))
        {
            Assert.Equal(HttpStatusCode.OK, restarted.StatusCode);
        }

        var replay = new HostedBrowser(host, HostA);
        replay.Cookies[ProtocolContract.TransactionCookie] = old;
        using var refused = await replay.GetAsync(ProtocolContract.LoginPath);

        await StepPage.AssertGenericErrorAsync(refused, ProtocolDatabase.TestTenantName, "invalid_transaction");
        Assert.Equal(2L, await flow.Database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
        Assert.Equal(2L, await EventsAsync(flow, "authentication.signin_transaction.started"));
        Assert.Equal(0L, await flow.Database.ScalarAsync<long>($"SELECT count(*) FROM signin_transaction WHERE binding_hash = '\\x{HashHex(old)}'"));
    }

    [Fact]
    public async Task A_Token_Familys_refreshed_ID_token_keeps_its_own_auth_time_after_the_Session_rotates()
    {
        var flow = await CodeFlowSetup.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new HostedBrowser(host, HostA);
        var firstAuth = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(10);
        var pkce = Pkce.New();

        string code;
        using (var first = await browser.SignInAsync(
            CodeFlow.AuthorizeUrl(flow.ClientA.ClientId, Callback, pkce, scope: "openid offline_access"), flow.UserA, firstAuth))
        {
            AssertCode(first);
            code = QueryHelpers.ParseQuery(first.Headers.Location!.Query)["code"].ToString();
        }

        using var tokens = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, Callback, pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, tokens.Status);
        var refresh = tokens.Body.RootElement.GetProperty("refresh_token").GetString()!;

        // The same browser signs in again: the Session rotates, and its auth_time becomes now.
        using (var again = await browser.SignInAsync(Url(flow, extra: [("prompt", "login")]), flow.UserA))
        {
            AssertCode(again);
        }

        Assert.Equal(1L, await EventsAsync(flow, "sessions.session.rotated"));
        Assert.True(await flow.Database.ScalarAsync<bool>("SELECT auth_time > now() - interval '1 minute' FROM user_session"), "The Session's auth_time didn't move.");

        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, refresh);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        var idToken = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(refreshed.Body.RootElement.GetProperty("id_token").GetString()!);
        Assert.Equal(
            firstAuth.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            idToken.GetClaim("auth_time").Value);
    }

    [Fact]
    public void The_clients_expiry_warning_is_the_limits_files()
    {
        var source = File.ReadAllText(Path.Combine(Repository.Root, "apps", "hosted-login", "src", "expiry.ts"));
        var match = WarningConstant().Match(source);

        Assert.True(match.Success, "apps/hosted-login/src/expiry.ts holds no EXPIRY_WARNING_SECONDS.");
        Assert.Equal((int)SecurityLimits.SignInExpiryWarning.TotalSeconds, int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>A valid authorization request for client A, as its path and query.</summary>
    private static string Url(CodeFlowSetup flow, string state = "state", (string Name, string Value)[]? extra = null) =>
        CodeFlow.AuthorizeUrl(flow.ClientA.ClientId, Callback, Pkce.New(), state: state, extra: extra);

    /// <summary>A fresh browser whose valid authorization request went to Login, holding its transaction cookie.</summary>
    private static async Task<HostedBrowser> BeginAsync(ProtocolHost host, CodeFlowSetup flow, string state = "state")
    {
        var browser = new HostedBrowser(host, HostA);
        using var authorize = await browser.GetAsync(Url(flow, state));
        Assert.True(HostedBrowser.IsLoginRedirect(authorize), $"The request answered {(int)authorize.StatusCode}, not the redirect to Login.");
        return browser;
    }

    /// <summary>Continue with the test-only credential step's email for <paramref name="user"/>: the resume location.</summary>
    private static async Task<string> AuthenticateAsync(HostedBrowser browser, Guid user)
    {
        var login = await browser.LoginStepAsync();
        using var continued = await browser.PostAsync(
            ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email = TestOnlyCredentialStep.Email(user) }, login.Csrf);
        using var step = await HostedBrowser.StepAsync(continued);
        Assert.Equal("redirect", step.RootElement.GetProperty("step").GetString());
        return step.RootElement.GetProperty("data").GetProperty("location").GetString()!;
    }

    private static void AssertCode(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(Callback, location.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.False(query.TryGetValue("error", out var error), $"The request failed: {error}.");
        Assert.True(query.ContainsKey("code"), "No code was issued.");
    }

    /// <summary>A refused resume: Generic error <c>invalid_transaction</c>, 400, the cookie cleared, no code.</summary>
    private static async Task AssertRefusedAsync(HttpResponseMessage response)
    {
        await StepPage.AssertGenericErrorAsync(response, ProtocolDatabase.TestTenantName, "invalid_transaction");
        Assert.Contains($"{ProtocolContract.TransactionCookie}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0", SetCookie.Of(response));
    }

    /// <summary>The CSRF token Hosted Login derives from the browser's transaction cookie, computed here independently.</summary>
    private static string Csrf(HostedBrowser browser)
    {
        var value = Encoding.ASCII.GetBytes(browser.Cookies[ProtocolContract.TransactionCookie]);
        return Base64UrlEncoder.Encode(SHA256.HashData([.. "gatekeep-signin-csrf\0"u8.ToArray(), .. value]));
    }

    private static string HashHex(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    private static Task<long> EventsAsync(CodeFlowSetup flow, string code) =>
        flow.Database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.A.TenantId}' AND type_code = '{code}'");

    /// <summary>An expression over the one transaction of Tenant A.</summary>
    private static Task<string> TransactionAsync(CodeFlowSetup flow, string expression) =>
        flow.Database.ScalarAsync<string>($"SELECT {expression} FROM signin_transaction WHERE tenant_id = '{flow.A.TenantId}'");

    /// <summary>Everything a refused or stale request must leave as it was: the transactions, Sessions and events.</summary>
    private static Task<string> StateAsync(CodeFlowSetup flow, bool exceptRefusals = false) =>
        flow.Database.ScalarAsync<string>(
            $"""
            SELECT 'transactions ' || (SELECT count(*) FROM signin_transaction)
                   || ' rows ' || coalesce((SELECT string_agg(id || '/' || expires_at::text || '/' || step_version || '/' || coalesce(identifier, '') || '/' || array_to_string(completed_steps, ','), ',' ORDER BY id) FROM signin_transaction), '')
                   || ' sessions ' || (SELECT count(*) FROM user_session)
                   || ' events ' || (SELECT count(*) FROM audit_event WHERE {(exceptRefusals ? "type_code <> 'authentication.signin_transaction.refused'" : "true")})
            """);

    private const string SecurityHeadersPolicy = Gatekeep.Adapters.Hosting.SecurityHeaders.ContentSecurityPolicy;

    [GeneratedRegex(@"EXPIRY_WARNING_SECONDS\s*=\s*(\d+)")]
    private static partial Regex WarningConstant();
}
