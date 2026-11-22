using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Notifications.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.9 (FR-17, FR-23, NFR-2, NFR-6, NFR-20): password sign-in, at the HTTP level, through the real Hosted Login
/// surface, PostgreSQL as <c>gk_hosted</c> and OpenBao. Login's Continue leads every identifier to the same Password step;
/// a submit runs one Argon2id verification whatever the account, and answers a wrong password, no password and no account
/// alike, in content, status and timing; the correct one starts a Session and the Application gets its code. Also the
/// sign-in limits, the audit events, the hash upgrade and the User token audience. One test or more per row of the
/// story's I/O matrix. No assertion prints a password, cookie, hash or token.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SignInTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.signin-password.test";
    private const string HostB = "beta.signin-password.test";
    private const string Known = "known.user@example.com";
    private const string Unknown = "nobody@example.com";
    private const string WrongPassword = "Wrong-Horse-9battery";
    private const string Succeeded = "authentication.signin.succeeded";
    private const string Failed = "authentication.signin.failed";

    /// <summary>The stated tolerance (NFR-20, <c>docs/threat-model.md</c> T-6): the two medians differ by at most this.</summary>
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(100);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Continue_answers_the_same_Password_step_for_a_known_and_an_unknown_email_looking_nothing_up()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();

        using var known = await (await flow.BeginAsync(host, HostA)).IdentifyAsync(Known);
        using var unknown = await (await flow.BeginAsync(host, HostA)).IdentifyAsync(Unknown);

        Assert.Equal(StepNames.Password, SignUpFlow.Name(known));
        Assert.Equal(Known, SignUpFlow.Data(known).GetProperty("email").GetString());
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(known).GetProperty("error").ValueKind);
        Assert.Equal(Comparable(unknown, Unknown), Comparable(known, Known));
        Assert.Equal(0L, await flow.EventsAsync(Failed));
    }

    [Fact]
    public async Task With_the_database_Connection_disabled_Continue_is_temporarily_unavailable_for_every_email()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await flow.Database.ExecuteAsync($"UPDATE connection SET enabled = false WHERE tenant_id = '{flow.TenantA}'");
        await using var host = await flow.StartHostAsync();

        foreach (var email in new[] { Known, Unknown })
        {
            using var step = await (await flow.BeginAsync(host, HostA)).IdentifyAsync(email);
            Assert.Equal(StepNames.GenericError, SignUpFlow.Name(step));
            Assert.Equal("temporarily_unavailable", SignUpFlow.Data(step).GetProperty("code").GetString());
        }
    }

    [Fact]
    public async Task The_correct_password_starts_a_pwd_Session_under_the_Connection_and_the_Application_gets_its_code()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);

        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.True(browser.Http.Cookies.ContainsKey(ProtocolContract.SessionCookie), "No Session cookie was set.");
        var connection = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM connection WHERE tenant_id = '{flow.TenantA}'");
        Assert.Equal(
            $"pwd|{connection}|true",
            await flow.Database.ScalarAsync<string>(
                $"SELECT array_to_string(amr, ',') || '|' || connection_id || '|' || (auth_time > now() - interval '1 minute')::text FROM user_session WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}'"));
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}' AND type_code = '{Succeeded}' AND actor_kind = 'user' AND actor_id = '{user}' AND target_id = '{user}'"));
        Assert.Equal(0L, await flow.EventsAsync(Failed));

        // The resume issues the code, and its tokens carry the password sign-in.
        using var resumed = await browser.FollowAsync(SignUpFlow.Data(redirect).GetProperty("location").GetString()!);
        Assert.Equal(HttpStatusCode.Found, resumed.StatusCode);
        var code = QueryHelpers.ParseQuery(resumed.Headers.Location!.Query)["code"].ToString();
        using var issued = await CodeFlow.ExchangeAsync(
            host, HostA, flow.Flow.ClientA.ClientId, flow.Flow.ClientA.Secret, code, CodeFlowSetup.Callback, browser.Pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        var idToken = issued.Body.RootElement.GetProperty("id_token").GetString()!;
        var payload = Encoding.UTF8.GetString(Base64UrlDecode(idToken.Split('.')[1]));
        Assert.Contains("\"amr\":[\"pwd\"]", payload, StringComparison.Ordinal);
        Assert.Contains("\"auth_time\":", payload, StringComparison.Ordinal);

        // No API named and no default audience: the access token is for the Tenant's userinfo endpoint only.
        Assert.Equal([$"{flow.Flow.A.Issuer}connect/userinfo"], new JsonWebToken(issued.AccessToken).Audiences);
    }

    [Fact]
    public async Task An_email_typed_in_another_case_signs_in()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known.ToUpperInvariant());
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);

        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}'"));
    }

    [Fact]
    public async Task On_a_Dev_Tenant_with_verification_off_an_unverified_User_signs_in_with_no_email()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB, verificationOff: true);
        var (user, _) = await flow.AddPasswordUserAsync(Known, verified: false);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);

        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.Equal("pwd", await flow.Database.ScalarAsync<string>(
            $"SELECT string_agg(array_to_string(amr, ','), ';') FROM user_session WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}'"));
        Assert.Empty(host.Jobs.Jobs);
    }

    [Fact]
    public async Task Signing_in_again_with_the_live_Session_of_the_same_User_rotates_it()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using (var first = await browser.IdentifyAsync(Known))
        using (var signedIn = await browser.LogInAsync(first, SignUpFlow.Password))
        {
            Assert.Equal(StepNames.Redirect, SignUpFlow.Name(signedIn));
        }

        var cookie = browser.Http.Cookies[ProtocolContract.SessionCookie];

        // prompt=login: the live Session isn't fresh enough, so the request goes to Login in the same browser.
        using (var again = await browser.Http.GetAsync(
            CodeFlow.AuthorizeUrl(flow.Flow.ClientA.ClientId, CodeFlowSetup.Callback, Pkce.New(), extra: [("prompt", "login")])))
        {
            Assert.True(HostedBrowser.IsLoginRedirect(again), $"The prompt=login request answered {(int)again.StatusCode}.");
        }

        using var second = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(second, SignUpFlow.Password);

        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.False(browser.Http.Cookies[ProtocolContract.SessionCookie] == cookie, "The Session cookie wasn't replaced.");
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM user_session WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}'"));
        Assert.Equal(1L, await flow.EventsAsync("sessions.session.rotated"));
    }

    [Fact]
    public async Task Hosted_Login_hashes_sign_up_and_sign_in_through_one_gate()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        var gate = new CountingGate(AuthenticationContract.CreatePasswordHashGate(PasswordHashLimits.Default));
        await using var host = await ProtocolHost.StartAsync(
            flow.Database.Hosted,
            bao,
            configure: services => services.Replace(ServiceDescriptor.Singleton<IPasswordHashGate>(gate)));

        var (_, verify) = await flow.SignUpAsync(host, HostA, "new.user@example.com");
        verify.Dispose();
        Assert.Equal(1, gate.Entered);

        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.Equal(2, gate.Entered);
    }

    [Fact]
    public async Task A_wrong_password_an_unknown_account_and_only_a_pending_password_answer_alike_and_write_only_the_failure()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        const string pending = "pending.user@example.com";
        var pendingUser = Guid.CreateVersion7();
        var pendingHash = await AuthenticationContract.HashPasswordAsync(new Secret<string>(SignUpFlow.Password));
        await flow.Database.ExecuteAsync(
            $"INSERT INTO \"user\" (tenant_id, id, email) VALUES ('{flow.TenantA}', '{pendingUser}', '{pending}'); "
            + "INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) "
            + $"SELECT '{flow.TenantA}', gen_random_uuid(), '{pendingUser}', id, '{pendingHash}', 'pending' FROM connection WHERE tenant_id = '{flow.TenantA}'");
        await using var host = await flow.StartHostAsync();

        var answers = new List<string>();
        foreach (var (email, typed) in new[] { (Known, WrongPassword), (Unknown, SignUpFlow.Password), (pending, SignUpFlow.Password) })
        {
            var browser = await flow.BeginAsync(host, HostA);
            using var password = await browser.IdentifyAsync(email);
            var before = await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'");
            using var refused = await browser.LogInAsync(password, typed);

            Assert.Equal(StepNames.Password, SignUpFlow.Name(refused));
            Assert.Equal(PasswordErrors.Incorrect, SignUpFlow.Data(refused).GetProperty("error").GetString());
            Assert.Equal(SignUpBrowser.Version(password), SignUpBrowser.Version(refused));
            Assert.False(browser.Http.Cookies.ContainsKey(ProtocolContract.SessionCookie), "A refused password set a Session cookie.");
            // Only the failure's event was kept: the transaction and everything else are as they were.
            Assert.Equal(before + 1, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'"));
            answers.Add(Comparable(refused, email));
        }

        Assert.Single(answers.Distinct());
        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.EventsAsync(Succeeded));
        Assert.Equal(3L, await flow.CountAsync(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}' AND type_code = '{Failed}' AND actor_kind = 'anonymous'"));
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE type_code = '{Failed}' AND target_id = '{user}'"));
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE type_code = '{Failed}' AND target_id = '{pendingUser}'"));
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE type_code = '{Failed}' AND target_id IS NULL"));
        Assert.Equal(3L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND completed_steps = ARRAY['identifier']::text[] AND step_version = 2"));
    }

    [Fact]
    public async Task A_wrong_password_and_an_unknown_account_take_the_same_time_within_the_stated_tolerance()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(signInLimits: SignUpFlow.GenerousSignIn);

        // One warm-up of each, so neither path pays for the dummy hash or a cold cache, then 8 alternating of each.
        await TimedLogInAsync(flow, host, Known);
        await TimedLogInAsync(flow, host, Unknown);
        var known = new List<TimeSpan>();
        var unknown = new List<TimeSpan>();
        for (var i = 0; i < 8; i++)
        {
            known.Add(await TimedLogInAsync(flow, host, Known));
            unknown.Add(await TimedLogInAsync(flow, host, Unknown));
        }

        var difference = (Median(known) - Median(unknown)).Duration();
        Assert.True(difference <= Tolerance, $"The medians differ by {difference.TotalMilliseconds:F0} ms, over the {Tolerance.TotalMilliseconds:F0} ms tolerance.");

        // One hash is 50 to 150 ms, so the tolerance alone can't show the dummy verification ran: an unknown account must
        // take at least half a wrong password's time.
        Assert.True(
            Median(unknown) >= Median(known) / 2,
            $"An unknown account's median ({Median(unknown).TotalMilliseconds:F0} ms) is under half a wrong password's ({Median(known).TotalMilliseconds:F0} ms): no dummy verification ran.");
    }

    [Fact]
    public async Task A_hash_with_old_parameters_is_upgraded_at_the_next_sign_in_and_still_verifies()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, credential) = await flow.AddPasswordUserAsync(Known, OldHash(SignUpFlow.Password));
        var history = await flow.CountAsync($"SELECT count(*) FROM password_history WHERE tenant_id = '{flow.TenantA}'");
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);

        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        var stored = await flow.Database.ScalarAsync<string>($"SELECT password_hash FROM password_credential WHERE id = '{credential}'");
        Assert.Equal((19456, 2, 1), AuthenticationContract.PasswordHashParameters(stored));
        Assert.True(await AuthenticationContract.VerifyPasswordAsync(new Secret<string>(SignUpFlow.Password), stored), "The upgraded hash doesn't verify.");
        Assert.Equal(history, await flow.CountAsync($"SELECT count(*) FROM password_history WHERE tenant_id = '{flow.TenantA}'"));
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM password_credential WHERE user_id = '{user}'"));
    }

    [Fact]
    public async Task The_correct_password_of_an_unverified_User_asks_for_verification_with_a_new_link_and_no_Session()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, credential) = await flow.AddPasswordUserAsync(Known, verified: false);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known);
        using var verify = await browser.LogInAsync(password, SignUpFlow.Password);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        Assert.Equal(Known, SignUpFlow.Data(verify).GetProperty("email").GetString());
        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));
        Assert.False(browser.Http.Cookies.ContainsKey(ProtocolContract.SessionCookie), "An unverified User got a Session cookie.");
        var job = Assert.Single(host.Jobs.Jobs);
        Assert.Equal(user, job.UserId);
        Assert.Equal(NotificationsContract.VerificationTemplate, job.TemplateId);
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND completed_steps = ARRAY['identifier', 'registered']::text[] AND signup_user_id = '{user}' AND signup_credential_id = '{credential}'"));

        // Story 4.7's Continue: not yet; then the link, in this browser, verifies and signs in, and Continue's code follows.
        using var early = await browser.ContinueAsync(verify);
        Assert.Equal(VerifyEmailErrors.NotVerifiedYet, SignUpFlow.Data(early).GetProperty("error").GetString());
        using var resent = await browser.ResendAsync(verify);
        Assert.True(SignUpFlow.Data(resent).GetProperty("resent").GetBoolean());
        Assert.Equal(2, host.Jobs.LinksFor(user).Count);

        using var verified = await browser.OpenLinkAsync(host.Jobs.LastLink());
        Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(verified));
        Assert.Equal(EmailVerifiedContinuations.App, SignUpFlow.Data(verified).GetProperty("continueTo").GetString());
        using var resumed = await browser.FollowAsync(SignUpFlow.Data(verified).GetProperty("location").GetString()!);
        Assert.Equal(HttpStatusCode.Found, resumed.StatusCode);
        Assert.Contains("code=", resumed.Headers.Location!.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unverified_Users_sign_in_link_once_expired_sends_a_new_one()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known, verified: false);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using (var password = await browser.IdentifyAsync(Known))
        using (var verify = await browser.LogInAsync(password, SignUpFlow.Password))
        {
            Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        }

        var link = Assert.Single(host.Jobs.LinksFor(user));
        await flow.Database.BackdateAsync($"UPDATE one_time_token SET expires_at = now() - interval '1 second' WHERE tenant_id = '{flow.TenantA}'");
        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        using var expired = await other.OpenLinkAsync(link);
        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(expired));
        using (var sent = await other.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = link }, SignUpBrowser.Csrf(expired)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        }

        Assert.Equal(2, host.Jobs.LinksFor(user).Count);
        Assert.Equal(2, host.Jobs.Jobs.Count(j => j.UserId == user && j.TemplateId == NotificationsContract.VerificationTemplate));
    }

    [Fact]
    public async Task A_wrong_password_of_an_unverified_User_is_incorrect_revealing_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known, verified: false);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known);
        using var refused = await browser.LogInAsync(password, WrongPassword);

        Assert.Equal(StepNames.Password, SignUpFlow.Name(refused));
        Assert.Equal(PasswordErrors.Incorrect, SignUpFlow.Data(refused).GetProperty("error").GetString());
        Assert.Empty(host.Jobs.Jobs);
    }

    [Fact]
    public async Task Edit_goes_back_to_Login_with_the_email_kept_and_Continue_works_again()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var password = await browser.IdentifyAsync(Known);
        using var login = await browser.EditAsync(password);

        Assert.Equal(StepNames.Login, SignUpFlow.Name(login));
        Assert.Equal(Known, SignUpFlow.Data(login).GetProperty("email").GetString());
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND cardinality(completed_steps) = 0 AND identifier = '{Known}'"));

        // The page and Extend show Login now, and Continue leads to the Password step again.
        using (var page = await browser.PageAsync())
        {
            Assert.Equal(StepNames.Login, SignUpFlow.Name(page));
        }

        using var again = await browser.IdentifyAsync(Known);
        Assert.Equal(StepNames.Password, SignUpFlow.Name(again));
        using var redirect = await browser.LogInAsync(again, SignUpFlow.Password);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
    }

    [Fact]
    public async Task Extend_and_the_page_answer_the_Password_step_and_a_stale_version_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);

        using var extended = await browser.PostAsync(ProtocolContract.LoginExtendPath, new { }, SignUpBrowser.Csrf(password));
        Assert.Equal(StepNames.Password, SignUpFlow.Name(extended));
        using (var page = await browser.PageAsync())
        {
            Assert.Equal(StepNames.Password, SignUpFlow.Name(page));
        }

        using var stale = await browser.PostAsync(
            ProtocolContract.PasswordPath, new { stepVersion = SignUpBrowser.Version(password) + 5, password = SignUpFlow.Password }, SignUpBrowser.Csrf(password));
        Assert.Equal(StepNames.Password, SignUpFlow.Name(stale));
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(stale).GetProperty("error").ValueKind);
        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.EventsAsync(Failed));
    }

    [Fact]
    public async Task Past_the_per_source_limit_a_password_submit_is_429_and_looks_nothing_up()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        var limits = new SignInLimits(SignInLimits.TenantPolicy, new("signin.attempt.source", 3, TimeSpan.FromMinutes(15)));
        await using var host = await flow.StartHostAsync(signInLimits: limits);
        var browser = await flow.BeginAsync(host, HostA, source: "198.51.100.7");
        using var password = await browser.IdentifyAsync(Known);

        for (var i = 0; i < 3; i++)
        {
            using var refused = await browser.LogInAsync(password, WrongPassword);
            Assert.Equal(PasswordErrors.Incorrect, SignUpFlow.Data(refused).GetProperty("error").GetString());
        }

        // The correct password, past the limit: refused before any lookup or hash, so no event at all.
        using var limited = await browser.Http.PostAsync(
            ProtocolContract.PasswordPath, new { stepVersion = SignUpBrowser.Version(password), password = SignUpFlow.Password }, SignUpBrowser.Csrf(password));
        await AssertLimitedAsync(limited);
        Assert.Equal(3L, await flow.EventsAsync(Failed));
        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));

        // Another source still signs in, and the default is the story's 30.
        var other = await flow.BeginAsync(host, HostA, source: "198.51.100.8");
        using var otherPassword = await other.IdentifyAsync(Known);
        using var redirect = await other.LogInAsync(otherPassword, SignUpFlow.Password);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.Equal(30, SignInLimits.Default.Source.Limit);
        Assert.Equal(1200, SignInLimits.Default.Tenant.Limit);
        Assert.Equal(TimeSpan.FromMinutes(15), SignInLimits.Default.Source.Window);
    }

    [Fact]
    public async Task Past_the_Tenants_limit_a_new_sources_password_submit_is_429()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        var limits = new SignInLimits(new("signin.attempt.tenant", 2, TimeSpan.FromMinutes(15)), SignInLimits.SourcePolicy);
        await using var host = await flow.StartHostAsync(signInLimits: limits);

        for (var i = 0; i < 2; i++)
        {
            var browser = await flow.BeginAsync(host, HostA, source: $"203.0.113.{i + 1}");
            using var password = await browser.IdentifyAsync(Known);
            using var refused = await browser.LogInAsync(password, WrongPassword);
            Assert.Equal(StepNames.Password, SignUpFlow.Name(refused));
        }

        var fresh = await flow.BeginAsync(host, HostA, source: "203.0.113.9");
        using var freshPassword = await fresh.IdentifyAsync(Known);
        using var limited = await fresh.Http.PostAsync(
            ProtocolContract.PasswordPath, new { stepVersion = SignUpBrowser.Version(freshPassword), password = SignUpFlow.Password }, SignUpBrowser.Csrf(freshPassword));
        await AssertLimitedAsync(limited);
    }

    [Fact]
    public async Task With_the_hashing_budget_full_a_password_submit_is_temporarily_unavailable_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(hashLimits: new PasswordHashLimits(concurrency: 0, tenantShare: 0, wait: TimeSpan.Zero));

        foreach (var (email, typed) in new[] { (Known, SignUpFlow.Password), (Unknown, SignUpFlow.Password) })
        {
            var browser = await flow.BeginAsync(host, HostA);
            using var password = await browser.IdentifyAsync(email);
            using var refused = await browser.LogInAsync(password, typed);
            Assert.Equal(StepNames.GenericError, SignUpFlow.Name(refused));
            Assert.Equal("temporarily_unavailable", SignUpFlow.Data(refused).GetProperty("code").GetString());
        }

        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.EventsAsync(Failed));
        Assert.Equal(0L, await flow.EventsAsync(Succeeded));
        Assert.Equal(2L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND completed_steps = ARRAY['identifier']::text[] AND step_version = 2"));
    }

    [Theory]
    [InlineData("no-csrf", null, "csrf_mismatch")]
    [InlineData("right", "https://evil.signin-password.test", "origin_mismatch")]
    public async Task A_password_submit_or_Edit_without_its_CSRF_token_or_with_a_wrong_Origin_is_refused_with_403(string csrf, string? origin, string code)
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);

        foreach (var path in new[] { ProtocolContract.PasswordPath, ProtocolContract.PasswordBackPath })
        {
            using var refused = await browser.Http.PostAsync(
                path,
                new { stepVersion = SignUpBrowser.Version(password), password = SignUpFlow.Password },
                csrf == "right" ? SignUpBrowser.Csrf(password) : null,
                origin);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            using var step = await HostedBrowser.StepAsync(refused);
            Assert.Equal(code, SignUpFlow.Data(step).GetProperty("code").GetString());
        }

        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.EventsAsync(Failed));
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND completed_steps = ARRAY['identifier']::text[]"));
    }

    [Fact]
    public async Task A_code_flow_naming_an_API_gets_it_as_aud()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var tokens = await TokensAsync(host, flow.Flow, "openid", [("resource", ProtocolDatabase.TestApi)]);

        Assert.Equal([ProtocolDatabase.TestApi], new JsonWebToken(tokens.Access).Audiences);
    }

    [Fact]
    public async Task With_none_named_the_Tenants_default_audience_is_the_aud_and_a_refresh_keeps_it()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.Database.ExecuteAsync(
            $"INSERT INTO tenant_settings (tenant_id, default_audience) VALUES ('{flow.TenantA}', '{ProtocolDatabase.TestApi}') "
            + $"ON CONFLICT (tenant_id) DO UPDATE SET default_audience = '{ProtocolDatabase.TestApi}'; "
            + $"UPDATE api SET offline_access = true WHERE tenant_id = '{flow.TenantA}' AND identifier = '{ProtocolDatabase.TestApi}'");
        await using var host = await flow.StartHostAsync();

        var tokens = await TokensAsync(host, flow.Flow, "openid offline_access", []);
        Assert.Equal([ProtocolDatabase.TestApi], new JsonWebToken(tokens.Access).Audiences);
        Assert.NotEmpty(tokens.Refresh);

        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.Flow.ClientA.ClientId, flow.Flow.ClientA.Secret, tokens.Refresh);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal([ProtocolDatabase.TestApi], new JsonWebToken(refreshed.AccessToken).Audiences);
    }

    [Fact]
    public async Task With_no_API_and_no_default_audience_the_aud_is_only_the_userinfo_endpoint_which_accepts_it_and_a_refresh_keeps_it()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        // A default audience naming an API since removed counts as none.
        await flow.Database.ExecuteAsync(
            $"INSERT INTO tenant_settings (tenant_id, default_audience) VALUES ('{flow.TenantA}', 'https://gone.example') "
            + "ON CONFLICT (tenant_id) DO UPDATE SET default_audience = 'https://gone.example'");
        await using var host = await flow.StartHostAsync();
        var userinfo = $"{flow.Flow.A.Issuer}connect/userinfo";

        var tokens = await TokensAsync(host, flow.Flow, "openid offline_access", []);
        var access = new JsonWebToken(tokens.Access);
        Assert.Equal([userinfo], access.Audiences);
        Assert.False(access.TryGetPayloadValue<string>("gk_api", out _), "The access token holds gk_api.");
        Assert.DoesNotContain("urn:gatekeep:placeholder", Encoding.UTF8.GetString(Base64UrlDecode(tokens.Access.Split('.')[1])), StringComparison.Ordinal);

        var answered = await UserinfoAndRevocationTests.UserinfoAsync(host, HostA, tokens.Access);
        Assert.Equal(HttpStatusCode.OK, answered.Status);

        using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.Flow.ClientA.ClientId, flow.Flow.ClientA.Secret, tokens.Refresh);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal([userinfo], new JsonWebToken(refreshed.AccessToken).Audiences);
    }

    /// <summary>The setup User's code flow with <paramref name="scope"/> and <paramref name="extra"/> parameters, exchanged.</summary>
    private static async Task<(string Access, string Refresh)> TokensAsync(
        ProtocolHost host, CodeFlowSetup flow, string scope, (string Name, string Value)[] extra)
    {
        var pkce = Pkce.New();
        using var response = await CodeFlow.AuthorizeAsync(host, HostA, flow.ClientA.ClientId, CodeFlowSetup.Callback, pkce, flow.UserA, scope: scope, extra: extra);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var code = QueryHelpers.ParseQuery(response.Headers.Location!.Query)["code"].ToString();
        using var issued = await CodeFlow.ExchangeAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, code, CodeFlowSetup.Callback, pkce.Verifier);
        Assert.True(issued.Status == HttpStatusCode.OK, issued.Body.RootElement.GetRawText());
        var refresh = issued.Body.RootElement.TryGetProperty("refresh_token", out var value) ? value.GetString() ?? string.Empty : string.Empty;
        return (issued.AccessToken, refresh);
    }

    private static byte[] Base64UrlDecode(string value) => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(value);

    /// <summary>
    /// A PHC string for <paramref name="password"/> under old parameters, m=8192 KiB and t=1, as an earlier release could
    /// have stored it.
    /// </summary>
    private static string OldHash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        using var argon = new Konscious.Security.Cryptography.Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        };
        var hash = argon.GetBytes(32);
        return $"$argon2id$v=19$m=8192,t=1,p=1${Convert.ToBase64String(salt).TrimEnd('=')}${Convert.ToBase64String(hash).TrimEnd('=')}";
    }

    /// <summary>A fresh browser's password submit for <paramref name="email"/>, with a wrong password, only the POST timed.</summary>
    private static async Task<TimeSpan> TimedLogInAsync(SignUpFlow flow, ProtocolHost host, string email)
    {
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(email);
        var watch = Stopwatch.StartNew();
        using var refused = await browser.LogInAsync(password, WrongPassword);
        watch.Stop();
        Assert.Equal(PasswordErrors.Incorrect, SignUpFlow.Data(refused).GetProperty("error").GetString());
        return watch.Elapsed;
    }

    private static TimeSpan Median(List<TimeSpan> times)
    {
        var sorted = times.Order().ToList();
        return sorted.Count % 2 == 1 ? sorted[sorted.Count / 2] : (sorted[(sorted.Count / 2) - 1] + sorted[sorted.Count / 2]) / 2;
    }

    /// <summary>
    /// The step as JSON with what differs by transaction by design set aside: its version, life and CSRF token, and
    /// <paramref name="email"/>, the address the browser typed, wherever the data holds it.
    /// </summary>
    private static string Comparable(JsonDocument step, string email)
    {
        var node = JsonNode.Parse(step.RootElement.GetRawText())!.AsObject();
        node["stepVersion"] = 0;
        node["expiresInSeconds"] = 0;
        node["csrfToken"] = "csrf";
        if (node["data"]?["email"]?.GetValue<string>() == email)
        {
            node["data"]!["email"] = "email";
        }

        return node.ToJsonString();
    }

    /// <summary>The host's hashing gate, counting every slot asked of it.</summary>
    private sealed class CountingGate(IPasswordHashGate inner) : IPasswordHashGate
    {
        private int _entered;

        public int Entered => Volatile.Read(ref _entered);

        public Task<IDisposable?> EnterAsync(Guid tenantId, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _entered);
            return inner.EnterAsync(tenantId, cancellationToken);
        }
    }

    /// <summary>A rate-limited answer: 429, a positive <c>Retry-After</c> in seconds, and Generic error <c>temporarily_unavailable</c>.</summary>
    private static async Task AssertLimitedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        var retryAfter = Assert.Single(response.Headers.GetValues("Retry-After"));
        Assert.True(int.TryParse(retryAfter, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var seconds) && seconds is >= 1 and <= 900, $"Retry-After is {retryAfter}.");
        using var step = await HostedBrowser.StepAsync(response);
        Assert.Equal(StepNames.GenericError, SignUpFlow.Name(step));
        Assert.Equal("temporarily_unavailable", SignUpFlow.Data(step).GetProperty("code").GetString());
    }
}
