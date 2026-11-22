using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.12 (FR-14, UX-DR32): Hosted Login offers, and the server accepts, only the Connections enabled for the
/// transaction's Application. With none, Login, Continue, a restart and Keep going are Generic error
/// <c>temporarily_unavailable</c>; every password, sign-up, reset and verification request on its behalf answers as for a
/// disabled Connection, writing and sending nothing. A Session started through a Connection the Application doesn't allow
/// is not reused: Login is shown, nothing is revoked, and signing in again rotates it. The system Application follows every
/// Connection its Tenant enables. The release build's credential step throughout, as on Host.Hosted.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class ApplicationConnectionSignInTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.app-connections.test";
    private const string HostB = "beta.app-connections.test";
    private const string Known = "known.user@example.com";
    private const string Unknown = "nobody@example.com";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_Application_with_its_Connection_off_gets_Generic_error_at_Login_and_one_with_it_on_gets_Login()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var other = await flow.Database.CreateWebClientAsync(flow.TenantA, [CodeFlowSetup.Callback], "Web B");
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        await using var host = await flow.StartHostAsync(releaseSignIn: true);

        // A, with it off: the page, and Keep going, are Generic error, the same for every browser.
        var off = await flow.BeginAsync(host, HostA);
        using (var page = await off.PageAsync())
        {
            AssertUnavailable(page);
        }

        // B, with it on: Login, and its "Sign up" link.
        var on = await flow.BeginAsync(host, HostA, clientId: other.ClientId);
        var login = await on.Http.LoginStepAsync();
        Assert.True(login.Step.GetProperty("data").GetProperty("signupEnabled").GetBoolean());
    }

    [Fact]
    public async Task Continue_Extend_and_a_restart_are_Generic_error_for_every_identifier_once_the_Connection_is_off()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(releaseSignIn: true);

        var answers = new List<string>();
        foreach (var email in new[] { Known, Unknown })
        {
            var browser = await flow.BeginAsync(host, HostA);
            var login = await browser.Http.LoginStepAsync();
            await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);

            using var continued = await browser.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email }, login.Csrf);
            AssertUnavailable(continued);
            answers.Add(Comparable(continued));

            using var extended = await browser.PostAsync(ProtocolContract.LoginExtendPath, new { }, login.Csrf);
            AssertUnavailable(extended);

            await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: true);
        }

        Assert.Equal(answers[0], answers[1]);

        // A restart of an expired transaction keeps its cookie's promise, but with nothing to sign in through it is Generic error.
        var expired = await flow.BeginAsync(host, HostA);
        await flow.Database.BackdateAsync(
            "UPDATE signin_transaction SET created_at = now() - interval '40 minutes', expires_at = now() - interval '10 minutes'");
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        using var restarted = await expired.PageAsync();
        AssertUnavailable(restarted);
    }

    [Fact]
    public async Task Every_direct_request_for_an_Application_with_its_Connection_off_is_refused_writing_and_sending_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB, verificationOff: false);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(releaseSignIn: true, resetLimits: SignUpFlow.GenerousReset);

        // Each browser reaches its step while the Connection is on: Password, Login, Forgot password, and a reset link.
        var password = await flow.BeginAsync(host, HostA);
        using var passwordStep = await password.IdentifyAsync(Known);
        Assert.Equal(StepNames.Password, SignUpFlow.Name(passwordStep));

        var signup = await flow.BeginAsync(host, HostA);
        var login = await signup.Http.LoginStepAsync();

        var forgot = await flow.BeginAsync(host, HostA);
        using var forgotPassword = await forgot.IdentifyAsync(Known);
        using var forgotStep = await forgot.ForgotAsync(forgotPassword);
        Assert.Equal(StepNames.ForgotPassword, SignUpFlow.Name(forgotStep));

        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));

        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        var transactions = await flow.Database.ScalarAsync<string>("SELECT string_agg(id || ':' || step_version, ',' ORDER BY id) FROM signin_transaction");
        var jobs = host.Jobs.Jobs.Count;
        var hash = await flow.Database.ScalarAsync<string>($"SELECT password_hash FROM password_credential WHERE user_id = '{user}'");

        // The correct password: Generic error, no Session.
        using (var signedIn = await password.LogInAsync(passwordStep, SignUpFlow.Password))
        {
            AssertUnavailable(signedIn);
        }

        // Sign up and Forgot password: the current step, which is Generic error.
        using (var opened = await signup.PostAsync(ProtocolContract.SignupOpenPath, new { stepVersion = login.StepVersion, email = "new@example.com" }, login.Csrf))
        {
            AssertUnavailable(opened);
        }

        using (var reopened = await password.ForgotAsync(passwordStep))
        {
            AssertUnavailable(reopened);
        }

        // Forgot password stays as it was, as with the Connection disabled: no link, no email.
        using (var requested = await forgot.RequestResetAsync(forgotStep, Known))
        {
            Assert.Equal(StepNames.ForgotPassword, SignUpFlow.Name(requested));
        }

        // The reset link: Link expired, its completion too, and its new link the neutral answer with nothing sent.
        var linkBrowser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using (var page = await linkBrowser.OpenResetLinkAsync(link))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(page));
        }

        using (var completed = await linkBrowser.CompleteResetAsync(link, "Fresh-Lantern-4orbit"))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(completed));
        }

        using (var fresh = await linkBrowser.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(fresh));
        }

        Assert.Equal(0L, await flow.RowsAsync("user_session"));
        Assert.Equal(1L, await flow.RowsAsync("user"));
        Assert.Equal(transactions, await flow.Database.ScalarAsync<string>("SELECT string_agg(id || ':' || step_version, ',' ORDER BY id) FROM signin_transaction"));
        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(hash, await flow.Database.ScalarAsync<string>($"SELECT password_hash FROM password_credential WHERE user_id = '{user}'"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset' AND used_at IS NULL"));
        Assert.Equal(0L, await flow.EventsAsync("authentication.signin.succeeded"));
    }

    [Fact]
    public async Task A_sign_ups_Resend_and_Continue_send_and_start_nothing_once_the_Connection_is_off()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync(releaseSignIn: true, signUpLimits: SignUpFlow.Generous);
        var (browser, verify) = await flow.SignUpAsync(host, HostA, "new.user@example.com");
        using (verify)
        {
            Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
            var link = host.Jobs.LastLink();
            await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
            var jobs = host.Jobs.Jobs.Count;
            var expires = await flow.Database.ScalarAsync<string>("SELECT expires_at::text FROM signin_transaction");

            using (var resent = await browser.ResendAsync(verify))
            {
                Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(resent));
            }

            Assert.Equal(jobs, host.Jobs.Jobs.Count);
            Assert.Equal(expires, await flow.Database.ScalarAsync<string>("SELECT expires_at::text FROM signin_transaction"));

            // The link verifies the email, as with the Connection disabled, but starts no Session; Continue none either.
            using (var opened = await browser.OpenLinkAsync(link))
            {
                Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(opened));
            }

            using (var continued = await browser.ContinueAsync(verify))
            {
                Assert.NotEqual(StepNames.Redirect, SignUpFlow.Name(continued));
            }

            Assert.Equal(0L, await flow.RowsAsync("user_session"));
            Assert.Equal(jobs, host.Jobs.Jobs.Count);
        }
    }

    [Fact]
    public async Task A_Session_from_a_Connection_the_Application_turned_off_isnt_reused_and_signing_in_again_rotates_it()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        var other = await flow.Database.CreateWebClientAsync(flow.TenantA, [CodeFlowSetup.Callback], "Web B");
        await using var host = await flow.StartHostAsync(releaseSignIn: true);
        var browser = await flow.BeginAsync(host, HostA);
        using (var first = await browser.IdentifyAsync(Known))
        using (var signedIn = await browser.LogInAsync(first, SignUpFlow.Password))
        {
            Assert.Equal(StepNames.Redirect, SignUpFlow.Name(signedIn));
        }

        var cookie = browser.Http.Cookies[ProtocolContract.SessionCookie];

        // B still allows the database Connection: the Session is reused, and the code issued with no Login.
        using (var reused = await browser.Http.GetAsync(CodeFlow.AuthorizeUrl(other.ClientId, CodeFlowSetup.Callback, Pkce.New())))
        {
            Assert.Equal(HttpStatusCode.Found, reused.StatusCode);
            Assert.Contains("code=", reused.Headers.Location!.Query, StringComparison.Ordinal);
        }

        // A turns it off: Login, not the code, and the Session isn't revoked.
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        using (var refused = await browser.Http.GetAsync(CodeFlow.AuthorizeUrl(flow.Flow.ClientA.ClientId, CodeFlowSetup.Callback, Pkce.New())))
        {
            Assert.True(HostedBrowser.IsLoginRedirect(refused), $"The authorization request answered {(int)refused.StatusCode}.");
        }

        Assert.Equal(1L, await flow.RowsAsync("user_session", $"user_id = '{user}' AND ended_at IS NULL"));
        Assert.Equal(cookie, browser.Http.Cookies[ProtocolContract.SessionCookie]);

        // A turns it on again: signing in once more rotates the one Session.
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: true);
        using (var again = await browser.Http.GetAsync(
            CodeFlow.AuthorizeUrl(flow.Flow.ClientA.ClientId, CodeFlowSetup.Callback, Pkce.New(), extra: [("prompt", "login")])))
        {
            Assert.True(HostedBrowser.IsLoginRedirect(again), $"The prompt=login request answered {(int)again.StatusCode}.");
        }

        using var second = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(second, SignUpFlow.Password);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.False(browser.Http.Cookies[ProtocolContract.SessionCookie] == cookie, "The Session cookie wasn't replaced.");
        Assert.Equal(1L, await flow.RowsAsync("user_session", $"user_id = '{user}'"));
        Assert.Equal(1L, await flow.EventsAsync("sessions.session.rotated"));
    }

    [Fact]
    public async Task Create_account_on_a_Signup_already_open_writes_no_account_or_email_once_the_Connection_is_off()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync(releaseSignIn: true, signUpLimits: SignUpFlow.Generous);
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync("new.user@example.com");
        Assert.Equal(StepNames.Signup, SignUpFlow.Name(signup));
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        var jobs = host.Jobs.Jobs.Count;

        using var created = await browser.CreateAsync(signup, "new.user@example.com", SignUpFlow.Password);

        AssertUnavailable(created);
        Assert.Equal(0L, await flow.RowsAsync("user"));
        Assert.Equal(0L, await flow.RowsAsync("password_credential"));
        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(0L, await flow.EmailJobsAsync());
    }

    [Fact]
    public async Task A_verification_links_Send_a_new_link_sends_nothing_once_the_Connection_is_off()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync(releaseSignIn: true, signUpLimits: SignUpFlow.Generous);
        var (_, verify) = await flow.SignUpAsync(host, HostA, "new.user@example.com");
        verify.Dispose();
        var link = host.Jobs.LastLink();
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        var jobs = host.Jobs.Jobs.Count;
        var tokens = await flow.RowsAsync("one_time_token");

        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using var sent = await other.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = link }, SignUpFlow.LinkCsrf(link));

        Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(tokens, await flow.RowsAsync("one_time_token"));
    }

    [Fact]
    public async Task A_resume_after_the_Connection_is_turned_off_issues_no_code()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(releaseSignIn: true);
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));

        // Authenticated, then the Application turns its Connection off before the resume.
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        using var resumed = await browser.FollowAsync(SignUpFlow.Data(redirect).GetProperty("location").GetString()!);

        var location = resumed.Headers.Location?.OriginalString ?? string.Empty;
        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
        Assert.Equal(0L, await flow.RowsAsync("authorization"));
        Assert.Equal(0L, await flow.RowsAsync("signin_transaction", "completed_at IS NOT NULL"));
    }

    /// <summary>
    /// The system Application has no row, and follows the Tenant: its sign-in is accepted (a wrong password is
    /// <c>incorrect</c>, not unavailable), while an Application with its row off is refused.
    /// </summary>
    [Fact]
    public async Task The_system_Application_follows_the_Tenants_Connection_and_signs_in()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        var system = Guid.CreateVersion7();
        await flow.Database.ExecuteAsync(
            $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{flow.TenantA}', '{system}', 'Account Portal', 'system', now())");
        await SetAsync(flow, flow.Flow.ClientA.ApplicationId, enabled: false);
        Assert.Equal(0L, await flow.RowsAsync("application_connection", $"application_id = '{system}'"));

        var audit = AuditContract.CreateAppender();
        var signIn = AuthenticationContract.CreateSignIn(
            audit,
            TimeProvider.System,
            Gatekeep.Modules.Operations.Contracts.OperationsContract.CreateEnqueuer(Gatekeep.Modules.Operations.Contracts.OperationsContract.ProductionRegistry, custody: null),
            AuthenticationContract.CreatePasswordHashGate(PasswordHashLimits.Default));
        var signUp = AuthenticationContract.CreateSignUp(
            audit,
            TimeProvider.System,
            Gatekeep.Modules.Operations.Contracts.OperationsContract.CreateEnqueuer(Gatekeep.Modules.Operations.Contracts.OperationsContract.ProductionRegistry, custody: null),
            AuthenticationContract.CreatePasswordHashGate(PasswordHashLimits.Default));

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, flow.Database.Name));
        foreach (var (application, expected) in new[] { (system, SignInStatus.Incorrect), (flow.Flow.ClientA.ApplicationId, SignInStatus.Unavailable) })
        {
            await using var scope = await TenantScope.BeginAsync(source, flow.TenantA, Cancellation);
            var context = scope.CreateCommandContext();
            Assert.Equal(application == system, (await signUp.ReadPolicyAsync(context, application, Cancellation)).PasswordEnabled);

            var transaction = new SignInTransaction(
                Guid.CreateVersion7(), application, new Dictionary<string, string>(), [SignInSteps.Identifier], 2, Known, null, DateTimeOffset.UtcNow.AddMinutes(30), null);
            var result = await signIn.SignInAsync(context, transaction, new Secret<string>("Wrong-Horse-9battery"), null, Cancellation);
            Assert.Equal(expected, result.Status);
        }
    }

    /// <summary>Turns the database Connection on or off for <paramref name="application"/>, as the Application · Connections toggle stores it.</summary>
    private static Task SetAsync(SignUpFlow flow, Guid application, bool enabled) =>
        flow.Database.ExecuteAsync(
            $"UPDATE application_connection SET enabled = {(enabled ? "true" : "false")} WHERE tenant_id = '{flow.TenantA}' AND application_id = '{application}'");

    private static void AssertUnavailable(JsonDocument step)
    {
        Assert.Equal(StepNames.GenericError, SignUpFlow.Name(step));
        Assert.Equal("temporarily_unavailable", SignUpFlow.Data(step).GetProperty("code").GetString());
    }

    /// <summary>A Generic error's body without its trace ID, which differs per request.</summary>
    private static string Comparable(JsonDocument step)
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse(step.RootElement.GetRawText())!;
        node["data"]!.AsObject().Remove("traceId");
        return node.ToJsonString();
    }
}
