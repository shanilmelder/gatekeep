using System.Net;
using System.Text.Json;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.7 (FR-17, FR-18, NFR-2): signing up through Hosted Login, at the HTTP level, through the real Tenant
/// resolution, Protocol registration and Hosted Login surface, against the real PostgreSQL as <c>gk_hosted</c> and the
/// real OpenBao. One test or more per sign-up row of the story's I/O matrix, with the rows it leaves behind. No assertion
/// prints a password, link or cookie.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SignUpTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.signup.test";
    private const string HostB = "beta.signup.test";
    private const string Email = "new.user@example.com";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Login_shows_Sign_up_only_while_the_database_Connection_lets_users_sign_up()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();

        var browser = await flow.BeginAsync(host, HostA);
        using (var open = await browser.PageAsync())
        {
            Assert.True(SignUpFlow.Data(open).GetProperty("signupEnabled").GetBoolean());
        }

        await flow.Database.ExecuteAsync($"UPDATE connection SET signup_enabled = false WHERE tenant_id = '{flow.TenantA}'");
        using var closed = await browser.PageAsync();
        Assert.False(SignUpFlow.Data(closed).GetProperty("signupEnabled").GetBoolean());
    }

    [Fact]
    public async Task A_new_sign_up_leaves_an_unverified_User_a_pending_credential_one_link_and_one_email_and_no_Session()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);

        using var signup = await browser.OpenAsync(Email);
        Assert.Equal(StepNames.Signup, SignUpFlow.Name(signup));
        var data = SignUpFlow.Data(signup);
        Assert.Equal(Email, data.GetProperty("email").GetString());
        Assert.Equal(12, data.GetProperty("policy").GetProperty("minLength").GetInt32());
        Assert.Equal("good", data.GetProperty("policy").GetProperty("strength").GetString());

        using var verify = await browser.CreateAsync(signup, Email, SignUpFlow.Password);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        Assert.Equal(Email, SignUpFlow.Data(verify).GetProperty("email").GetString());
        Assert.False(SignUpFlow.Data(verify).GetProperty("resent").GetBoolean());
        Assert.DoesNotContain(browser.Http.SetCookies, c => c.StartsWith(ProtocolContract.SessionCookie, StringComparison.Ordinal));

        var user = await flow.UserAsync(Email);
        Assert.Equal(1L, await flow.RowsAsync("user", $"id = '{user}' AND email_verified_at IS NULL"));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND status = 'pending' AND password_hash LIKE '$argon2id$v=19$m=19456,t=2,p=1$%'"));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND connection_id = (SELECT id FROM connection WHERE tenant_id = '{flow.TenantA}')"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"user_id = '{user}' AND used_at IS NULL AND application_id = '{flow.Flow.ClientA.ApplicationId}'"));
        Assert.Equal(1L, await flow.EmailJobsAsync());
        Assert.Equal(0L, await flow.RowsAsync("user_session"));
        Assert.Equal(0L, await flow.RowsAsync("token"));
        Assert.Equal(0L, await flow.RowsAsync("password_history"));
        Assert.Equal(1L, await flow.EventsAsync("identity.user.signed_up"));
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}' AND type_code = 'identity.user.signed_up' AND target_kind = 'user' AND target_id = '{user}' AND actor_kind = 'anonymous'"));

        // The link went to the User's email job, held only as its hash; the password nowhere.
        var link = Assert.Single(host.Jobs.LinksFor(user));
        Assert.True(link.StartsWith(Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.Tenant, flow.TenantA) + ".", StringComparison.Ordinal), "The link isn't Tenant A's.");
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"token_hash = '\\x{SignUpFlow.HashHex(link)}'"));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "job_payload", link));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "password_credential", SignUpFlow.Password));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "signin_transaction", SignUpFlow.Password));
        Assert.Equal(
            $"signup,registered|{user}",
            await flow.Database.ScalarAsync<string>($"SELECT array_to_string(completed_steps, ',') || '|' || signup_user_id FROM signin_transaction WHERE tenant_id = '{flow.TenantA}'"));
    }

    [Fact]
    public async Task With_verification_off_on_a_Dev_Tenant_the_User_gets_an_active_credential_and_a_Session_and_no_link()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB, verificationOff: true);
        await using var host = await flow.StartHostAsync();

        var (browser, step) = await flow.SignUpAsync(host, HostA, Email);
        using var redirect = step;

        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        Assert.Contains(browser.Http.SetCookies, c => c.StartsWith(ProtocolContract.SessionCookie + "=", StringComparison.Ordinal));
        var user = await flow.UserAsync(Email);
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND status = 'active'"));
        Assert.Equal(1L, await flow.RowsAsync("password_history", $"user_id = '{user}'"));
        Assert.Equal(0L, await flow.RowsAsync("one_time_token"));
        Assert.Equal(0L, await flow.EmailJobsAsync());
        Assert.Equal(1L, await flow.RowsAsync(
            "user_session", $"user_id = '{user}' AND amr = ARRAY['pwd'] AND connection_id = (SELECT id FROM connection WHERE tenant_id = '{flow.TenantA}')"));

        // The redirect resumes the authorization request, and a code is issued.
        using var resumed = await browser.FollowAsync(SignUpFlow.Data(redirect).GetProperty("location").GetString()!);
        Assert.Equal(HttpStatusCode.Found, resumed.StatusCode);
        Assert.StartsWith(CodeFlowSetup.Callback, resumed.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.Contains("code=", resumed.Headers.Location!.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verification_off_stored_on_a_Tenant_that_isnt_Dev_behaves_as_a_new_sign_up()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB, verificationOff: true);
        await flow.Database.BackdateAsync($"UPDATE tenant SET label = 'prod' WHERE id = '{flow.TenantA}'");
        await using var host = await flow.StartHostAsync();

        var (_, step) = await flow.SignUpAsync(host, HostA, Email);
        using var verify = step;

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", "status = 'pending'"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token"));
        Assert.Equal(0L, await flow.RowsAsync("user_session"));
    }

    [Fact]
    public async Task A_failing_password_names_each_rule_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        var events = await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'");

        using var refused = await browser.CreateAsync(signup, Email, "aaaaaaaaaaaa");

        Assert.Equal(StepNames.Signup, SignUpFlow.Name(refused));
        Assert.Equal(SignupErrors.PasswordRule, SignUpFlow.Data(refused).GetProperty("error").GetString());
        Assert.Equal([PasswordRuleCodes.Classes], SignUpFlow.Data(refused).GetProperty("rules").EnumerateArray().Select(r => r.GetString()));
        Assert.Equal(SignUpBrowser.Version(signup), SignUpBrowser.Version(refused));
        await AssertNothingWrittenAsync(flow, events);
        Assert.Empty(host.Jobs.Jobs);
    }

    [Fact]
    public async Task A_password_holding_the_emails_local_part_is_refused_as_personal_data()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync("felix@brandt.dev");

        using var refused = await browser.CreateAsync(signup, "felix@brandt.dev", "Correct-felix-7battery");

        Assert.Equal([PasswordRuleCodes.PersonalData], SignUpFlow.Data(refused).GetProperty("rules").EnumerateArray().Select(r => r.GetString()));
        Assert.Equal(0L, await flow.RowsAsync("user"));
    }

    [Fact]
    public async Task An_invalid_email_is_the_email_field_error_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(string.Empty);

        using var refused = await browser.CreateAsync(signup, "nope", SignUpFlow.Password);

        Assert.Equal(StepNames.Signup, SignUpFlow.Name(refused));
        Assert.Equal(SignupErrors.EmailInvalid, SignUpFlow.Data(refused).GetProperty("error").GetString());
        Assert.Equal(0L, await flow.RowsAsync("user"));
    }

    [Fact]
    public async Task With_sign_up_closed_Sign_up_leaves_Login_as_it_is_and_Create_account_goes_back_to_Login_creating_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        await flow.Database.ExecuteAsync($"UPDATE connection SET signup_enabled = false WHERE tenant_id = '{flow.TenantA}'");

        using var back = await browser.CreateAsync(signup, Email, SignUpFlow.Password);

        Assert.Equal(StepNames.Login, SignUpFlow.Name(back));
        Assert.False(SignUpFlow.Data(back).GetProperty("signupEnabled").GetBoolean());
        Assert.Equal(0L, await flow.RowsAsync("user"));
        Assert.Equal(0L, await flow.EmailJobsAsync());

        // At Login, Sign up with sign-up closed answers the same Login step, writing nothing.
        var version = SignUpBrowser.Version(back);
        using var again = await browser.PostAsync(ProtocolContract.SignupOpenPath, new { stepVersion = version, email = Email }, SignUpBrowser.Csrf(back));
        Assert.Equal(StepNames.Login, SignUpFlow.Name(again));
        Assert.Equal(version, SignUpBrowser.Version(again));
        Assert.Equal(string.Empty, await flow.Database.ScalarAsync<string>($"SELECT array_to_string(completed_steps, ',') FROM signin_transaction WHERE tenant_id = '{flow.TenantA}'"));
    }

    [Fact]
    public async Task Log_in_from_Signup_goes_back_to_Login_with_the_email_kept()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);

        using var login = await browser.PostAsync(ProtocolContract.SignupBackPath, new { stepVersion = SignUpBrowser.Version(signup) }, SignUpBrowser.Csrf(signup));

        Assert.Equal(StepNames.Login, SignUpFlow.Name(login));
        Assert.Equal(Email, SignUpFlow.Data(login).GetProperty("email").GetString());
        Assert.True(SignUpFlow.Data(login).GetProperty("signupEnabled").GetBoolean());
        Assert.Equal(SignUpBrowser.Version(signup) + 1, SignUpBrowser.Version(login));
    }

    [Fact]
    public async Task A_sign_up_with_an_address_already_verified_looks_the_same_and_changes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var existing = Guid.CreateVersion7();
        await flow.Database.ExecuteAsync(
            $"INSERT INTO \"user\" (tenant_id, id, email, email_verified_at) VALUES ('{flow.TenantA}', '{existing}', 'Known@Example.com', now()); "
            + $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{flow.TenantA}', gen_random_uuid(), '{existing}', gen_random_uuid(), '$argon2id$known', 'active')");
        var userRow = $"SELECT to_jsonb(u)::text FROM \"user\" u WHERE tenant_id = '{flow.TenantA}' AND id = '{existing}'";
        var credentialRow = $"SELECT to_jsonb(c)::text FROM password_credential c WHERE tenant_id = '{flow.TenantA}' AND user_id = '{existing}'";
        var before = (await flow.Database.ScalarAsync<string>(userRow), await flow.Database.ScalarAsync<string>(credentialRow));

        var (_, knownStep) = await flow.SignUpAsync(host, HostA, "known@example.com");
        var (_, newStep) = await flow.SignUpAsync(host, HostA, Email);
        using var known = knownStep;
        using var fresh = newStep;

        // The same step, version and shape for both; only the address each typed differs.
        Assert.Equal(SignUpFlow.Name(fresh), SignUpFlow.Name(known));
        Assert.Equal(SignUpBrowser.Version(fresh), SignUpBrowser.Version(known));
        Assert.Equal(
            SignUpFlow.Data(fresh).EnumerateObject().Select(p => p.Name),
            SignUpFlow.Data(known).EnumerateObject().Select(p => p.Name));
        Assert.Equal("known@example.com", SignUpFlow.Data(known).GetProperty("email").GetString());

        // Nothing of the existing account changed, and nothing was sent to it.
        Assert.Equal(before, (await flow.Database.ScalarAsync<string>(userRow), await flow.Database.ScalarAsync<string>(credentialRow)));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{existing}'"));
        Assert.Equal(0L, await flow.RowsAsync("one_time_token", $"user_id = '{existing}'"));
        Assert.DoesNotContain(host.Jobs.Jobs, j => j.UserId == existing);
        Assert.Equal(0L, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}' AND target_id = '{existing}'"));

        // Its transaction names no User, so "I've verified" can never sign it in.
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND 'registered' = ANY (completed_steps) AND signup_user_id IS NULL AND signup_credential_id IS NULL"));
    }

    [Fact]
    public async Task Every_sign_up_request_is_refused_without_its_CSRF_token_or_from_another_Origin()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        var body = new { stepVersion = SignUpBrowser.Version(signup), email = Email, password = SignUpFlow.Password };

        foreach (var path in new[]
        {
            ProtocolContract.SignupOpenPath, ProtocolContract.SignupBackPath, ProtocolContract.SignupPath,
            ProtocolContract.VerificationResendPath, ProtocolContract.VerificationContinuePath, ProtocolContract.VerificationNewLinkPath,
        })
        {
            using (var noCsrf = await browser.Http.PostAsync(path, new { body.stepVersion, body.email, body.password, token = "x" }, csrf: null))
            {
                Assert.Equal(HttpStatusCode.Forbidden, noCsrf.StatusCode);
                using var step = await HostedBrowser.StepAsync(noCsrf);
                Assert.Equal("csrf_mismatch", step.RootElement.GetProperty("data").GetProperty("code").GetString());
            }

            using (var otherOrigin = await browser.Http.PostAsync(path, body, SignUpBrowser.Csrf(signup), requestOrigin: $"https://{HostB}"))
            {
                Assert.Equal(HttpStatusCode.Forbidden, otherOrigin.StatusCode);
                using var step = await HostedBrowser.StepAsync(otherOrigin);
                Assert.Equal("origin_mismatch", step.RootElement.GetProperty("data").GetProperty("code").GetString());
            }

            using (var noOrigin = await browser.Http.PostAsync(path, body, SignUpBrowser.Csrf(signup), requestOrigin: HostedBrowser.NoOrigin))
            {
                Assert.Equal(HttpStatusCode.Forbidden, noOrigin.StatusCode);
            }
        }

        Assert.Equal(0L, await flow.RowsAsync("user"));
        Assert.Equal(StepNames.Signup, SignUpFlow.Name(await browser.PageAsync()));
    }

    [Fact]
    public async Task With_the_hashing_budget_full_a_sign_up_is_temporarily_unavailable_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync(new PasswordHashLimits(0, 0, TimeSpan.Zero));
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        var events = await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'");

        using var refused = await browser.CreateAsync(signup, Email, SignUpFlow.Password);

        Assert.Equal(StepNames.GenericError, SignUpFlow.Name(refused));
        Assert.Equal("temporarily_unavailable", SignUpFlow.Data(refused).GetProperty("code").GetString());
        await AssertNothingWrittenAsync(flow, events);
    }

    [Fact]
    public async Task A_stale_step_version_gets_the_current_step_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);

        using var stale = await browser.PostAsync(
            ProtocolContract.SignupPath, new { stepVersion = SignUpBrowser.Version(signup) - 1, email = Email, password = SignUpFlow.Password }, SignUpBrowser.Csrf(signup));

        Assert.Equal(StepNames.Signup, SignUpFlow.Name(stale));
        Assert.Equal(SignUpBrowser.Version(signup), SignUpBrowser.Version(stale));
        Assert.Equal(0L, await flow.RowsAsync("user"));
    }

    /// <summary>No account state, no job and no event since <paramref name="events"/>; the transaction still at Signup.</summary>
    private static async Task AssertNothingWrittenAsync(SignUpFlow flow, long events)
    {
        Assert.Equal(0L, await flow.RowsAsync("user"));
        Assert.Equal(0L, await flow.RowsAsync("password_credential"));
        Assert.Equal(0L, await flow.RowsAsync("one_time_token"));
        Assert.Equal(0L, await flow.EmailJobsAsync());
        Assert.Equal(events, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'"));
        Assert.Equal("signup", await flow.Database.ScalarAsync<string>($"SELECT array_to_string(completed_steps, ',') FROM signin_transaction WHERE tenant_id = '{flow.TenantA}'"));
    }
}
