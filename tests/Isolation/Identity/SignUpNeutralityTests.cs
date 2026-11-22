using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Notifications.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.8 (FR-17, FR-8, NFR-6, NFR-20): sign-up stays neutral and limited, at the HTTP level, through the real Hosted
/// Login surface, PostgreSQL as <c>gk_hosted</c> and OpenBao. An address already verified looks like a new one in content,
/// status, next step and timing, changes nothing and only notifies its owner; a Tenant's terms must be accepted and are
/// recorded; sign-up, resend and "Send a new link" are limited per Tenant and per source, alike for every address. One test
/// or more per row of the story's I/O matrix. No assertion prints a password, link or cookie.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SignUpNeutralityTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.neutral.test";
    private const string HostB = "beta.neutral.test";
    private const string Email = "new.user@example.com";
    private const string Known = "known@example.com";
    private const string TermsUrl = "https://acme.example/terms@v2";

    /// <summary>The stated tolerance (NFR-20, <c>docs/threat-model.md</c>): the two medians differ by at most this.</summary>
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(100);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task An_address_already_verified_answers_as_a_new_one_changes_nothing_and_notifies_its_owner_once()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var existing = await AddVerifiedUserAsync(flow, Known);
        var before = await AccountAsync(flow, existing);

        var (_, knownStep) = await flow.SignUpAsync(host, HostA, Known);
        var (_, newStep) = await flow.SignUpAsync(host, HostA, Email);
        using var known = knownStep;
        using var fresh = newStep;

        // The same status (each helper call asserted 200), step and body, apart from the step's life, its CSRF token and
        // the address each typed.
        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(known));
        Assert.Equal(Comparable(fresh, Email), Comparable(known, Known));
        Assert.False(SignUpFlow.Data(known).GetProperty("resent").GetBoolean());

        // No account row changed, and exactly one security notice, with no credential, went to the owner.
        Assert.Equal(before, await AccountAsync(flow, existing));
        var notice = Assert.Single(host.Jobs.Jobs, j => j.UserId == existing);
        Assert.Equal(NotificationsContract.SecurityNotificationTemplate, notice.TemplateId);
        Assert.Null(notice.Credential);
        Assert.Equal(2L, await flow.EmailJobsAsync());
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM job WHERE tenant_id = '{flow.TenantA}' AND id = '{notice.Id}'"));

        // Its transaction records registered the same way, naming no User.
        Assert.Equal(2L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND completed_steps = ARRAY['signup', 'registered']::text[]"));
    }

    [Fact]
    public async Task After_an_address_already_verified_Resend_sends_nothing_and_Continue_is_not_verified_yet_as_for_a_new_one()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var existing = await AddVerifiedUserAsync(flow, Known);

        var (knownBrowser, knownStep) = await flow.SignUpAsync(host, HostA, Known);
        var (newBrowser, newStep) = await flow.SignUpAsync(host, HostA, Email);
        using var known = knownStep;
        using var fresh = newStep;
        var jobs = host.Jobs.Jobs.Count;

        using var knownResent = await knownBrowser.ResendAsync(known);
        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        using var newResent = await newBrowser.ResendAsync(fresh);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(knownResent));
        Assert.True(SignUpFlow.Data(knownResent).GetProperty("resent").GetBoolean());
        Assert.Equal(Comparable(newResent, Email), Comparable(knownResent, Known));
        Assert.Single(host.Jobs.Jobs, j => j.UserId == existing);

        using var knownContinued = await knownBrowser.ContinueAsync(knownResent);
        using var newContinued = await newBrowser.ContinueAsync(newResent);
        Assert.Equal(VerifyEmailErrors.NotVerifiedYet, SignUpFlow.Data(knownContinued).GetProperty("error").GetString());
        Assert.Equal(Comparable(newContinued, Email), Comparable(knownContinued, Known));
        Assert.Equal(0L, await flow.RowsAsync("user_session"));
    }

    [Fact]
    public async Task The_sign_up_of_an_address_already_verified_takes_as_long_as_a_new_ones_within_the_stated_tolerance()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync(signUpLimits: SignUpFlow.Generous);
        await AddVerifiedUserAsync(flow, Known);

        // One of each first, unmeasured, so neither path pays for warming up.
        await TimedSignUpAsync(flow, host, "warm.up@example.com");
        await TimedSignUpAsync(flow, host, Known);

        var newTimes = new List<TimeSpan>();
        var knownTimes = new List<TimeSpan>();
        for (var i = 0; i < 8; i++)
        {
            newTimes.Add(await TimedSignUpAsync(flow, host, $"new.{i}@example.com"));
            knownTimes.Add(await TimedSignUpAsync(flow, host, Known));
        }

        var difference = (Median(newTimes) - Median(knownTimes)).Duration();
        Assert.True(
            difference <= Tolerance,
            $"The medians differ by {difference.TotalMilliseconds:F0} ms (new {Median(newTimes).TotalMilliseconds:F0} ms, existing {Median(knownTimes).TotalMilliseconds:F0} ms).");
    }

    [Fact]
    public async Task With_a_terms_URL_Signup_shows_it_and_an_accepted_sign_up_records_the_URL_and_the_time()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.SetTermsAsync(flow.TenantA, TermsUrl);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        Assert.Equal(TermsUrl, SignUpFlow.Data(signup).GetProperty("termsUrl").GetString());

        using var verify = await browser.CreateAsync(signup, Email, SignUpFlow.Password, acceptTerms: true);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        var user = await flow.UserAsync(Email);
        Assert.Equal(1L, await flow.RowsAsync(
            "user", $"id = '{user}' AND terms_accepted_url = '{TermsUrl}' AND terms_accepted_at > now() - interval '1 minute' AND terms_accepted_at <= now()"));
        Assert.Equal(1L, await flow.EventsAsync("identity.user.signed_up"));
        Assert.Equal(0L, await CodeFlow.RowsHoldingAsync(flow.Database, "audit_event", TermsUrl));
        Assert.DoesNotContain(host.Logs.Lines, l => l.Contains(TermsUrl, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public async Task With_a_terms_URL_a_sign_up_that_doesnt_accept_them_is_terms_required_before_the_rules_and_the_hash(bool? acceptTerms)
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.SetTermsAsync(flow.TenantA, TermsUrl);

        // No hash can run: a sign-up that reached the hash would be temporarily_unavailable instead.
        await using var host = await flow.StartHostAsync(new PasswordHashLimits(0, 0, TimeSpan.Zero));
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        var events = await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'");

        // A password failing the rules too: the terms come first.
        using var refused = await browser.CreateAsync(signup, Email, "aaaaaaaaaaaa", acceptTerms);

        Assert.Equal(StepNames.Signup, SignUpFlow.Name(refused));
        Assert.Equal(SignupErrors.TermsRequired, SignUpFlow.Data(refused).GetProperty("error").GetString());
        Assert.Empty(SignUpFlow.Data(refused).GetProperty("rules").EnumerateArray());
        Assert.Equal(TermsUrl, SignUpFlow.Data(refused).GetProperty("termsUrl").GetString());
        Assert.Equal(Email, SignUpFlow.Data(refused).GetProperty("email").GetString());
        Assert.Equal(SignUpBrowser.Version(signup), SignUpBrowser.Version(refused));
        Assert.Equal(0L, await flow.RowsAsync("user"));
        Assert.Equal(0L, await flow.RowsAsync("password_credential"));
        Assert.Equal(0L, await flow.EmailJobsAsync());
        Assert.Equal(events, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}'"));
        Assert.Equal("signup", await flow.Database.ScalarAsync<string>($"SELECT array_to_string(completed_steps, ',') FROM signin_transaction WHERE tenant_id = '{flow.TenantA}'"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public async Task With_no_terms_URL_a_sign_up_goes_ahead_whatever_acceptTerms_says_and_records_no_terms(bool? acceptTerms)
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(Email);
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(signup).GetProperty("termsUrl").ValueKind);

        using var verify = await browser.CreateAsync(signup, Email, SignUpFlow.Password, acceptTerms);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        Assert.Equal(1L, await flow.RowsAsync("user", "terms_accepted_url IS NULL AND terms_accepted_at IS NULL"));
    }

    [Fact]
    public async Task An_unverified_User_signing_up_again_records_the_terms_with_the_new_credential_and_a_verified_one_records_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (_, first) = await flow.SignUpAsync(host, HostA, Email);
        first.Dispose();
        Assert.Equal(1L, await flow.RowsAsync("user", "terms_accepted_url IS NULL"));
        var existing = await AddVerifiedUserAsync(flow, Known);

        await flow.SetTermsAsync(flow.TenantA, TermsUrl);
        var (_, second) = await flow.SignUpAsync(host, HostA, Email, SignUpFlow.OtherPassword, acceptTerms: true);
        var (_, third) = await flow.SignUpAsync(host, HostA, Known, acceptTerms: true);
        second.Dispose();
        third.Dispose();

        var user = await flow.UserAsync(Email);
        Assert.Equal(1L, await flow.RowsAsync("user", $"id = '{user}' AND terms_accepted_url = '{TermsUrl}' AND terms_accepted_at IS NOT NULL"));
        Assert.Equal(2L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND status = 'pending'"));
        Assert.Equal(1L, await flow.RowsAsync("user", $"id = '{existing}' AND terms_accepted_url IS NULL AND terms_accepted_at IS NULL"));
    }

    [Fact]
    public async Task The_eleventh_sign_up_from_one_source_is_429_with_Retry_After_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        const string source = "203.0.113.7";

        // Ten counted under the default limit; a refused password is counted too, and costs no hash.
        for (var i = 0; i < SecurityLimitsSignUpSource; i++)
        {
            var browser = await flow.BeginAsync(host, HostA, source);
            using var signup = await browser.OpenAsync(Email);
            using var refused = await browser.CreateAsync(signup, Email, "aaaaaaaaaaaa");
            Assert.Equal(StepNames.Signup, SignUpFlow.Name(refused));
        }

        var limited = await flow.BeginAsync(host, HostA, source);
        using var last = await limited.OpenAsync(Email);
        using var response = await limited.Http.PostAsync(ProtocolContract.SignupPath, SignUpBrowser.CreateBody(last, Email, SignUpFlow.Password), SignUpBrowser.Csrf(last));

        await AssertLimitedAsync(response);
        Assert.Equal(0L, await flow.RowsAsync("user"));
        Assert.Equal(0L, await flow.EmailJobsAsync());
        Assert.Empty(host.Jobs.Jobs);
        Assert.Equal("signup", await flow.Database.ScalarAsync<string>(
            $"SELECT array_to_string(completed_steps, ',') FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' ORDER BY created_at DESC LIMIT 1"));

        // Another source still signs up.
        var (_, other) = await flow.SignUpAsync(host, HostA, Email, source: "203.0.113.8");
        using (other)
        {
            Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(other));
        }

        // Only the Tenant's counter and one per source: none keyed by an address.
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{flow.TenantA}' AND policy = 'signup.attempt.tenant'"));
        Assert.Equal(2L, await flow.CountAsync($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{flow.TenantA}' AND policy = 'signup.attempt.source'"));
    }

    [Fact]
    public async Task With_the_Tenants_sign_up_counter_at_its_limit_a_new_source_is_429_too()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var limits = SignUpFlow.Generous with { SignUpTenant = new("signup.attempt.tenant", 2, TimeSpan.FromMinutes(15)) };
        await using var host = await flow.StartHostAsync(signUpLimits: limits);

        foreach (var source in new[] { "198.51.100.1", "198.51.100.2" })
        {
            var browser = await flow.BeginAsync(host, HostA, source);
            using var signup = await browser.OpenAsync(Email);
            using var refused = await browser.CreateAsync(signup, Email, "aaaaaaaaaaaa");
        }

        var limited = await flow.BeginAsync(host, HostA, "198.51.100.3");
        using var last = await limited.OpenAsync(Known);
        using var response = await limited.Http.PostAsync(ProtocolContract.SignupPath, SignUpBrowser.CreateBody(last, Known, SignUpFlow.Password), SignUpBrowser.Csrf(last));

        await AssertLimitedAsync(response);
        Assert.Equal(0L, await flow.RowsAsync("user"));
    }

    [Fact]
    public async Task A_source_kept_going_past_its_limit_doesnt_use_up_the_Tenants_limit()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var limits = SignUpFlow.Generous with
        {
            SignUpTenant = new("signup.attempt.tenant", 3, TimeSpan.FromMinutes(15)),
            SignUpSource = new("signup.attempt.source", 2, TimeSpan.FromMinutes(15)),
        };
        await using var host = await flow.StartHostAsync(signUpLimits: limits);
        const string flooding = "198.51.100.20";

        // Two allowed, then six refused by the source: only the two reach the Tenant's counter.
        for (var i = 0; i < 8; i++)
        {
            var browser = await flow.BeginAsync(host, HostA, flooding);
            using var signup = await browser.OpenAsync(Email);
            using var response = await browser.Http.PostAsync(
                ProtocolContract.SignupPath, SignUpBrowser.CreateBody(signup, Email, "aaaaaaaaaaaa"), SignUpBrowser.Csrf(signup));
            Assert.Equal(i < 2 ? HttpStatusCode.OK : HttpStatusCode.TooManyRequests, response.StatusCode);
        }

        var (_, other) = await flow.SignUpAsync(host, HostA, Email, source: "198.51.100.21");
        using (other)
        {
            Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(other));
        }

        Assert.Equal(1L, await flow.RowsAsync("user"));
    }

    [Fact]
    public async Task Past_the_verification_send_limit_Resend_is_429_and_Send_a_new_link_is_link_sent_sending_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var limits = SignUpFlow.Generous with { SendSource = new("verification.send.source", 2, TimeSpan.FromMinutes(15)) };
        await using var host = await flow.StartHostAsync(signUpLimits: limits);
        const string source = "192.0.2.10";
        var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, Email, source: source);
        using var verify = verifyStep;
        var user = await flow.UserAsync(Email);
        var link = Assert.Single(host.Jobs.LinksFor(user));

        // One resend and one new link use up the source's two sends; the new link replaces the resent one.
        using var resent = await browser.ResendAsync(verify);
        Assert.True(SignUpFlow.Data(resent).GetProperty("resent").GetBoolean());
        var newest = host.Jobs.LinksFor(user)[^1];
        using (var sent = await NewLinkAsync(browser.Http, newest))
        {
            Assert.Equal(HttpStatusCode.OK, sent.StatusCode);
        }

        var jobs = host.Jobs.Jobs.Count;
        Assert.Equal(3, host.Jobs.LinksFor(user).Count);

        using (var limitedResend = await browser.Http.PostAsync(
            ProtocolContract.VerificationResendPath, new { stepVersion = SignUpBrowser.Version(resent) }, SignUpBrowser.Csrf(resent)))
        {
            await AssertLimitedAsync(limitedResend);
        }

        using (var limitedLink = await NewLinkAsync(browser.Http, host.Jobs.LinksFor(user)[^1]))
        {
            Assert.Equal(HttpStatusCode.OK, limitedLink.StatusCode);
            using var step = await HostedBrowser.StepAsync(limitedLink);
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(step));
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(3L, await flow.EmailJobsAsync());
        Assert.NotEqual(link, newest);
    }

    [Fact]
    public async Task With_the_Tenants_send_counter_at_its_limit_a_new_sources_Resend_is_429_and_its_new_link_sends_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var limits = SignUpFlow.Generous with { SendTenant = new("verification.send.tenant", 2, TimeSpan.FromMinutes(15)) };
        await using var host = await flow.StartHostAsync(signUpLimits: limits);

        // Two sends, from two sources, use up the Tenant's.
        foreach (var (email, source) in new[] { ("first@example.com", "203.0.113.31"), ("second@example.com", "203.0.113.32") })
        {
            var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, email, source: source);
            using var verify = verifyStep;
            using var resent = await browser.ResendAsync(verify);
            Assert.True(SignUpFlow.Data(resent).GetProperty("resent").GetBoolean());
        }

        const string third = "203.0.113.33";
        var (limited, limitedStep) = await flow.SignUpAsync(host, HostA, Email, source: third);
        using var limitedVerify = limitedStep;
        var link = Assert.Single(host.Jobs.LinksFor(await flow.UserAsync(Email)));
        var jobs = host.Jobs.Jobs.Count;

        using (var resend = await limited.Http.PostAsync(
            ProtocolContract.VerificationResendPath, new { stepVersion = SignUpBrowser.Version(limitedVerify) }, SignUpBrowser.Csrf(limitedVerify)))
        {
            await AssertLimitedAsync(resend);
        }

        using (var newLink = await NewLinkAsync(limited.Http, link))
        {
            Assert.Equal(HttpStatusCode.OK, newLink.StatusCode);
            using var step = await HostedBrowser.StepAsync(newLink);
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(step));
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
    }

    [Fact]
    public async Task A_source_limited_in_one_Tenant_still_signs_up_in_another()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var clientB = await flow.Database.CreateWebClientAsync(flow.Flow.B.TenantId, [CodeFlowSetup.Callback]);
        var limits = SignUpFlow.Generous with { SignUpSource = new("signup.attempt.source", 1, TimeSpan.FromMinutes(15)) };
        await using var host = await flow.StartHostAsync(signUpLimits: limits);
        const string source = "192.0.2.44";

        var (_, first) = await flow.SignUpAsync(host, HostA, Email, source: source);
        first.Dispose();
        var limited = await flow.BeginAsync(host, HostA, source);
        using var again = await limited.OpenAsync(Known);
        using (var response = await limited.Http.PostAsync(ProtocolContract.SignupPath, SignUpBrowser.CreateBody(again, Known, SignUpFlow.Password), SignUpBrowser.Csrf(again)))
        {
            await AssertLimitedAsync(response);
        }

        var (_, atB) = await flow.SignUpAsync(host, HostB, Known, source: source, clientId: clientB.ClientId);
        using (atB)
        {
            Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(atB));
        }

        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM \"user\" WHERE tenant_id = '{flow.Flow.B.TenantId}' AND email = '{Known}'"));
    }

    [Fact]
    public async Task The_same_email_in_two_Tenants_makes_two_unrelated_Users_and_the_second_gets_a_link_not_a_notice()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var clientB = await flow.Database.CreateWebClientAsync(flow.Flow.B.TenantId, [CodeFlowSetup.Callback]);
        await using var host = await flow.StartHostAsync();
        var tenantB = flow.Flow.B.TenantId;

        // A's User signs up and verifies, so A holds a verified account with that address.
        var (browserA, stepA) = await flow.SignUpAsync(host, HostA, Email);
        stepA.Dispose();
        var userA = await flow.UserAsync(Email);
        using (var verified = await browserA.OpenLinkAsync(Assert.Single(host.Jobs.LinksFor(userA))))
        {
            Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(verified));
        }

        var (_, stepB) = await flow.SignUpAsync(host, HostB, Email, clientId: clientB.ClientId);
        using (stepB)
        {
            Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(stepB));
        }

        var userB = await flow.Database.ScalarAsync<Guid>($"SELECT id FROM \"user\" WHERE tenant_id = '{tenantB}' AND email = '{Email}'");
        Assert.NotEqual(userA, userB);
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM \"user\" WHERE tenant_id = '{tenantB}' AND email = '{Email}' AND email_verified_at IS NULL"));
        Assert.Equal(1L, await flow.CountAsync($"SELECT count(*) FROM password_credential WHERE tenant_id = '{tenantB}' AND user_id = '{userB}' AND status = 'pending'"));

        // B's sign-up is a new one: a verification link for B's User, and no notice to anyone.
        Assert.Single(host.Jobs.LinksFor(userB));
        Assert.DoesNotContain(host.Jobs.Jobs, j => j.TemplateId == NotificationsContract.SecurityNotificationTemplate);
        Assert.All(host.Jobs.Jobs.Where(j => j.UserId == userB), j => Assert.Equal(tenantB, j.TenantId));
    }

    [Fact]
    public async Task With_sign_up_disabled_Sign_up_and_Create_account_answer_the_same_Login_step_for_an_existing_and_a_new_address()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var existing = await AddVerifiedUserAsync(flow, Known);
        var before = await AccountAsync(flow, existing);

        // Create account after sign-up closed, from a Signup opened with no email.
        var knownBrowser = await flow.BeginAsync(host, HostA);
        var newBrowser = await flow.BeginAsync(host, HostA);
        using var knownSignup = await knownBrowser.OpenAsync(string.Empty);
        using var newSignup = await newBrowser.OpenAsync(string.Empty);
        await flow.Database.ExecuteAsync($"UPDATE connection SET signup_enabled = false WHERE tenant_id = '{flow.TenantA}'");

        using var knownCreate = await knownBrowser.Http.PostAsync(ProtocolContract.SignupPath, SignUpBrowser.CreateBody(knownSignup, Known, SignUpFlow.Password), SignUpBrowser.Csrf(knownSignup));
        using var newCreate = await newBrowser.Http.PostAsync(ProtocolContract.SignupPath, SignUpBrowser.CreateBody(newSignup, Email, SignUpFlow.Password), SignUpBrowser.Csrf(newSignup));
        Assert.Equal(newCreate.StatusCode, knownCreate.StatusCode);
        using var knownLogin = await HostedBrowser.StepAsync(knownCreate);
        using var newLogin = await HostedBrowser.StepAsync(newCreate);
        Assert.Equal(StepNames.Login, SignUpFlow.Name(knownLogin));
        Assert.Equal(Comparable(newLogin), Comparable(knownLogin));

        // Sign up at Login, closed: the same Login step, unchanged.
        using var knownOpen = await knownBrowser.Http.PostAsync(
            ProtocolContract.SignupOpenPath, new { stepVersion = SignUpBrowser.Version(knownLogin), email = Known }, SignUpBrowser.Csrf(knownLogin));
        using var newOpen = await newBrowser.Http.PostAsync(
            ProtocolContract.SignupOpenPath, new { stepVersion = SignUpBrowser.Version(newLogin), email = Email }, SignUpBrowser.Csrf(newLogin));
        Assert.Equal(newOpen.StatusCode, knownOpen.StatusCode);
        using var knownStill = await HostedBrowser.StepAsync(knownOpen);
        using var newStill = await HostedBrowser.StepAsync(newOpen);
        Assert.Equal(StepNames.Login, SignUpFlow.Name(knownStill));
        Assert.Equal(Comparable(newStill), Comparable(knownStill));

        Assert.Equal(1L, await flow.RowsAsync("user"));
        Assert.Equal(before, await AccountAsync(flow, existing));
        Assert.Empty(host.Jobs.Jobs);
        Assert.Equal(0L, await flow.EmailJobsAsync());
    }

    /// <summary>The default per-source sign-up limit (Story 4.8), as the policy holds it.</summary>
    private static int SecurityLimitsSignUpSource => SignUpLimits.Default.SignUpSource.Limit;

    /// <summary>A verified User with an active password, as an earlier sign-up and verification leave one.</summary>
    private static async Task<Guid> AddVerifiedUserAsync(SignUpFlow flow, string email)
    {
        var id = Guid.CreateVersion7();
        await flow.Database.ExecuteAsync(
            $"INSERT INTO \"user\" (tenant_id, id, email, email_verified_at) VALUES ('{flow.TenantA}', '{id}', '{email}', now()); "
            + $"INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) VALUES ('{flow.TenantA}', gen_random_uuid(), '{id}', gen_random_uuid(), '$argon2id$known', 'active')");
        return id;
    }

    /// <summary>Every account row of <paramref name="userId"/>: the User, its credentials and its links, as JSON.</summary>
    private static async Task<string> AccountAsync(SignUpFlow flow, Guid userId) =>
        await flow.Database.ScalarAsync<string>(
            $"""
            SELECT (SELECT to_jsonb(u)::text FROM "user" u WHERE u.tenant_id = '{flow.TenantA}' AND u.id = '{userId}')
                || '|' || COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.id)::text FROM password_credential c WHERE c.tenant_id = '{flow.TenantA}' AND c.user_id = '{userId}'), '')
                || '|' || COALESCE((SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id)::text FROM one_time_token t WHERE t.tenant_id = '{flow.TenantA}' AND t.user_id = '{userId}'), '')
            """);

    /// <summary>
    /// The step as JSON with what differs by transaction by design set aside: its version, life and CSRF token, and
    /// <paramref name="email"/>, the address the browser typed, wherever the data holds it.
    /// </summary>
    private static string Comparable(JsonDocument step, string? email = null)
    {
        var node = JsonNode.Parse(step.RootElement.GetRawText())!.AsObject();
        node["stepVersion"] = 0;
        node["expiresInSeconds"] = 0;
        node["csrfToken"] = "csrf";
        if (email is not null && node["data"]?["email"]?.GetValue<string>() == email)
        {
            node["data"]!["email"] = "email";
        }

        return node.ToJsonString();
    }

    /// <summary>A fresh browser's Create account for <paramref name="email"/>, only the POST timed.</summary>
    private static async Task<TimeSpan> TimedSignUpAsync(SignUpFlow flow, ProtocolHost host, string email)
    {
        var browser = await flow.BeginAsync(host, HostA);
        using var signup = await browser.OpenAsync(email);
        var watch = Stopwatch.StartNew();
        using var verify = await browser.CreateAsync(signup, email, SignUpFlow.Password);
        watch.Stop();
        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(verify));
        return watch.Elapsed;
    }

    private static TimeSpan Median(List<TimeSpan> times)
    {
        var sorted = times.Order().ToList();
        return sorted.Count % 2 == 1 ? sorted[sorted.Count / 2] : (sorted[(sorted.Count / 2) - 1] + sorted[sorted.Count / 2]) / 2;
    }

    /// <summary>"Send a new link" for <paramref name="token"/>, with its link-bound CSRF token.</summary>
    private static Task<HttpResponseMessage> NewLinkAsync(HostedBrowser browser, string token) =>
        browser.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token }, SignUpFlow.LinkCsrf(token));

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
