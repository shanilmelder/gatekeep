using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.11 (FR-19, FR-48, NFR-6, NFR-20): resetting a forgotten password, at the HTTP level, through the real Hosted
/// Login surface, PostgreSQL as <c>gk_hosted</c> and OpenBao. A request answers the same neutral confirmation for every
/// address, in content, status and timing; only a User holding an active password gets a 30-minute, single-use, hashed
/// link, the newest of which alone works. Completing it replaces the password, verifies the email, ends every Session and
/// Token Family of the User through the one revocation path, queues a security notice and starts no Session. Also the
/// reset limits, the cross-Tenant reset link and the request checks. One test or more per row of the story's I/O matrix.
/// No assertion prints a password, link or token.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class PasswordResetTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.reset-password.test";
    private const string HostB = "beta.reset-password.test";
    private const string Known = "known.user@example.com";
    private const string Unknown = "nobody@example.com";
    private const string Pending = "pending.user@example.com";
    private const string NewPassword = "Fresh-Lantern-4orbit";
    private const string ResetEvent = "identity.password.reset";

    /// <summary>The stated tolerance (NFR-20, <c>docs/threat-model.md</c> T-6): the two medians differ by at most this.</summary>
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(100);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_request_for_a_User_with_a_password_answers_the_neutral_confirmation_and_sends_one_hashed_link()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, credential) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();

        var (_, sent) = await flow.RequestResetAsync(host, HostA, Known);
        using (sent)
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
            Assert.True(SignUpFlow.Data(sent).GetProperty("back").GetBoolean());
        }

        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        Assert.Equal(1L, await flow.RowsAsync(
            "one_time_token",
            $"user_id = '{user}' AND credential_id = '{credential}' AND purpose = 'password_reset' AND used_at IS NULL "
            + $"AND token_hash = '\\x{SignUpFlow.HashHex(link)}'::bytea "
            + "AND expires_at BETWEEN now() + interval '29 minutes' AND now() + interval '31 minutes'"));
        Assert.Equal(0L, await flow.CountAsync($"SELECT count(*) FROM one_time_token WHERE token_hash = convert_to('{link}', 'UTF8')"));
        Assert.Equal(1L, await flow.EmailJobsAsync());
        Assert.Equal(0L, await flow.CountAsync("SELECT count(*) FROM user_session"));
    }

    [Fact]
    public async Task An_unknown_or_pending_only_address_gets_the_identical_confirmation_with_no_link_or_email()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await AddPendingUserAsync(flow, Pending);
        await using var host = await flow.StartHostAsync();

        var (_, known) = await flow.RequestResetAsync(host, HostA, Known);
        var (_, unknown) = await flow.RequestResetAsync(host, HostA, Unknown);
        var (_, pending) = await flow.RequestResetAsync(host, HostA, Pending);
        using (known)
        using (unknown)
        using (pending)
        {
            Assert.Equal(Comparable(known), Comparable(unknown));
            Assert.Equal(Comparable(known), Comparable(pending));
        }

        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset'"));
        Assert.Single(host.Jobs.Jobs, j => j.TemplateId == NotificationsContract.PasswordResetTemplate);
        Assert.Equal(1L, await flow.EmailJobsAsync());
    }

    [Fact]
    public async Task A_known_and_an_unknown_address_take_the_same_time_within_the_stated_tolerance()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(resetLimits: SignUpFlow.GenerousReset);

        // One warm-up of each, then 8 alternating of each; only the request itself is timed. Neither path sleeps.
        await TimedRequestAsync(flow, host, Known);
        await TimedRequestAsync(flow, host, Unknown);
        var known = new List<TimeSpan>();
        var unknown = new List<TimeSpan>();
        for (var i = 0; i < 8; i++)
        {
            known.Add(await TimedRequestAsync(flow, host, Known));
            unknown.Add(await TimedRequestAsync(flow, host, Unknown));
        }

        var difference = (Median(known) - Median(unknown)).Duration();
        Assert.True(difference <= Tolerance, $"The medians differ by {difference.TotalMilliseconds:F0} ms, over the {Tolerance.TotalMilliseconds:F0} ms tolerance.");
    }

    [Fact]
    public async Task Of_two_requests_only_the_newest_link_works_and_the_older_shows_link_expired()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();

        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var links = host.Jobs.ResetLinksFor(user);
        Assert.Equal(2, links.Count);
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"user_id = '{user}' AND purpose = 'password_reset'"));

        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using (var first = await browser.OpenResetLinkAsync(links[0]))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(first));
            Assert.Equal(LinkPurposes.Reset, SignUpFlow.Data(first).GetProperty("purpose").GetString());
            Assert.Equal(links[0], SignUpFlow.Data(first).GetProperty("token").GetString());
            Assert.Equal(SignUpFlow.ResetCsrf(links[0]), SignUpBrowser.Csrf(first));
        }

        using (var refused = await browser.CompleteResetAsync(links[0], NewPassword))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(refused));
        }

        using var second = await browser.OpenResetLinkAsync(links[1]);
        Assert.Equal(StepNames.ResetPassword, SignUpFlow.Name(second));
        Assert.Equal(12, SignUpFlow.Data(second).GetProperty("policy").GetProperty("minLength").GetInt32());
        Assert.Equal("good", SignUpFlow.Data(second).GetProperty("policy").GetProperty("strength").GetString());
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(second).GetProperty("error").ValueKind);
        Assert.Equal(0, SignUpFlow.Data(second).GetProperty("rules").GetArrayLength());
        Assert.Equal(SignUpFlow.ResetCsrf(links[1]), SignUpBrowser.Csrf(second));
        Assert.DoesNotContain(links[1], second.RootElement.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_expired_or_used_link_shows_link_expired_and_changes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        // Used once, then again.
        using (var changed = await browser.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.PasswordChanged, SignUpFlow.Name(changed));
        }

        var hash = await HashAsync(flow, user);
        using (var again = await browser.OpenResetLinkAsync(link))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(again));
        }

        using (var reused = await browser.CompleteResetAsync(link, SignUpFlow.OtherPassword))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(reused));
        }

        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(1L, await flow.EventsAsync(ResetEvent));

        // A new link, 31 minutes old.
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var fresh = host.Jobs.ResetLinksFor(user)[^1];
        await flow.Database.ExecuteAsync(
            $"UPDATE one_time_token SET expires_at = now() - interval '1 minute' WHERE tenant_id = '{flow.TenantA}' AND purpose = 'password_reset' AND used_at IS NULL");
        using (var expired = await browser.OpenResetLinkAsync(fresh))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(expired));
            Assert.Equal(LinkPurposes.Reset, SignUpFlow.Data(expired).GetProperty("purpose").GetString());
        }

        using (var late = await browser.CompleteResetAsync(fresh, SignUpFlow.OtherPassword))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(late));
        }

        Assert.Equal(hash, await HashAsync(flow, user));

        // A value that was never a link keeps no token.
        using var malformed = await browser.OpenResetLinkAsync("nope");
        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(malformed));
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(malformed).GetProperty("token").ValueKind);
    }

    [Fact]
    public async Task A_confirmation_that_doesnt_match_is_password_mismatch_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var hash = await HashAsync(flow, user);
        var jobs = host.Jobs.Jobs.Count;

        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using var mismatch = await browser.CompleteResetAsync(link, NewPassword, NewPassword + "x");

        Assert.Equal(StepNames.ResetPassword, SignUpFlow.Name(mismatch));
        Assert.Equal(ResetPasswordErrors.PasswordMismatch, SignUpFlow.Data(mismatch).GetProperty("error").GetString());
        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset' AND used_at IS NULL"));
        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(0L, await flow.EventsAsync(ResetEvent));
    }

    [Fact]
    public async Task The_current_password_again_is_refused_by_the_history_rule_and_a_short_one_by_length_writing_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);

        // The password the User holds is in their history, as activating it leaves it; the default policy keeps 5.
        await flow.Database.ExecuteAsync(
            "INSERT INTO password_history (tenant_id, id, user_id, password_hash, created_at) "
            + $"SELECT tenant_id, gen_random_uuid(), user_id, password_hash, now() FROM password_credential WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}'");
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var hash = await HashAsync(flow, user);
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        using (var reused = await browser.CompleteResetAsync(link, SignUpFlow.Password))
        {
            Assert.Equal(StepNames.ResetPassword, SignUpFlow.Name(reused));
            Assert.Equal(ResetPasswordErrors.PasswordRule, SignUpFlow.Data(reused).GetProperty("error").GetString());
            Assert.Equal(["history"], SignUpFlow.Data(reused).GetProperty("rules").EnumerateArray().Select(r => r.GetString()!).ToArray());
        }

        using (var shortOne = await browser.CompleteResetAsync(link, "Sh0rt!"))
        {
            Assert.Contains("length", SignUpFlow.Data(shortOne).GetProperty("rules").EnumerateArray().Select(r => r.GetString()));
        }

        // Personal data: the email's local part.
        using (var personal = await browser.CompleteResetAsync(link, "Known.user-Lantern-4"))
        {
            Assert.Contains("personal_data", SignUpFlow.Data(personal).GetProperty("rules").EnumerateArray().Select(r => r.GetString()));
        }

        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(1L, await flow.RowsAsync("password_history", $"user_id = '{user}'"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset' AND used_at IS NULL"));
        Assert.Equal(0L, await flow.EventsAsync(ResetEvent));
    }

    /// <summary>
    /// FR-48's "password reset" trigger: a completed reset ends every Session and Token Family of the User through
    /// <c>ISessions.RevokeAccessAsync</c>, sparing none, and starts no Session.
    /// </summary>
    [Fact]
    [Trait("FR-48", "password reset")]
    public async Task A_completed_reset_ends_every_Session_and_Token_Family_of_the_User_and_starts_none()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, credential) = await flow.AddPasswordUserAsync(Known, verified: false);

        // Two signed-in browsers, each with a Token Family from the code flow. The User is verified only for signing in.
        await flow.Database.ExecuteAsync($"UPDATE \"user\" SET email_verified_at = now() WHERE id = '{user}'");
        await using var host = await flow.StartHostAsync();
        for (var i = 0; i < 2; i++)
        {
            await SignInWithFamilyAsync(flow, host);
        }

        await flow.Database.ExecuteAsync($"UPDATE \"user\" SET email_verified_at = NULL WHERE id = '{user}'");

        // A pending credential, as an earlier unverified sign-up would leave, with its verification link.
        var pendingCredential = Guid.CreateVersion7();
        await flow.Database.ExecuteAsync(
            "INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) "
            + $"SELECT tenant_id, '{pendingCredential}', user_id, connection_id, password_hash, 'pending' FROM password_credential WHERE id = '{credential}'; "
            + "INSERT INTO one_time_token (tenant_id, id, user_id, credential_id, purpose, token_hash, expires_at) "
            + $"VALUES ('{flow.TenantA}', gen_random_uuid(), '{user}', '{pendingCredential}', 'email_verification', sha256('pending'), now() + interval '1 day')");
        Assert.Equal(2L, await flow.RowsAsync("user_session", $"user_id = '{user}' AND ended_at IS NULL"));
        var sessionsBefore = await flow.CountAsync("SELECT count(*) FROM user_session");

        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var jobs = host.Jobs.Jobs.Count;
        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using (var changed = await other.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.PasswordChanged, SignUpFlow.Name(changed));
            Assert.Equal(PasswordChangedContinuations.Close, SignUpFlow.Data(changed).GetProperty("continueTo").GetString());
        }

        // The password is replaced in place and kept in the history; the link is used; the email verified; the pending
        // credential and its link gone.
        Assert.True(await Gatekeep.Modules.Authentication.Contracts.AuthenticationContract.VerifyPasswordAsync(
            new Gatekeep.Kernel.Secrets.Secret<string>(NewPassword), await HashAsync(flow, user)));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND id = '{credential}' AND status = 'active'"));
        Assert.Equal(0L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND status = 'pending'"));
        Assert.Equal(1L, await flow.RowsAsync("password_history", $"user_id = '{user}'"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"user_id = '{user}' AND purpose = 'password_reset' AND used_at IS NOT NULL"));
        Assert.Equal(0L, await flow.RowsAsync("one_time_token", $"user_id = '{user}' AND purpose = 'email_verification'"));
        Assert.Equal(1L, await flow.RowsAsync("user", $"id = '{user}' AND email_verified_at IS NOT NULL"));

        // Every Session and Token Family of the User ended, none spared, and no Session started.
        Assert.Equal(sessionsBefore, await flow.CountAsync("SELECT count(*) FROM user_session"));
        Assert.Equal(0L, await flow.RowsAsync("user_session", $"user_id = '{user}' AND ended_at IS NULL"));
        Assert.Equal(2L, await flow.RowsAsync("user_session", $"user_id = '{user}' AND end_reason = 'credential_change'"));
        Assert.Equal(0L, await flow.CountAsync(
            $"SELECT count(*) FROM \"authorization\" a JOIN user_session s ON s.tenant_id = a.tenant_id AND s.id = a.user_session_id WHERE s.user_id = '{user}' AND a.status <> 'revoked'"));
        Assert.Equal(2L, await flow.CountAsync(
            $"SELECT count(*) FROM \"authorization\" a JOIN user_session s ON s.tenant_id = a.tenant_id AND s.id = a.user_session_id WHERE s.user_id = '{user}'"));
        Assert.False(other.Http.Cookies.ContainsKey(ProtocolContract.SessionCookie), "A reset set a Session cookie.");

        // One revocation by the User, the reset event, and the security notice queued in the same command.
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}' AND type_code = 'sessions.access.revoked' AND actor_kind = 'user' AND actor_id = '{user}' AND target_id = '{user}'"));
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM audit_event e WHERE tenant_id = '{flow.TenantA}' AND type_code = '{ResetEvent}' AND actor_kind = 'user' AND actor_id = '{user}' AND target_id = '{user}' "
            + "AND NOT EXISTS (SELECT 1 FROM audit_detail d WHERE d.tenant_id = e.tenant_id AND d.event_id = e.id)"));
        var notice = Assert.Single(host.Jobs.Jobs.Skip(jobs));
        Assert.Equal(NotificationsContract.SecurityNotificationTemplate, notice.TemplateId);
        Assert.Equal(user, notice.UserId);
        Assert.Null(notice.Credential);
    }

    [Fact]
    public async Task After_a_reset_the_old_password_is_incorrect_and_the_new_one_signs_in()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        using (var changed = await new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New())
            .CompleteResetAsync(Assert.Single(host.Jobs.ResetLinksFor(user)), NewPassword))
        {
            Assert.Equal(StepNames.PasswordChanged, SignUpFlow.Name(changed));
        }

        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);
        using (var old = await browser.LogInAsync(password, SignUpFlow.Password))
        {
            Assert.Equal(PasswordErrors.Incorrect, SignUpFlow.Data(old).GetProperty("error").GetString());
        }

        using var redirect = await browser.LogInAsync(password, NewPassword);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
    }

    [Fact]
    public async Task In_the_browser_that_asked_Password_changed_offers_Log_in_and_the_transaction_is_back_at_Login_with_the_email()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var (browser, sent) = await flow.RequestResetAsync(host, HostA, Known);
        sent.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));

        using (var page = await browser.OpenResetLinkAsync(link))
        {
            Assert.Equal(StepNames.ResetPassword, SignUpFlow.Name(page));
        }

        using (var changed = await browser.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.PasswordChanged, SignUpFlow.Name(changed));
            Assert.Equal(PasswordChangedContinuations.Login, SignUpFlow.Data(changed).GetProperty("continueTo").GetString());
        }

        Assert.False(browser.Http.Cookies.ContainsKey(ProtocolContract.SessionCookie), "A reset set a Session cookie.");
        using var login = await browser.PageAsync();
        Assert.Equal(StepNames.Login, SignUpFlow.Name(login));
        Assert.Equal(Known, SignUpFlow.Data(login).GetProperty("email").GetString());

        // Continue works again, and the new password signs in.
        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, NewPassword);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
    }

    [Fact]
    public async Task Forgot_password_keeps_the_email_names_an_invalid_one_and_Back_to_login_returns_with_it()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);

        using var forgot = await browser.ForgotAsync(password);
        Assert.Equal(StepNames.ForgotPassword, SignUpFlow.Name(forgot));
        Assert.Equal(Known, SignUpFlow.Data(forgot).GetProperty("email").GetString());
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(forgot).GetProperty("error").ValueKind);

        using var invalid = await browser.RequestResetAsync(forgot, "not an email");
        Assert.Equal(StepNames.ForgotPassword, SignUpFlow.Name(invalid));
        Assert.Equal(ForgotPasswordErrors.EmailInvalid, SignUpFlow.Data(invalid).GetProperty("error").GetString());
        Assert.Equal(SignUpBrowser.Version(forgot), SignUpBrowser.Version(invalid));

        using var back = await browser.ResetBackAsync(forgot);
        Assert.Equal(StepNames.Login, SignUpFlow.Name(back));
        Assert.Equal(Known, SignUpFlow.Data(back).GetProperty("email").GetString());

        // From the confirmation too: Back to login, with the address asked for.
        using var again = await browser.IdentifyAsync(Known);
        using var forgotAgain = await browser.ForgotAsync(again);
        using var sent = await browser.RequestResetAsync(forgotAgain, Unknown);
        using var fromSent = await browser.ResetBackAsync(sent);
        Assert.Equal(StepNames.Login, SignUpFlow.Name(fromSent));
        Assert.Equal(Unknown, SignUpFlow.Data(fromSent).GetProperty("email").GetString());
        Assert.Equal(0L, await flow.RowsAsync("one_time_token"));
    }

    [Fact]
    public async Task Past_the_recipient_limit_a_request_is_still_the_neutral_confirmation_with_no_new_link_or_email()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();

        var answers = new List<string>();
        for (var i = 0; i < 4; i++)
        {
            var (_, sent) = await flow.RequestResetAsync(host, HostA, Known, source: $"198.51.100.{i + 1}");
            using (sent)
            {
                Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
                answers.Add(Comparable(sent));
            }
        }

        Assert.Single(answers.Distinct());
        Assert.Equal(3, host.Jobs.ResetLinksFor(user).Count);
        Assert.Equal(3L, await flow.EmailJobsAsync());
    }

    [Fact]
    public async Task An_unknown_address_past_the_recipient_limit_gets_the_same_answer_every_time()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        var (_, knownSent) = await flow.RequestResetAsync(host, HostA, Known, source: "198.51.100.200");
        var expected = Comparable(knownSent);
        knownSent.Dispose();

        for (var i = 0; i < 4; i++)
        {
            var (_, sent) = await flow.RequestResetAsync(host, HostA, Unknown, source: $"198.51.100.{i + 1}");
            using (sent)
            {
                Assert.Equal(expected, Comparable(sent));
            }
        }

        // Only the known address's one link and email exist.
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset'"));
        Assert.Equal(1L, await flow.EmailJobsAsync());
    }

    [Fact]
    public async Task One_request_runs_one_Transit_encryption_for_a_known_an_unknown_and_a_pending_only_address_and_none_past_the_recipient_limit()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        await AddPendingUserAsync(flow, Pending);
        var limits = new PasswordResetLimits(
            SignUpFlow.GenerousReset.Tenant, SignUpFlow.GenerousReset.Source, new("reset.request.recipient", 1, TimeSpan.FromMinutes(15)));
        await using var host = await flow.StartHostAsync(resetLimits: limits);

        foreach (var email in new[] { Known, Unknown, Pending })
        {
            Assert.Equal(1, await EncryptionsOfOneRequestAsync(flow, host, email));
        }

        // Each address is now past its limit of 1: nothing is encrypted, as nothing is issued or sent.
        foreach (var email in new[] { Known, Unknown })
        {
            Assert.Equal(0, await EncryptionsOfOneRequestAsync(flow, host, email));
        }
    }

    [Fact]
    public async Task Send_a_new_link_past_the_source_limit_still_answers_link_sent_and_issues_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        var limits = new PasswordResetLimits(
            SignUpFlow.GenerousReset.Tenant, new("reset.request.source", 1, TimeSpan.FromMinutes(15)), SignUpFlow.GenerousReset.Recipient);
        await using var host = await flow.StartHostAsync(resetLimits: limits);
        (await flow.RequestResetAsync(host, HostA, Known, source: "198.51.100.40")).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        await flow.Database.ExecuteAsync($"UPDATE one_time_token SET expires_at = now() - interval '1 minute' WHERE tenant_id = '{flow.TenantA}'");

        var browser = new SignUpBrowser(new HostedBrowser(host, HostA) { Source = "198.51.100.50" }, Pkce.New());
        using (var first = await browser.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(first));
        }

        Assert.Equal(2, host.Jobs.ResetLinksFor(user).Count);
        var jobs = host.Jobs.Jobs.Count;
        var rows = await flow.RowsAsync("one_time_token");

        using (var limited = await browser.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(limited));
            Assert.False(SignUpFlow.Data(limited).GetProperty("back").GetBoolean());
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(rows, await flow.RowsAsync("one_time_token"));
    }

    [Fact]
    public async Task Reset_password_submits_past_the_source_limit_are_429()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        var limits = new PasswordResetLimits(
            SignUpFlow.GenerousReset.Tenant, new("reset.request.source", 2, TimeSpan.FromMinutes(15)), SignUpFlow.GenerousReset.Recipient);
        await using var host = await flow.StartHostAsync(resetLimits: limits);
        (await flow.RequestResetAsync(host, HostA, Known, source: "198.51.100.40")).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var hash = await HashAsync(flow, user);

        var browser = new SignUpBrowser(new HostedBrowser(host, HostA) { Source = "198.51.100.60" }, Pkce.New());
        for (var i = 0; i < 2; i++)
        {
            using var mismatch = await browser.CompleteResetAsync(link, NewPassword, NewPassword + "x");
            Assert.Equal(ResetPasswordErrors.PasswordMismatch, SignUpFlow.Data(mismatch).GetProperty("error").GetString());
        }

        using (var limited = await browser.Http.PostAsync(
            ProtocolContract.ResetCompletePath, new { token = link, password = NewPassword, confirm = NewPassword }, SignUpFlow.ResetCsrf(link)))
        {
            await AssertLimitedAsync(limited);
        }

        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(0L, await flow.EventsAsync(ResetEvent));
    }

    [Fact]
    public async Task A_verification_link_at_the_reset_page_or_Reset_password_is_link_expired()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        (await flow.SignUpAsync(host, HostA, "new.user@example.com")).Step.Dispose();
        var link = host.Jobs.LastLink();
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        using (var page = await browser.OpenResetLinkAsync(link))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(page));
            Assert.Equal(LinkPurposes.Reset, SignUpFlow.Data(page).GetProperty("purpose").GetString());
        }

        using (var complete = await browser.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(complete));
        }

        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'email_verification' AND used_at IS NULL"));
        Assert.Equal(0L, await flow.EventsAsync(ResetEvent));
    }

    [Fact]
    public async Task Log_in_isnt_offered_when_the_browsers_transaction_asked_for_another_address()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var (browser, sent) = await flow.RequestResetAsync(host, HostA, Unknown);
        sent.Dispose();

        using (var changed = await browser.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.PasswordChanged, SignUpFlow.Name(changed));
            Assert.Equal(PasswordChangedContinuations.Close, SignUpFlow.Data(changed).GetProperty("continueTo").GetString());
        }

        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND identifier = '{Unknown}' AND completed_steps = ARRAY['identifier', 'reset', 'reset_sent']::text[]"));
    }

    [Fact]
    public async Task A_used_reset_links_Send_a_new_link_sends_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        (await browser.CompleteResetAsync(link, NewPassword)).Dispose();
        var jobs = host.Jobs.Jobs.Count;

        using var sent = await browser.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link));

        Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Single(host.Jobs.ResetLinksFor(user));
        Assert.Equal(0L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset' AND used_at IS NULL"));
    }

    [Fact]
    public async Task With_the_database_Connection_disabled_the_reset_routes_refuse()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));

        // A browser at the Password step, and one at Forgot password, before the Connection is disabled.
        var atPassword = await flow.BeginAsync(host, HostA);
        using var password = await atPassword.IdentifyAsync(Known);
        var atForgot = await flow.BeginAsync(host, HostA);
        using var forgotPassword = await atForgot.IdentifyAsync(Known);
        using var forgot = await atForgot.ForgotAsync(forgotPassword);
        await flow.Database.ExecuteAsync($"UPDATE connection SET enabled = false WHERE tenant_id = '{flow.TenantA}'");
        var jobs = host.Jobs.Jobs.Count;
        var hash = await HashAsync(flow, user);

        using (var opened = await atPassword.ForgotAsync(password))
        {
            Assert.NotEqual(StepNames.ForgotPassword, SignUpFlow.Name(opened));
        }

        using (var requested = await atForgot.RequestResetAsync(forgot, Known))
        {
            Assert.Equal(StepNames.ForgotPassword, SignUpFlow.Name(requested));
            Assert.Equal(SignUpBrowser.Version(forgot), SignUpBrowser.Version(requested));
        }

        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using (var page = await other.OpenResetLinkAsync(link))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(page));
            Assert.Equal(LinkPurposes.Reset, SignUpFlow.Data(page).GetProperty("purpose").GetString());
        }

        using (var complete = await other.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(complete));
            Assert.Equal(LinkPurposes.Reset, SignUpFlow.Data(complete).GetProperty("purpose").GetString());
        }

        using (var sent = await other.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset' AND used_at IS NULL"));
        // Only the request made before the Connection was disabled reached the confirmation.
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND 'reset_sent' = ANY (completed_steps)"));
    }

    [Fact]
    public async Task Past_the_per_source_limit_a_request_is_429_and_past_the_Tenants_a_new_sources_is_too()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await flow.AddPasswordUserAsync(Known);
        var limits = new PasswordResetLimits(
            new("reset.request.tenant", 5, TimeSpan.FromMinutes(15)), new("reset.request.source", 3, TimeSpan.FromMinutes(15)), SignUpFlow.GenerousReset.Recipient);
        await using var host = await flow.StartHostAsync(resetLimits: limits);

        for (var i = 0; i < 3; i++)
        {
            (await flow.RequestResetAsync(host, HostA, Unknown, source: "198.51.100.7")).Step.Dispose();
        }

        var browser = await flow.BeginAsync(host, HostA, source: "198.51.100.7");
        using var password = await browser.IdentifyAsync(Known);
        using var forgot = await browser.ForgotAsync(password);
        var jobs = host.Jobs.Jobs.Count;
        using (var limited = await browser.Http.PostAsync(
            ProtocolContract.ResetPath, new { stepVersion = SignUpBrowser.Version(forgot), email = Known }, SignUpBrowser.Csrf(forgot)))
        {
            await AssertLimitedAsync(limited);
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(0L, await flow.RowsAsync("one_time_token"));

        // Two more sources take the Tenant to 5; a sixth source is refused as well.
        (await flow.RequestResetAsync(host, HostA, Unknown, source: "198.51.100.8")).Step.Dispose();
        (await flow.RequestResetAsync(host, HostA, Unknown, source: "198.51.100.9")).Step.Dispose();
        var fresh = await flow.BeginAsync(host, HostA, source: "198.51.100.10");
        using var freshPassword = await fresh.IdentifyAsync(Known);
        using var freshForgot = await fresh.ForgotAsync(freshPassword);
        using var tenantLimited = await fresh.Http.PostAsync(
            ProtocolContract.ResetPath, new { stepVersion = SignUpBrowser.Version(freshForgot), email = Known }, SignUpBrowser.Csrf(freshForgot));
        await AssertLimitedAsync(tenantLimited);

        Assert.Equal(10, PasswordResetLimits.Default.Source.Limit);
        Assert.Equal(600, PasswordResetLimits.Default.Tenant.Limit);
        Assert.Equal(TimeSpan.FromMinutes(15), PasswordResetLimits.Default.Source.Window);
    }

    /// <summary>
    /// The "reset link" artifact (Story 1.31): Tenant A's reset link at Tenant B's host is refused by its prefix before any
    /// lookup, as an unknown link is, for the page, Reset password and Send a new link, changing nothing at either Tenant;
    /// the same link still works at A.
    /// </summary>
    [Fact]
    public async Task Tenant_As_reset_link_presented_at_Tenant_B_is_link_expired_and_refused_before_any_lookup()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var rowsA = await flow.Database.ScalarAsync<string>(
            $"SELECT string_agg(to_jsonb(t)::text, ';') FROM one_time_token t WHERE tenant_id = '{flow.TenantA}'");
        var hash = await HashAsync(flow, user);
        var eventsB = await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.Flow.B.TenantId}'");
        var jobs = host.Jobs.Jobs.Count;

        var atB = new SignUpBrowser(new HostedBrowser(host, HostB), Pkce.New());
        using (var page = await atB.OpenResetLinkAsync(link))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(page));
            Assert.Equal(ProtocolDatabase.TestTenantName, SignUpFlow.Data(page).GetProperty("tenant").GetString());
        }

        using (var complete = await atB.CompleteResetAsync(link, NewPassword))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(complete));
        }

        using (var sent = await atB.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
            Assert.False(SignUpFlow.Data(sent).GetProperty("back").GetBoolean());
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(rowsA, await flow.Database.ScalarAsync<string>(
            $"SELECT string_agg(to_jsonb(t)::text, ';') FROM one_time_token t WHERE tenant_id = '{flow.TenantA}'"));
        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(eventsB, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.Flow.B.TenantId}'"));
        Assert.Equal(0L, await flow.CountAsync($"SELECT count(*) FROM one_time_token WHERE tenant_id = '{flow.Flow.B.TenantId}'"));

        using var atA = await new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New()).OpenResetLinkAsync(link);
        Assert.Equal(StepNames.ResetPassword, SignUpFlow.Name(atA));
    }

    [Fact]
    public async Task Send_a_new_link_from_an_expired_reset_link_sends_one_only_while_the_User_holds_a_password()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        await flow.Database.ExecuteAsync($"UPDATE one_time_token SET expires_at = now() - interval '1 minute' WHERE tenant_id = '{flow.TenantA}'");
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        using var expired = await browser.OpenResetLinkAsync(link);
        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(expired));
        using (var sent = await browser.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpBrowser.Csrf(expired)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
            Assert.False(SignUpFlow.Data(sent).GetProperty("back").GetBoolean());
        }

        var links = host.Jobs.ResetLinksFor(user);
        Assert.Equal(2, links.Count);
        using (var fresh = await browser.OpenResetLinkAsync(links[1]))
        {
            Assert.Equal(StepNames.ResetPassword, SignUpFlow.Name(fresh));
        }

        // With no active password any more, the same answer and nothing sent.
        await flow.Database.ExecuteAsync(
            $"UPDATE password_credential SET status = 'pending' WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}'");
        using (var none = await browser.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(none));
        }

        Assert.Equal(2, host.Jobs.ResetLinksFor(user).Count);

        // A verification link's CSRF token never posts a reset.
        using var wrong = await browser.Http.PostAsync(ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.LinkCsrf(link));
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);
    }

    [Theory]
    [InlineData("no-csrf", null, "csrf_mismatch")]
    [InlineData("right", "https://evil.reset-password.test", "origin_mismatch")]
    public async Task A_reset_request_without_its_CSRF_token_or_with_a_wrong_Origin_is_refused_with_403(string csrf, string? origin, string code)
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync();
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);
        var jobs = host.Jobs.Jobs.Count;
        var hash = await HashAsync(flow, user);

        var requests = new (string Path, object Body, string Right)[]
        {
            (ProtocolContract.ResetOpenPath, new { stepVersion = SignUpBrowser.Version(password) }, SignUpBrowser.Csrf(password)),
            (ProtocolContract.ResetPath, new { stepVersion = SignUpBrowser.Version(password), email = Known }, SignUpBrowser.Csrf(password)),
            (ProtocolContract.ResetBackPath, new { stepVersion = SignUpBrowser.Version(password) }, SignUpBrowser.Csrf(password)),
            (ProtocolContract.ResetCompletePath, new { token = link, password = NewPassword, confirm = NewPassword }, SignUpFlow.ResetCsrf(link)),
            (ProtocolContract.ResetNewLinkPath, new { token = link }, SignUpFlow.ResetCsrf(link)),
        };
        foreach (var (path, body, right) in requests)
        {
            using var refused = await browser.Http.PostAsync(path, body, csrf == "right" ? right : null, origin);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            using var step = await HostedBrowser.StepAsync(refused);
            Assert.Equal(code, SignUpFlow.Data(step).GetProperty("code").GetString());
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM signin_transaction WHERE tenant_id = '{flow.TenantA}' AND completed_steps = ARRAY['identifier']::text[]"));
    }

    [Fact]
    public async Task With_the_hashing_budget_full_Reset_password_is_temporarily_unavailable_and_writes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        var (user, _) = await flow.AddPasswordUserAsync(Known);
        await using var host = await flow.StartHostAsync(
            hashLimits: new Gatekeep.Modules.Authentication.Contracts.PasswordHashLimits(concurrency: 0, tenantShare: 0, wait: TimeSpan.Zero));
        (await flow.RequestResetAsync(host, HostA, Known)).Step.Dispose();
        var link = Assert.Single(host.Jobs.ResetLinksFor(user));
        var hash = await HashAsync(flow, user);

        using var refused = await new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New()).CompleteResetAsync(link, NewPassword);

        Assert.Equal(StepNames.GenericError, SignUpFlow.Name(refused));
        Assert.Equal("temporarily_unavailable", SignUpFlow.Data(refused).GetProperty("code").GetString());
        Assert.Equal(hash, await HashAsync(flow, user));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "purpose = 'password_reset' AND used_at IS NULL"));
        Assert.Equal(0L, await flow.EventsAsync(ResetEvent));
    }

    /// <summary>How many Transit encryptions one "Send reset link" for <paramref name="email"/> runs, in a fresh browser.</summary>
    private static async Task<int> EncryptionsOfOneRequestAsync(SignUpFlow flow, ProtocolHost host, string email)
    {
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(email);
        using var forgot = await browser.ForgotAsync(password);
        var before = host.Custody.Calls(KeyOperation.Encrypt);
        using var sent = await browser.RequestResetAsync(forgot, email);
        Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        return host.Custody.Calls(KeyOperation.Encrypt) - before;
    }

    /// <summary>A User of Tenant A with <paramref name="email"/> holding only a pending password, as an unverified sign-up leaves one.</summary>
    private static Task AddPendingUserAsync(SignUpFlow flow, string email) =>
        flow.Database.ExecuteAsync(
            $"WITH u AS (INSERT INTO \"user\" (tenant_id, id, email) VALUES ('{flow.TenantA}', gen_random_uuid(), '{email}') RETURNING id) "
            + "INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) "
            + $"SELECT '{flow.TenantA}', gen_random_uuid(), u.id, c.id, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', 'pending' FROM u, connection c WHERE c.tenant_id = '{flow.TenantA}'");

    /// <summary>The User's active password hash.</summary>
    private static Task<string> HashAsync(SignUpFlow flow, Guid user) =>
        flow.Database.ScalarAsync<string>(
            $"SELECT password_hash FROM password_credential WHERE tenant_id = '{flow.TenantA}' AND user_id = '{user}' AND status = 'active'");

    /// <summary>A password sign-in of <see cref="Known"/> in a fresh browser, through to its code's exchange, which makes its Token Family.</summary>
    private static async Task SignInWithFamilyAsync(SignUpFlow flow, ProtocolHost host)
    {
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(Known);
        using var redirect = await browser.LogInAsync(password, SignUpFlow.Password);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(redirect));
        using var resumed = await browser.FollowAsync(SignUpFlow.Data(redirect).GetProperty("location").GetString()!);
        Assert.Equal(HttpStatusCode.Found, resumed.StatusCode);
        var code = QueryHelpers.ParseQuery(resumed.Headers.Location!.Query)["code"].ToString();
        using var issued = await CodeFlow.ExchangeAsync(
            host, HostA, flow.Flow.ClientA.ClientId, flow.Flow.ClientA.Secret, code, CodeFlowSetup.Callback, browser.Pkce.Verifier);
        Assert.Equal(HttpStatusCode.OK, issued.Status);
    }

    /// <summary>A fresh browser's reset request for <paramref name="email"/>, only the request itself timed.</summary>
    private static async Task<TimeSpan> TimedRequestAsync(SignUpFlow flow, ProtocolHost host, string email)
    {
        var browser = await flow.BeginAsync(host, HostA);
        using var password = await browser.IdentifyAsync(email);
        using var forgot = await browser.ForgotAsync(password);
        var watch = Stopwatch.StartNew();
        using var sent = await browser.RequestResetAsync(forgot, email);
        watch.Stop();
        Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        return watch.Elapsed;
    }

    private static TimeSpan Median(List<TimeSpan> times)
    {
        var sorted = times.Order().ToList();
        return sorted.Count % 2 == 1 ? sorted[sorted.Count / 2] : (sorted[(sorted.Count / 2) - 1] + sorted[sorted.Count / 2]) / 2;
    }

    /// <summary>The step as JSON with what differs by transaction by design set aside: its version, life and CSRF token.</summary>
    private static string Comparable(JsonDocument step)
    {
        var node = JsonNode.Parse(step.RootElement.GetRawText())!.AsObject();
        node["stepVersion"] = 0;
        node["expiresInSeconds"] = 0;
        node["csrfToken"] = "csrf";
        return node.ToJsonString();
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
