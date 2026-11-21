using System.Net;
using System.Text.Json;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Xunit;

namespace Gatekeep.Tests.Isolation.Identity;

/// <summary>
/// Story 4.7 (FR-17, NFR-3): verification links, at the HTTP level, through the real Hosted Login surface, PostgreSQL as
/// <c>gk_hosted</c> and OpenBao. A link works once, is stored only as its SHA-256, and its use activates the password it
/// was sent for and removes every other pending one; a Session starts only in the browser that signed up, or from its
/// "I've verified — continue" once the email is verified. One test or more per verification row of the I/O matrix, and the
/// cross-Tenant case of the "verification link" artifact.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class EmailVerificationTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.verify.test";
    private const string HostB = "beta.verify.test";
    private const string Email = "new.user@example.com";

    [Fact]
    public async Task The_link_in_the_browser_that_signed_up_verifies_starts_the_Session_and_continues_to_the_Application()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        using var verify = verifyStep;
        var user = await flow.UserAsync(Email);
        var link = Assert.Single(host.Jobs.LinksFor(user));

        using var verified = await browser.OpenLinkAsync(link);

        Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(verified));
        Assert.Equal(EmailVerifiedContinuations.App, SignUpFlow.Data(verified).GetProperty("continueTo").GetString());
        Assert.Contains(browser.Http.SetCookies, c => c.StartsWith(ProtocolContract.SessionCookie + "=", StringComparison.Ordinal));
        Assert.Equal(1L, await flow.RowsAsync("user", $"id = '{user}' AND email_verified_at IS NOT NULL"));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND status = 'active'"));
        Assert.Equal(1L, await flow.RowsAsync("password_history", $"user_id = '{user}'"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"user_id = '{user}' AND used_at IS NOT NULL"));
        Assert.Equal(1L, await flow.RowsAsync("user_session", $"user_id = '{user}' AND amr = ARRAY['pwd']"));
        Assert.Equal(1L, await flow.CountAsync(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.TenantA}' AND type_code = 'identity.user.email_verified' AND target_kind = 'user' AND target_id = '{user}'"));

        // Continue is a top-level GET back to the authorization request, which issues the code.
        using var resumed = await browser.FollowAsync(SignUpFlow.Data(verified).GetProperty("location").GetString()!);
        Assert.Equal(HttpStatusCode.Found, resumed.StatusCode);
        Assert.StartsWith(CodeFlowSetup.Callback, resumed.Headers.Location!.OriginalString, StringComparison.Ordinal);
        Assert.Contains("code=", resumed.Headers.Location!.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task After_the_link_in_the_same_browser_the_first_tabs_I_have_verified_gets_the_redirect()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        using var verify = verifyStep;
        var link = Assert.Single(host.Jobs.LinksFor(await flow.UserAsync(Email)));
        using (var verified = await browser.OpenLinkAsync(link))
        {
            Assert.Equal(EmailVerifiedContinuations.App, SignUpFlow.Data(verified).GetProperty("continueTo").GetString());
        }

        // Its step version is stale now: the current step, the redirect, and no second Session.
        using var stale = await browser.ContinueAsync(verify);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(stale));
        Assert.Equal(1L, await flow.RowsAsync("user_session"));
    }

    [Fact]
    public async Task The_link_in_another_browser_verifies_without_a_Session_and_the_first_browser_then_continues()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        using var verify = verifyStep;
        var link = Assert.Single(host.Jobs.LinksFor(await flow.UserAsync(Email)));

        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using var verified = await other.OpenLinkAsync(link);

        Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(verified));
        Assert.Equal(EmailVerifiedContinuations.Close, SignUpFlow.Data(verified).GetProperty("continueTo").GetString());
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(verified).GetProperty("location").ValueKind);
        Assert.Empty(other.Http.SetCookies);
        Assert.Equal(0L, await flow.RowsAsync("user_session"));

        using var continued = await browser.ContinueAsync(verify);
        Assert.Equal(StepNames.Redirect, SignUpFlow.Name(continued));
        Assert.Contains(browser.Http.SetCookies, c => c.StartsWith(ProtocolContract.SessionCookie + "=", StringComparison.Ordinal));
        Assert.Equal(1L, await flow.RowsAsync("user_session"));
    }

    [Fact]
    public async Task I_have_verified_before_the_link_is_used_is_not_verified_yet_and_changes_nothing()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        using var verify = verifyStep;

        using var early = await browser.ContinueAsync(verify);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(early));
        Assert.Equal(VerifyEmailErrors.NotVerifiedYet, SignUpFlow.Data(early).GetProperty("error").GetString());
        Assert.Equal(SignUpBrowser.Version(verify), SignUpBrowser.Version(early));
        Assert.Equal(0L, await flow.RowsAsync("user_session"));
        Assert.Equal(1L, await flow.RowsAsync("user", "email_verified_at IS NULL"));
    }

    [Fact]
    public async Task A_link_works_once_and_a_second_use_is_link_expired_with_nothing_changed()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (_, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        verifyStep.Dispose();
        var link = Assert.Single(host.Jobs.LinksFor(await flow.UserAsync(Email)));
        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        using (var first = await other.OpenLinkAsync(link))
        {
            Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(first));
        }

        var state = await StateAsync(flow);
        using var second = await other.OpenLinkAsync(link);

        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(second));
        Assert.Equal(state, await StateAsync(flow));
        Assert.Equal(1L, await flow.EventsAsync("identity.user.email_verified"));
        // The page keeps its own link for "Send a new link", with the link-bound CSRF token.
        Assert.True(SignUpFlow.Data(second).GetProperty("token").GetString() == link, "The page didn't keep its link.");
        Assert.True(SignUpBrowser.Csrf(second) == SignUpFlow.LinkCsrf(link), "The CSRF token isn't the link-bound one.");
    }

    [Fact]
    public async Task An_expired_link_is_link_expired()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (_, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        verifyStep.Dispose();
        var link = Assert.Single(host.Jobs.LinksFor(await flow.UserAsync(Email)));
        Assert.Equal(
            1L,
            await flow.RowsAsync("one_time_token", "expires_at BETWEEN created_at + interval '23 hours 59 minutes' AND created_at + interval '24 hours'"));
        await flow.Database.BackdateAsync($"UPDATE one_time_token SET expires_at = now() - interval '1 second' WHERE tenant_id = '{flow.TenantA}'");

        using var expired = await new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New()).OpenLinkAsync(link);

        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(expired));
        Assert.Equal(1L, await flow.RowsAsync("user", "email_verified_at IS NULL"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", "used_at IS NULL"));
    }

    [Fact]
    public async Task A_malformed_or_unknown_link_is_link_expired()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        var prefix = Gatekeep.Kernel.Identifiers.PublicId.Format(Gatekeep.Kernel.Identifiers.PublicIdType.Tenant, flow.TenantA);

        foreach (var token in new[] { "nope", prefix + ".short", prefix + "." + new string('A', 43) })
        {
            using var step = await browser.OpenLinkAsync(token);
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(step));
        }

        using (var none = await browser.Http.GetAsync(ProtocolContract.VerifyEmailPath))
        using (var step = await SignUpFlow.PageStepAsync(none))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(step));
            Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(step).GetProperty("token").ValueKind);
        }

        // A value without a link's shape isn't kept for "Send a new link".
        using var malformed = await browser.OpenLinkAsync("nope");
        Assert.Equal(JsonValueKind.Null, SignUpFlow.Data(malformed).GetProperty("token").ValueKind);
    }

    /// <summary>
    /// The "verification link" artifact (Story 1.31): Tenant A's link at Tenant B's host is refused by its prefix before any
    /// lookup, as an unknown link is, changing nothing at either Tenant; the same link still works at A.
    /// </summary>
    [Fact]
    public async Task Tenant_As_verification_link_presented_at_Tenant_B_is_link_expired_and_refused_before_any_lookup()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (_, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        verifyStep.Dispose();
        var link = Assert.Single(host.Jobs.LinksFor(await flow.UserAsync(Email)));
        var state = await StateAsync(flow);
        var eventsB = await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.Flow.B.TenantId}'");

        var atB = new SignUpBrowser(new HostedBrowser(host, HostB), Pkce.New());
        using (var refused = await atB.OpenLinkAsync(link))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(refused));
            Assert.Equal(ProtocolDatabase.TestTenantName, SignUpFlow.Data(refused).GetProperty("tenant").GetString());
        }

        // "Send a new link" at B with A's link: the same neutral answer, and nothing sent.
        var jobs = host.Jobs.Jobs.Count;
        using (var sent = await atB.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = link }, SignUpFlow.LinkCsrf(link)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        }

        Assert.Equal(jobs, host.Jobs.Jobs.Count);
        Assert.Equal(state, await StateAsync(flow));
        Assert.Equal(eventsB, await flow.CountAsync($"SELECT count(*) FROM audit_event WHERE tenant_id = '{flow.Flow.B.TenantId}'"));
        Assert.Equal(0L, await flow.CountAsync($"SELECT count(*) FROM one_time_token WHERE tenant_id = '{flow.Flow.B.TenantId}'"));

        using var atA = await new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New()).OpenLinkAsync(link);
        Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(atA));
    }

    [Fact]
    public async Task Signing_up_again_unverified_adds_a_second_credential_and_its_link_wins_deleting_the_first()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (first, firstStep) = await flow.SignUpAsync(host, HostA, Email, SignUpFlow.Password);
        using var firstVerify = firstStep;
        var (_, secondStep) = await flow.SignUpAsync(host, HostA, Email, SignUpFlow.OtherPassword);
        secondStep.Dispose();
        var user = await flow.UserAsync(Email);

        Assert.Equal(1L, await flow.RowsAsync("user"));
        Assert.Equal(2L, await flow.RowsAsync("password_credential", $"user_id = '{user}' AND status = 'pending'"));
        Assert.Equal(2L, await flow.RowsAsync("one_time_token", $"user_id = '{user}'"));
        Assert.Equal(2L, await flow.EventsAsync("identity.user.signed_up"));
        var links = host.Jobs.LinksFor(user);
        Assert.Equal(2, links.Count);
        var secondCredential = await flow.Database.ScalarAsync<Guid>(
            $"SELECT credential_id FROM one_time_token WHERE tenant_id = '{flow.TenantA}' AND token_hash = '\\x{SignUpFlow.HashHex(links[1])}'");

        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using (var verified = await other.OpenLinkAsync(links[1]))
        {
            Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(verified));
        }

        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}'"));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"id = '{secondCredential}' AND status = 'active'"));
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"user_id = '{user}'"));
        using (var firstLink = await other.OpenLinkAsync(links[0]))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(firstLink));
        }

        // The first sign-up's credential is gone, so its browser's "I've verified" never signs it in.
        using var continued = await first.ContinueAsync(firstVerify);
        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(continued));
        Assert.Equal(VerifyEmailErrors.NotVerifiedYet, SignUpFlow.Data(continued).GetProperty("error").GetString());
        Assert.Equal(0L, await flow.RowsAsync("user_session"));
    }

    [Fact]
    public async Task Resend_replaces_the_unused_link_and_emails_again()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (browser, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        using var verify = verifyStep;
        var user = await flow.UserAsync(Email);

        using var resent = await browser.ResendAsync(verify);

        Assert.Equal(StepNames.VerifyEmail, SignUpFlow.Name(resent));
        Assert.True(SignUpFlow.Data(resent).GetProperty("resent").GetBoolean());
        var links = host.Jobs.LinksFor(user);
        Assert.Equal(2, links.Count);
        Assert.Equal(2L, await flow.EmailJobsAsync());
        Assert.Equal(1L, await flow.RowsAsync("one_time_token", $"user_id = '{user}'"));
        Assert.Equal(1L, await flow.RowsAsync("password_credential", $"user_id = '{user}'"));

        var other = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());
        using (var old = await other.OpenLinkAsync(links[0]))
        {
            Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(old));
        }

        using var fresh = await other.OpenLinkAsync(links[1]);
        Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(fresh));
    }

    [Fact]
    public async Task Send_a_new_link_is_neutral_and_emails_only_while_the_User_is_unverified()
    {
        var flow = await SignUpFlow.CreateAsync(postgres, bao, HostA, HostB);
        await using var host = await flow.StartHostAsync();
        var (_, verifyStep) = await flow.SignUpAsync(host, HostA, Email);
        verifyStep.Dispose();
        var user = await flow.UserAsync(Email);
        var link = Assert.Single(host.Jobs.LinksFor(user));
        await flow.Database.BackdateAsync($"UPDATE one_time_token SET expires_at = now() - interval '1 second' WHERE tenant_id = '{flow.TenantA}'");
        var browser = new SignUpBrowser(new HostedBrowser(host, HostA), Pkce.New());

        using var expired = await browser.OpenLinkAsync(link);
        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(expired));
        using (var sent = await browser.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = link }, SignUpBrowser.Csrf(expired)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(sent));
        }

        var links = host.Jobs.LinksFor(user);
        Assert.Equal(2, links.Count);
        using (var verified = await browser.OpenLinkAsync(links[1]))
        {
            Assert.Equal(StepNames.EmailVerified, SignUpFlow.Name(verified));
        }

        // Now verified: the used link's page offers a new link, which answers the same and sends nothing.
        using var used = await browser.OpenLinkAsync(links[1]);
        Assert.Equal(StepNames.LinkExpired, SignUpFlow.Name(used));
        using (var neutral = await browser.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = links[1] }, SignUpBrowser.Csrf(used)))
        {
            Assert.Equal(StepNames.LinkSent, SignUpFlow.Name(neutral));
        }

        Assert.Equal(2, host.Jobs.LinksFor(user).Count);

        // A link CSRF token for another link is refused.
        using var forged = await browser.Http.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = links[1] }, SignUpFlow.LinkCsrf(link));
        Assert.Equal(HttpStatusCode.Forbidden, forged.StatusCode);
    }

    /// <summary>Tenant A's Users, credentials, links and Sessions, as text: equal only when none changed.</summary>
    private static Task<string> StateAsync(SignUpFlow flow) =>
        flow.Database.ScalarAsync<string>(
            "SELECT coalesce(string_agg(r, ';' ORDER BY r), '') FROM ("
            + $"SELECT to_jsonb(u)::text AS r FROM \"user\" u WHERE tenant_id = '{flow.TenantA}' "
            + $"UNION ALL SELECT to_jsonb(c)::text FROM password_credential c WHERE tenant_id = '{flow.TenantA}' "
            + $"UNION ALL SELECT to_jsonb(t)::text FROM one_time_token t WHERE tenant_id = '{flow.TenantA}' "
            + $"UNION ALL SELECT to_jsonb(s)::text FROM user_session s WHERE tenant_id = '{flow.TenantA}') rows");
}
