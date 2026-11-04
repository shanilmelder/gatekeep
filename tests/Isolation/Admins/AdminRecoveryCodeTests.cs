using System.Net;
using System.Text.Json;
using Xunit;
using static Gatekeep.Tests.Isolation.Admins.FreshAssertionTests;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.26: Admin Recovery Codes on the real <c>Host.Admin</c> and PostgreSQL, with the OpenBao
/// stand-in computing the Deployment HMAC. Offered only to a seeded Admin who isn't the Deployment
/// Owner, in a setup Session with one credential; issued once and stored only as its HMAC; usable
/// once confirmed, once, for a recovery Session that reaches only credential registration; and
/// counted per client before the code is read.
/// </summary>
public sealed class AdminRecoveryCodeTests(PostgresFixture postgres)
{
    private const string SessionPath = "/api/v1/deployment/session";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_choice_is_offered_only_to_a_non_Owner_with_one_credential_in_setup()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (owner, ownerCsrf, _) = await host.ClaimedAsync();
        using var ownerKey = new SoftwareAuthenticator();
        await host.RegisterAsync(owner, ownerCsrf, ownerKey);
        var (cookie, csrf, _) = await host.InsertSetupAdminAsync();

        Assert.False((await SessionAsync(host, cookie)).GetProperty("recoveryCodeAllowed").GetBoolean());
        using var key = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, key);
        Assert.True((await SessionAsync(host, cookie)).GetProperty("recoveryCodeAllowed").GetBoolean());

        // The Deployment Owner registers two credentials (FR-2): the choice is never theirs.
        Assert.False((await SessionAsync(host, owner)).GetProperty("recoveryCodeAllowed").GetBoolean());
        using var refused = await host.SendAsync(HttpMethod.Post, AdminHost.RecoveryCodePath, owner, ownerCsrf, AdminHost.Origin);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Empty(await refused.Content.ReadAsByteArrayAsync(Cancellation));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_recovery_code"));
    }

    [Fact]
    public async Task Issue_shows_the_code_once_and_stores_only_its_HMAC_unconfirmed_and_a_reissue_voids_it()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (cookie, csrf, adminId) = await host.InsertSetupAdminAsync();
        using var key = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, key);

        using var issued = await host.SendAsync(HttpMethod.Post, AdminHost.RecoveryCodePath, cookie, csrf, AdminHost.Origin);
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        Assert.Equal("no-store", issued.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await issued.Content.ReadAsStringAsync(Cancellation));
        var code = json.RootElement.GetProperty("code").GetString()!;
        Assert.Matches("^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$", code);
        Assert.Matches("^[0-9a-f-]{36}$", json.RootElement.GetProperty("issueId").GetString());

        Assert.Equal(
            $"{Convert.ToHexStringLower(AdminHost.RecoveryCodeHmac(code.Replace("-", string.Empty, StringComparison.Ordinal)))} 1 t {adminId}",
            await host.ScalarAsync<string>(
                "SELECT encode(code_hmac, 'hex') || ' ' || hmac_key_version || ' ' || (confirmed_at IS NULL)::text::char || ' ' || admin_id FROM admin_recovery_code"));
        Assert.Equal(0L, await CountAsync(host, "admin.recovery_code.issued"));

        // A reload before confirming can't show it again: a new issue replaces it.
        var (second, _) = await host.IssueRecoveryCodeAsync(cookie, csrf);
        Assert.NotEqual(code, second);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_recovery_code"));
        Assert.Equal(
            Convert.ToHexStringLower(AdminHost.RecoveryCodeHmac(second.Replace("-", string.Empty, StringComparison.Ordinal))),
            await host.ScalarAsync<string>("SELECT encode(code_hmac, 'hex') FROM admin_recovery_code"));
    }

    [Fact]
    public async Task Confirm_completes_setup_and_an_unconfirmed_code_can_never_be_redeemed()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (cookie, csrf, adminId) = await host.InsertSetupAdminAsync();
        using var key = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, key);

        using (var nothing = await host.ConfirmRecoveryCodeAsync(cookie, csrf, Guid.CreateVersion7()))
        {
            await AssertProblemAsync(nothing, HttpStatusCode.Conflict, "recovery_code_superseded");
        }

        var (code, issueId) = await host.IssueRecoveryCodeAsync(cookie, csrf);
        using (var unconfirmed = await host.RedeemAsync(code))
        {
            await AssertProblemAsync(unconfirmed, HttpStatusCode.BadRequest, "recovery_code_refused");
        }

        using (var confirmed = await host.ConfirmRecoveryCodeAsync(cookie, csrf, issueId))
        {
            Assert.Equal(HttpStatusCode.NoContent, confirmed.StatusCode);
        }

        var session = await SessionAsync(host, cookie);
        Assert.Equal("full", session.GetProperty("kind").GetString());
        Assert.True(session.GetProperty("setupComplete").GetBoolean());
        Assert.False(session.GetProperty("recoveryCodeAllowed").GetBoolean());
        Assert.Equal(
            "admin.recovery_code.issued,admin.setup.completed",
            await host.ScalarAsync<string>(
                $"SELECT string_agg(type_code, ',' ORDER BY occurred_at, id) FROM deployment_audit_event WHERE target_id = '{adminId}' AND type_code IN ('admin.recovery_code.issued', 'admin.setup.completed')"));

        // Full now: Your credentials lists the code.
        Assert.True((await host.CredentialsAsync(cookie)).GetProperty("recoveryCode").GetBoolean());
    }

    [Fact]
    public async Task Redeem_normalizes_ends_every_Session_and_starts_a_recovery_Session_once()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (cookie, _, adminId, _, key) = await host.AdminWithRecoveryCodeAsync();
        using (key)
        {
            // A known code, so the input can use every normalization: lowercase, no hyphen, a space, O for 0 and L for 1.
            await PostgresFixture.ExecuteAsync(
                host.Superuser,
                $"UPDATE admin_recovery_code SET code_hmac = '\\x{Convert.ToHexStringLower(AdminHost.RecoveryCodeHmac("01ABCDEFGHJKMNPQ"))}'");

            using var redeemed = await host.RedeemAsync("olab cdef ghjk mnpq");

            Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
            var recovery = AdminHost.CookieValue(redeemed, AdminHost.Cookie)!;
            using (var json = JsonDocument.Parse(await redeemed.Content.ReadAsStringAsync(Cancellation)))
            {
                Assert.False(json.RootElement.GetProperty("setupComplete").GetBoolean());
                Assert.Equal(adminId, json.RootElement.GetProperty("adminId").GetGuid());
            }

            Assert.Equal("recovery", (await SessionAsync(host, recovery)).GetProperty("kind").GetString());
            using (var old = await host.SendAsync(HttpMethod.Get, SessionPath, cookie))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
            }

            Assert.Equal("revoked", await host.ScalarAsync<string>(
                $"SELECT end_reason FROM admin_session WHERE admin_id = '{adminId}' AND kind <> 'recovery'"));
            Assert.Equal(1L, await CountAsync(host, "admin.session.revoked"));
            Assert.Equal(1L, await CountAsync(host, "admin.recovery_code.used"));
            Assert.True(await host.ScalarAsync<bool>("SELECT used_at IS NOT NULL FROM admin_recovery_code"));

            using var again = await host.RedeemAsync("01AB-CDEF-GHJK-MNPQ");
            await AssertProblemAsync(again, HttpStatusCode.BadRequest, "recovery_code_refused");
        }
    }

    [Theory]
    [InlineData("""{"code":"ZZZZ-ZZZZ-ZZZZ-ZZZZ"}""")]
    [InlineData("""{"code":"ZZZZ-ZZZZ"}""")]
    [InlineData("""{"code":"UUUU-UUUU"}""")]
    [InlineData("""{"code":"0123"}""")]
    [InlineData("""{"other":1}""")]
    [InlineData("not json")]
    public async Task Wrong_or_malformed_codes_are_the_same_400_and_change_nothing(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, _, _, key) = await host.AdminWithRecoveryCodeAsync();
        key.Dispose();
        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");

        using var refused = await host.SendAsync(HttpMethod.Post, AdminHost.RedeemPath, origin: AdminHost.Origin, body: body);

        await AssertProblemAsync(refused, HttpStatusCode.BadRequest, "recovery_code_refused");
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        Assert.True(await host.ScalarAsync<bool>("SELECT used_at IS NULL FROM admin_recovery_code"));
        Assert.Null(AdminHost.CookieValue(refused, AdminHost.Cookie));
    }

    [Fact]
    public async Task A_recovery_Session_reaches_only_registration_which_makes_it_full()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, adminId, code, key) = await host.AdminWithRecoveryCodeAsync();
        key.Dispose();
        using var redeemed = await host.RedeemAsync(code);
        var recovery = AdminHost.CookieValue(redeemed, AdminHost.Cookie)!;
        var csrf = AdminHost.Csrf(recovery);

        foreach (var (method, path) in new[]
        {
            (HttpMethod.Get, "/api/v1/deployment/capabilities"),
            (HttpMethod.Get, AdminHost.CredentialsPath),
            (HttpMethod.Post, AdminHost.RecoveryCodePath),
            (HttpMethod.Post, AdminHost.AssertionsPath),
        })
        {
            using var refused = await host.SendAsync(method, path, recovery, csrf, AdminHost.Origin);
            Assert.True(refused.StatusCode == HttpStatusCode.Forbidden, $"{method} {path} answered {(int)refused.StatusCode}.");
            Assert.Empty(await refused.Content.ReadAsByteArrayAsync(Cancellation));
        }

        var setupCompleted = await CountAsync(host, "admin.setup.completed");
        using var replacement = new SoftwareAuthenticator();
        var registered = await host.RegisterAsync(recovery, csrf, replacement);

        Assert.True(registered.GetProperty("setupComplete").GetBoolean());
        Assert.Equal("full", (await SessionAsync(host, recovery)).GetProperty("kind").GetString());
        Assert.Equal(setupCompleted + 1, await CountAsync(host, "admin.setup.completed"));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM admin_credential WHERE admin_id = '{adminId}'"));

        // Full now, so the next add is a fresh assertion's.
        var (next, _) = await host.BeginRegistrationAsync(recovery, csrf);
        using (next)
        {
            await AssertProblemAsync(next, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }
    }

    [Fact]
    public async Task Sixth_redeem_from_one_client_in_15_minutes_is_429_before_the_code_is_read()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, _, code, key) = await host.AdminWithRecoveryCodeAsync();
        key.Dispose();

        for (var i = 0; i < 5; i++)
        {
            using var wrong = await host.RedeemAsync("ZZZZ-ZZZZ-ZZZZ-ZZZZ");
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        // Even the right code is refused now, and stays unused.
        using var limited = await host.RedeemAsync(code);
        await AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.True(int.Parse(limited.Headers.GetValues("Retry-After").Single(), System.Globalization.CultureInfo.InvariantCulture) >= 1);
        Assert.True(await host.ScalarAsync<bool>("SELECT used_at IS NULL FROM admin_recovery_code"));
        Assert.Equal(6, await host.ScalarAsync<int>("SELECT attempts FROM admin_attempt WHERE policy = 'admins.recovery_code.redeem'"));
    }

    [Fact]
    public async Task Before_bootstrap_completes_redeem_is_the_unknown_path_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.IssueTokenAsync();

        using var missing = await host.RedeemAsync("0123-ABCD");

        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Empty(await missing.Content.ReadAsByteArrayAsync(Cancellation));
    }

    [Fact]
    public async Task A_custody_failure_is_503_with_nothing_stored_or_used()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, _, code, key) = await host.AdminWithRecoveryCodeAsync();
        key.Dispose();
        var (cookie, csrf, _) = await host.InsertSetupAdminAsync();
        using var other = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, other);

        host.OpenBao.RespondToBody = (path, body) => path.Contains("/transit/", StringComparison.Ordinal) ? (503, "{}") : AdminHost.Custody(path, body);

        using (var issue = await host.SendAsync(HttpMethod.Post, AdminHost.RecoveryCodePath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, issue.StatusCode);
        }

        using (var redeem = await host.RedeemAsync(code))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, redeem.StatusCode);
            Assert.Null(AdminHost.CookieValue(redeem, AdminHost.Cookie));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_recovery_code"));
        Assert.True(await host.ScalarAsync<bool>("SELECT used_at IS NULL FROM admin_recovery_code"));
    }

    [Fact]
    public async Task Confirming_a_replaced_issue_is_409_and_leaves_the_newer_code_unconfirmed()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (cookie, csrf, _) = await host.InsertSetupAdminAsync();
        using var key = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, key);

        var (_, first) = await host.IssueRecoveryCodeAsync(cookie, csrf);
        var (second, secondIssue) = await host.IssueRecoveryCodeAsync(cookie, csrf);

        using (var stale = await host.ConfirmRecoveryCodeAsync(cookie, csrf, first))
        {
            await AssertProblemAsync(stale, HttpStatusCode.Conflict, "recovery_code_superseded");
        }

        Assert.Equal(
            $"{secondIssue} t",
            await host.ScalarAsync<string>("SELECT id || ' ' || (confirmed_at IS NULL)::text::char FROM admin_recovery_code"));
        Assert.Equal("setup", (await SessionAsync(host, cookie)).GetProperty("kind").GetString());
        Assert.Equal(0L, await CountAsync(host, "admin.recovery_code.issued"));

        // The newer one, named by its own issue, confirms.
        using var confirmed = await host.ConfirmRecoveryCodeAsync(cookie, csrf, secondIssue);
        Assert.Equal(HttpStatusCode.NoContent, confirmed.StatusCode);
        Assert.Equal(
            Convert.ToHexStringLower(AdminHost.RecoveryCodeHmac(second.Replace("-", string.Empty, StringComparison.Ordinal))),
            await host.ScalarAsync<string>("SELECT encode(code_hmac, 'hex') FROM admin_recovery_code WHERE confirmed_at IS NOT NULL"));
    }

    [Fact]
    public async Task A_recovery_Session_and_a_setup_Session_can_always_sign_out()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, adminId, code, key) = await host.AdminWithRecoveryCodeAsync();
        key.Dispose();
        using var redeemed = await host.RedeemAsync(code);
        var recovery = AdminHost.CookieValue(redeemed, AdminHost.Cookie)!;

        using (var signOut = await host.SendAsync(HttpMethod.Delete, SessionPath, recovery, AdminHost.Csrf(recovery), AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);
        }

        using (var gone = await host.SendAsync(HttpMethod.Get, SessionPath, recovery))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, gone.StatusCode);
        }

        var (setup, setupCsrf, _) = await host.InsertSetupAdminAsync();
        using (var setupOut = await host.SendAsync(HttpMethod.Delete, SessionPath, setup, setupCsrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.NoContent, setupOut.StatusCode);
        }

        Assert.Equal("signed_out", await host.ScalarAsync<string>($"SELECT end_reason FROM admin_session WHERE admin_id = '{adminId}' AND kind = 'recovery'"));
    }

    [Fact]
    public async Task Registering_in_a_recovery_Session_ends_a_thiefs_Session_signed_in_with_the_old_credential()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, adminId, code, lost) = await host.AdminWithRecoveryCodeAsync();
        using (lost)
        {
            using var redeemed = await host.RedeemAsync(code);
            var recovery = AdminHost.CookieValue(redeemed, AdminHost.Cookie)!;

            // Whoever holds the lost device signs in with it after the redeem.
            var (thief, _) = await host.SignInAsync(lost);
            using (var thiefNow = await host.SendAsync(HttpMethod.Get, SessionPath, thief))
            {
                Assert.Equal(HttpStatusCode.OK, thiefNow.StatusCode);
            }

            var revoked = await CountAsync(host, "admin.session.revoked");
            using var replacement = new SoftwareAuthenticator();
            await host.RegisterAsync(recovery, AdminHost.Csrf(recovery), replacement);

            using (var thiefAfter = await host.SendAsync(HttpMethod.Get, SessionPath, thief))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, thiefAfter.StatusCode);
            }

            Assert.Equal(revoked + 1, await CountAsync(host, "admin.session.revoked"));
            Assert.Equal("full", (await SessionAsync(host, recovery)).GetProperty("kind").GetString());
            Assert.Equal(1L, await host.ScalarAsync<long>(
                $"SELECT count(*) FROM admin_session WHERE admin_id = '{adminId}' AND ended_at IS NULL AND idle_expires_at > now()"));
        }
    }

    [Fact]
    public async Task Past_the_Deployment_wide_limit_every_redeem_is_429_before_its_client_is_counted_or_its_code_read()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var (_, _, _, code, key) = await host.AdminWithRecoveryCodeAsync();
        key.Dispose();

        // 50 redemptions already taken in this window, from anywhere.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "INSERT INTO admin_attempt (policy, subject_hash, window_start, attempts) VALUES ('admins.recovery_code.deployment', sha256(convert_to('deployment', 'UTF8')), now(), 50)");

        using var limited = await host.RedeemAsync(code);

        await AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.True(await host.ScalarAsync<bool>("SELECT used_at IS NULL FROM admin_recovery_code"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt WHERE policy = 'admins.recovery_code.redeem'"));
    }

    private static async Task<JsonElement> SessionAsync(AdminHost host, string cookie)
    {
        using var response = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }
}
