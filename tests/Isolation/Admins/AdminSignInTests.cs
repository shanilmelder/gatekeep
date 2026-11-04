using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.23: Admin sign-in with WebAuthn only, on the real <c>Host.Admin</c> and PostgreSQL,
/// with a software authenticator. Begin's options carry the Admin RP ID, required user
/// verification and no credential, and set a <c>SameSite=Strict</c> <c>__Host-</c> binding cookie;
/// the challenge is stored as its SHA-256 for 5 minutes, bound to the cookie's hash, and deleted by
/// the complete that takes it, whatever follows. A verified assertion advances the counter and
/// starts a full Session storing only its hash, with <c>admin.signin.succeeded</c>, in one
/// transaction. Every refusal is the same 400 <c>signin_refused</c> with no Session. Only one after
/// the signature verified is audited, a counter that doesn't go up as a clone; every other, a bad
/// signature or an unknown credential (a Tenant User's included), is only logged. Before bootstrap both endpoints are the
/// unknown-path 404; a wrong Origin is 403 with nothing written; each begin and complete is
/// counted per client. Sign-out ends the Session with its own event.
/// </summary>
public sealed class AdminSignInTests(PostgresFixture postgres)
{
    private const string RpId = "admin.gatekeep-admin.test";
    private const string SessionPath = "/api/v1/deployment/session";
    private const string CapabilitiesPath = "/api/v1/deployment/capabilities";
    private const string CompletePath = AdminHost.SignInPath + "/complete";
    private const string ClearedBinding = "__Host-gk-admin-signin=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0";
    private const string SignInEvents = "type_code IN ('admin.signin.succeeded', 'admin.signin.failed', 'admin.credential.sign_count_regressed')";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Begin_offers_the_Admin_RP_ID_with_no_credential_and_binds_the_challenge_to_a_cookie()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var first = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(first);

        var (begin, options, binding) = await host.BeginSignInAsync();
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            Assert.Equal("no-store", begin.Headers.CacheControl?.ToString());
            Assert.Equal(
                $"__Host-gk-admin-signin={binding}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300",
                Assert.Single(begin.Headers.GetValues("Set-Cookie")));
        }

        Assert.Equal(["challenge", "rpId", "timeout", "userVerification", "allowCredentials"], options.EnumerateObject().Select(p => p.Name));
        Assert.Equal(RpId, options.GetProperty("rpId").GetString());
        Assert.Equal("required", options.GetProperty("userVerification").GetString());
        Assert.Equal(300000, options.GetProperty("timeout").GetInt64());
        Assert.Empty(options.GetProperty("allowCredentials").EnumerateArray());

        // The challenge and the binding are 32 random bytes each, stored only as their SHA-256s, for 5 minutes.
        var challenge = Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!);
        Assert.Equal(32, challenge.Length);
        Assert.Equal(
            $"{Convert.ToHexStringLower(AdminHost.Hash(binding!))} {Convert.ToHexStringLower(SHA256.HashData(challenge))}",
            await host.ScalarAsync<string>("SELECT encode(binding_hash, 'hex') || ' ' || encode(challenge_sha256, 'hex') FROM admin_signin_challenge"));
        Assert.True(await host.ScalarAsync<bool>("SELECT expires_at - created_at = interval '5 minutes' FROM admin_signin_challenge"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt WHERE policy = 'admins.signin.begin'"));
    }

    [Fact]
    public async Task Valid_assertion_starts_a_full_Session_storing_only_its_hash_in_one_transaction()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        var (_, adminId) = await host.AdminWithCredentialsAsync(first, second);

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, first.Assert(options, AdminHost.Origin));

        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        Assert.Equal("no-store", complete.Headers.CacheControl?.ToString());
        var cookies = complete.Headers.GetValues("Set-Cookie").ToList();
        var cookie = AdminHost.CookieValue(complete, AdminHost.Cookie)!;
        Assert.Equal([$"__Host-gk-admin={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict", ClearedBinding], cookies);

        using var json = JsonDocument.Parse(await complete.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["adminId", "csrfToken", "setupComplete"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(adminId, json.RootElement.GetProperty("adminId").GetGuid());
        Assert.Equal(AdminHost.Csrf(cookie), json.RootElement.GetProperty("csrfToken").GetString());
        Assert.True(json.RootElement.GetProperty("setupComplete").GetBoolean());

        // Only the Session ID's hash, a full Session, 30 minutes idle and 8 hours absolute.
        var hash = Convert.ToHexStringLower(AdminHost.Hash(cookie));
        Assert.Equal(
            "full 00:30:00 08:00:00",
            await host.ScalarAsync<string>(
                $"SELECT kind || ' ' || (idle_expires_at - created_at)::text || ' ' || (absolute_expires_at - created_at)::text FROM admin_session WHERE id_hash = '\\x{hash}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM admin_session WHERE position(convert_to('{cookie}', 'UTF8') IN id_hash) > 0"));

        // The counter advanced, last use stamped, the event written, the challenge gone.
        Assert.Equal(
            "1 true",
            await host.ScalarAsync<string>(
                $"SELECT sign_count || ' ' || (last_used_at IS NOT NULL)::text FROM admin_credential WHERE credential_id = '\\x{Convert.ToHexStringLower(first.CredentialId)}'"));
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.signin.succeeded'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));

        // The Session, the counter and the event: one transaction.
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"""
                SELECT count(DISTINCT x) FROM (
                  SELECT xmin::text AS x FROM admin_session WHERE id_hash = '\x{hash}'
                  UNION ALL SELECT xmin::text FROM admin_credential WHERE credential_id = '\x{Convert.ToHexStringLower(first.CredentialId)}'
                  UNION ALL SELECT xmin::text FROM deployment_audit_event WHERE type_code = 'admin.signin.succeeded'
                ) AS writes
                """));

        // The Session works, and the next sign-in's counter must go on up.
        using var capabilities = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie);
        Assert.Equal(HttpStatusCode.OK, capabilities.StatusCode);
        await host.SignInAsync(second);
        await host.SignInAsync(first);
        Assert.Equal(2L, await host.ScalarAsync<long>(
            $"SELECT sign_count FROM admin_credential WHERE credential_id = '\\x{Convert.ToHexStringLower(first.CredentialId)}'"));
    }

    [Fact]
    public async Task Admin_with_one_credential_gets_a_full_Session_that_reaches_only_setup()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var only = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(only);

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, only.Assert(options, AdminHost.Origin));

        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        using var json = JsonDocument.Parse(await complete.Content.ReadAsStringAsync(Cancellation));
        Assert.False(json.RootElement.GetProperty("setupComplete").GetBoolean());
        var cookie = AdminHost.CookieValue(complete, AdminHost.Cookie)!;
        Assert.Equal("full", await host.ScalarAsync<string>($"SELECT kind FROM admin_session WHERE id_hash = '\\x{Convert.ToHexStringLower(AdminHost.Hash(cookie))}'"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.signin.succeeded'"));

        using var capabilities = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie);
        Assert.Equal(HttpStatusCode.Forbidden, capabilities.StatusCode);
        using var session = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);
        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
    }

    public static TheoryData<string> CeremonyRefusals => [.. Refusals.Keys];

    private static readonly Dictionary<string, AssertionTweaks> Refusals = new()
    {
        { "a bad signature", new AssertionTweaks { OtherKey = true } },
        { "a Tenant hostname's RP ID", new AssertionTweaks { RpId = "acme.gatekeep.test" } },
        { "the parent domain as RP ID", new AssertionTweaks { RpId = "gatekeep.test" } },
        { "another origin", new AssertionTweaks { Origin = "https://acme.gatekeep.test" } },
        { "the origin in other case", new AssertionTweaks { Origin = "https://ADMIN.gatekeep-admin.test" } },
        { "the origin with its default port", new AssertionTweaks { Origin = "https://admin.gatekeep-admin.test:443" } },
        { "the origin over http", new AssertionTweaks { Origin = "http://admin.gatekeep-admin.test" } },
        { "crossOrigin true", new AssertionTweaks { CrossOrigin = true } },
        { "a top origin", new AssertionTweaks { TopOrigin = "https://admin.gatekeep-admin.test" } },
        { "no user verification", new AssertionTweaks { UserVerified = false } },
        { "no user presence", new AssertionTweaks { UserPresent = false } },
        { "a registration's type", new AssertionTweaks { Type = "webauthn.create" } },
        { "another challenge", new AssertionTweaks { Challenge = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)) } },
        { "no user handle", new AssertionTweaks { OmitUserHandle = true } },
        { "another Admin's user handle", new AssertionTweaks { UserHandle = RandomNumberGenerator.GetBytes(64) } },
    };

    [Theory]
    [MemberData(nameof(CeremonyRefusals))]
    public async Task Assertion_the_ceremony_refuses_is_400_with_no_Session_and_is_only_logged(string assertion)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, authenticator.Assert(options, AdminHost.Origin, Refusals[assertion]));

        await AssertRefusedAsync(complete);
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));

        // Refused before the signature verified: nothing proves who sent it, so no event names the Admin.
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
        Assert.Equal(1, await host.ScalarAsync<int>("SELECT attempts FROM admin_attempt WHERE policy = 'admins.signin.complete'"));
        Assert.True(await host.ScalarAsync<bool>("SELECT sign_count = 0 AND last_used_at IS NULL FROM admin_credential"));

        // The challenge went with the refusal: the right assertion can't follow on it.
        using var retry = await host.CompleteSignInAsync(binding, authenticator.Assert(options, AdminHost.Origin));
        await AssertRefusedAsync(retry);
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
    }

    [Fact]
    public async Task Tenant_Users_credential_is_refused_unaudited_as_no_Admin_credential_has_it()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var admin = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(admin);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        // A passkey a Tenant User made for a Tenant hostname, never stored in admin_credential.
        using var tenantUser = new SoftwareAuthenticator { UserHandle = RandomNumberGenerator.GetBytes(64) };
        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using (var tenantRp = await host.CompleteSignInAsync(binding, tenantUser.Assert(options, AdminHost.Origin, new AssertionTweaks { RpId = "acme.gatekeep.test" })))
        {
            await AssertRefusedAsync(tenantRp);
        }

        // Even made for the Admin RP ID, it names no Admin credential.
        (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using (var adminRp = await host.CompleteSignInAsync(binding, tenantUser.Assert(options, AdminHost.Origin)))
        {
            await AssertRefusedAsync(adminRp);
        }

        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
    }

    [Theory]
    [InlineData(7u, 7u)]
    [InlineData(7u, 3u)]
    [InlineData(7u, 0u)]
    public async Task Counter_that_doesnt_advance_past_a_non_zero_one_is_refused_as_a_clone(uint stored, uint asserted)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        var (_, adminId) = await host.AdminWithCredentialsAsync(authenticator);
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE admin_credential SET sign_count = {stored}");
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, authenticator.Assert(options, AdminHost.Origin, new AssertionTweaks { SignCount = asserted }));

        await AssertRefusedAsync(complete);
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal((long)stored, await host.ScalarAsync<long>("SELECT sign_count FROM admin_credential"));
        Assert.Equal(
            $"admin.credential.sign_count_regressed anonymous admin {adminId}",
            await host.ScalarAsync<string>(
                $"SELECT type_code || ' ' || actor_kind || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE {SignInEvents}"));
    }

    [Fact]
    public async Task Authenticator_that_keeps_no_counter_signs_in_with_0_after_0()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, authenticator.Assert(options, AdminHost.Origin, new AssertionTweaks { SignCount = 0 }));

        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        Assert.True(await host.ScalarAsync<bool>("SELECT sign_count = 0 AND last_used_at IS NOT NULL FROM admin_credential"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.signin.succeeded'"));
    }

    [Fact]
    public async Task Complete_with_no_binding_an_unknown_one_or_an_expired_one_is_refused_and_clears_the_cookie()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        var body = authenticator.Assert(options, AdminHost.Origin);

        foreach (var sent in new[] { null, AdminHost.Unissued(), "not-a-binding" })
        {
            using var refused = await host.CompleteSignInAsync(sent, body);
            await AssertRefusedAsync(refused);
            Assert.Equal(ClearedBinding, Assert.Single(refused.Headers.GetValues("Set-Cookie")));
        }

        // None of those touched the pending challenge; now it expires, and its binding answers nothing.
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "UPDATE admin_signin_challenge SET created_at = now() - interval '6 minutes', expires_at = now() - interval '1 minute'");
        using (var expired = await host.CompleteSignInAsync(binding, body))
        {
            await AssertRefusedAsync(expired);
            Assert.Equal(ClearedBinding, Assert.Single(expired.Headers.GetValues("Set-Cookie")));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
    }

    [Fact]
    public async Task Replayed_assertion_and_cookie_are_refused()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        var body = authenticator.Assert(options, AdminHost.Origin);
        using (var accepted = await host.CompleteSignInAsync(binding, body))
        {
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        }

        using var replayed = await host.CompleteSignInAsync(binding, body);

        await AssertRefusedAsync(replayed);
        Assert.Equal(sessions + 1, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.signin.succeeded'"));
    }

    [Fact]
    public async Task New_begin_with_the_same_cookie_replaces_the_pending_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);

        var (first, earlier, firstBinding) = await host.BeginSignInAsync();
        first.Dispose();
        var (second, later, secondBinding) = await host.BeginSignInAsync(firstBinding);
        second.Dispose();

        Assert.NotEqual(firstBinding, secondBinding);
        Assert.NotEqual(earlier.GetProperty("challenge").GetString(), later.GetProperty("challenge").GetString());
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));

        using (var stale = await host.CompleteSignInAsync(firstBinding, authenticator.Assert(earlier, AdminHost.Origin)))
        {
            await AssertRefusedAsync(stale);
        }

        using var current = await host.CompleteSignInAsync(secondBinding, authenticator.Assert(later, AdminHost.Origin));
        Assert.Equal(HttpStatusCode.OK, current.StatusCode);
    }

    [Fact]
    public async Task Begin_sweeps_expired_challenges()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            """
            INSERT INTO admin_signin_challenge (id, binding_hash, challenge_sha256, created_at, expires_at)
            SELECT gen_random_uuid(), sha256(n::text::bytea), sha256(n::text::bytea), clock_timestamp() - interval '10 minutes', clock_timestamp() - interval '6 minutes'
            FROM generate_series(1, 3) AS n
            """);

        var (begin, _, _) = await host.BeginSignInAsync();
        begin.Dispose();

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));
    }

    [Fact]
    public async Task Signing_in_while_signed_in_supersedes_the_Session_the_browser_held()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        using var other = new SoftwareAuthenticator();
        var (_, adminId) = await host.AdminWithCredentialsAsync(authenticator, other);
        var (old, _) = await host.SignInAsync(authenticator);

        var (fresh, _) = await host.SignInAsync(authenticator, session: old);

        Assert.Equal("superseded", await host.ScalarAsync<string>(
            $"SELECT end_reason FROM admin_session WHERE id_hash = '\\x{Convert.ToHexStringLower(AdminHost.Hash(old))}' AND ended_at IS NOT NULL"));
        Assert.True(await host.ScalarAsync<bool>(
            $"SELECT ended_at IS NULL FROM admin_session WHERE id_hash = '\\x{Convert.ToHexStringLower(AdminHost.Hash(fresh))}'"));

        // Audited in the sign-in's own transaction: the Admin who signed in ended their own Session.
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.session.superseded'"));
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"""
                SELECT count(DISTINCT x) FROM (
                  SELECT xmin::text AS x FROM admin_session WHERE id_hash = '\x{Convert.ToHexStringLower(AdminHost.Hash(fresh))}'
                  UNION ALL SELECT xmin::text FROM admin_session WHERE id_hash = '\x{Convert.ToHexStringLower(AdminHost.Hash(old))}'
                  UNION ALL SELECT xmin::text FROM deployment_audit_event WHERE type_code = 'admin.session.superseded'
                ) AS writes
                """));
        using (var stale = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, old))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        }

        using var live = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, fresh);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
    }

    [Fact]
    public async Task Sign_out_ends_the_Session_with_its_event_and_the_old_cookie_is_then_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        var (_, adminId) = await host.AdminWithCredentialsAsync(first, second);
        var (cookie, csrf) = await host.SignInAsync(first);
        var hash = Convert.ToHexStringLower(AdminHost.Hash(cookie));

        using (var signedOut = await host.SendAsync(HttpMethod.Delete, SessionPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.NoContent, signedOut.StatusCode);
            Assert.Equal("__Host-gk-admin=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0", Assert.Single(signedOut.Headers.GetValues("Set-Cookie")));
        }

        Assert.Equal("signed_out", await host.ScalarAsync<string>($"SELECT end_reason FROM admin_session WHERE id_hash = '\\x{hash}' AND ended_at IS NOT NULL"));
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.session.signed_out'"));
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"""
                SELECT count(DISTINCT x) FROM (
                  SELECT xmin::text AS x FROM admin_session WHERE id_hash = '\x{hash}'
                  UNION ALL SELECT xmin::text FROM deployment_audit_event WHERE type_code = 'admin.session.signed_out'
                ) AS writes
                """));

        using (var after = await host.SendAsync(HttpMethod.Get, SessionPath, cookie))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }

        using (var again = await host.SendAsync(HttpMethod.Delete, SessionPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode);
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.session.signed_out'"));
    }

    [Fact]
    public async Task Before_bootstrap_completes_both_endpoints_are_the_unknown_path_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var unknown = await host.SendAsync(HttpMethod.Post, "/api/v1/deployment/nothing-here", origin: AdminHost.Origin);

        // Before init, then with a token issued but not claimed.
        for (var stage = 0; stage < 2; stage++)
        {
            var (begin, _, _) = await host.BeginSignInAsync();
            using (begin)
            {
                Assert.Equal(await AdminHost.SnapshotAsync(unknown), await AdminHost.SnapshotAsync(begin));
            }

            using (var complete = await host.CompleteSignInAsync(AdminHost.Unissued(), "{}"))
            {
                Assert.Equal(await AdminHost.SnapshotAsync(unknown), await AdminHost.SnapshotAsync(complete));
            }

            if (stage == 0)
            {
                await host.IssueTokenAsync();
            }
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));
    }

    public static TheoryData<string, string?, string?> OriginRefusals => new()
    {
        { AdminHost.SignInPath, null, null },
        { AdminHost.SignInPath, "https://elsewhere.test", null },
        { AdminHost.SignInPath, AdminHost.Origin + "/", null },
        { AdminHost.SignInPath, AdminHost.Origin, AdminHost.Origin },
        { CompletePath, null, null },
        { CompletePath, "https://elsewhere.test", null },
        { CompletePath, "null", null },
        { CompletePath, AdminHost.Origin, AdminHost.Origin },
    };

    [Theory]
    [MemberData(nameof(OriginRefusals))]
    public async Task Wrong_missing_or_duplicated_Origin_is_403_with_nothing_written(string path, string? origin, string? duplicate)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");
        IEnumerable<(string, string)> extra = duplicate is null ? Array.Empty<(string, string)>() : new[] { ("Origin", duplicate) };

        using var response = path == CompletePath
            ? await host.CompleteSignInAsync(binding, authenticator.Assert(options, AdminHost.Origin), origin: origin, headers: extra)
            : (await host.BeginSignInAsync(binding, origin, extra)).Response;

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        Assert.False(response.Headers.Contains("Set-Cookie"));

        // The one pending challenge is the earlier begin's, untouched; nothing counted past that begin.
        Assert.Equal(
            Convert.ToHexStringLower(AdminHost.Hash(binding!)),
            await host.ScalarAsync<string>("SELECT encode(binding_hash, 'hex') FROM admin_signin_challenge"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT coalesce(sum(attempts), 0) FROM admin_attempt WHERE policy LIKE 'admins.signin.%'"));
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
    }

    [Fact]
    public async Task Twenty_first_begin_and_eleventh_complete_in_15_minutes_are_429_with_Retry_After()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);

        string? binding = null;
        string? spare = null;
        JsonElement options = default;
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var (begin, began, bound) = await host.BeginSignInAsync();
            using (begin)
            {
                Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            }

            spare = binding;
            (binding, options) = (bound, began);
        }

        var (limitedBegin, _, _) = await host.BeginSignInAsync();
        using (limitedBegin)
        {
            await AssertRateLimitedAsync(limitedBegin);
        }

        // Ten completes, every one counted, the successful one too.
        for (var attempt = 0; attempt < 10; attempt++)
        {
            using var complete = await host.CompleteSignInAsync(attempt == 0 ? binding : null, attempt == 0 ? authenticator.Assert(options, AdminHost.Origin) : "{}");
            Assert.Equal(attempt == 0 ? HttpStatusCode.OK : HttpStatusCode.BadRequest, complete.StatusCode);
        }

        // The 19th begin's challenge is still pending. The eleventh complete is refused before the
        // take, so it leaves that challenge live, and its cookie alone.
        var spareHash = Convert.ToHexStringLower(AdminHost.Hash(spare!));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM admin_signin_challenge WHERE binding_hash = '\\x{spareHash}'"));
        using (var limitedComplete = await host.CompleteSignInAsync(spare, "{}"))
        {
            await AssertRateLimitedAsync(limitedComplete);
            Assert.False(limitedComplete.Headers.Contains("Set-Cookie"));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM admin_signin_challenge WHERE binding_hash = '\\x{spareHash}'"));
    }

    [Fact]
    public async Task Valid_assertion_sent_as_text_plain_is_refused_and_uses_up_the_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");
        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        var body = authenticator.Assert(options, AdminHost.Origin);

        using (var plain = await host.CompleteSignInAsync(binding, body, contentType: "text/plain"))
        {
            await AssertRefusedAsync(plain);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));

        using var json = await host.CompleteSignInAsync(binding, body);
        await AssertRefusedAsync(json);
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
    }

    [Fact]
    public async Task Body_over_64_KiB_is_refused_and_uses_up_the_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");
        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        var valid = authenticator.Assert(options, AdminHost.Origin);

        using var complete = await host.CompleteSignInAsync(binding, valid[..^1] + ",\"padding\":\"" + new string('x', 64 * 1024) + "\"}");

        await AssertRefusedAsync(complete);
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key"}""")]
    [InlineData("""{"id":"AQ","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"password","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"!!","authenticatorData":"AA","signature":"AA"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA","userHandle":"!!"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}}""")]
    public async Task Malformed_body_is_refused_and_uses_up_the_challenge(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var (begin, _, binding) = await host.BeginSignInAsync();
        begin.Dispose();

        using var complete = await host.CompleteSignInAsync(binding, body);

        await AssertRefusedAsync(complete);
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
    }

    [Theory]
    [InlineData("check_violation", HttpStatusCode.BadRequest)]
    [InlineData("raise_exception", HttpStatusCode.ServiceUnavailable)]
    public async Task Failure_after_the_challenge_is_taken_leaves_it_used_up(string errorCode, HttpStatusCode status)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");
        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        var body = authenticator.Assert(options, AdminHost.Origin);

        // Stands in for a constraint or a fault at the Session's insert, after verification passed.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $$"""
            CREATE FUNCTION test_fail_session_insert() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN
              RAISE EXCEPTION 'refused by the test' USING ERRCODE = '{{errorCode}}';
            END
            $body$;
            CREATE TRIGGER test_fail_session_insert BEFORE INSERT ON admin_session
              FOR EACH ROW EXECUTE FUNCTION test_fail_session_insert();
            """);

        using (var failed = await host.CompleteSignInAsync(binding, body))
        {
            Assert.Equal(status, failed.StatusCode);

            // Taken, so its cookie goes, a 503 included.
            Assert.Equal(ClearedBinding, Assert.Single(failed.Headers.GetValues("Set-Cookie")));
            if (status == HttpStatusCode.BadRequest)
            {
                await AssertRefusedAsync(failed);
            }
        }

        // Rolled back: no Session, the counter as it was, no event; and the challenge spent.
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.True(await host.ScalarAsync<bool>("SELECT sign_count = 0 AND last_used_at IS NULL FROM admin_credential"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_signin_challenge"));

        await PostgresFixture.ExecuteAsync(host.Superuser, "DROP TRIGGER test_fail_session_insert ON admin_session");
        using var again = await host.CompleteSignInAsync(binding, body);
        await AssertRefusedAsync(again);
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
    }

    [Fact]
    public async Task Lower_counter_after_a_higher_one_is_reported_as_a_clone()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        var (_, adminId) = await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        // Two sign-ins from one authenticator, made N+1 then N, arriving in that order. The row lock
        // runs them one at a time, so the second sees N+1 stored: no different from a clone.
        var (firstBegin, firstOptions, firstBinding) = await host.BeginSignInAsync();
        firstBegin.Dispose();
        var (secondBegin, secondOptions, secondBinding) = await host.BeginSignInAsync();
        secondBegin.Dispose();
        var higher = authenticator.Assert(firstOptions, AdminHost.Origin, new AssertionTweaks { SignCount = 2 });
        var lower = authenticator.Assert(secondOptions, AdminHost.Origin, new AssertionTweaks { SignCount = 1 });

        using (var committed = await host.CompleteSignInAsync(firstBinding, higher))
        {
            Assert.Equal(HttpStatusCode.OK, committed.StatusCode);
        }

        using var raced = await host.CompleteSignInAsync(secondBinding, lower);

        await AssertRefusedAsync(raced);
        Assert.Equal(sessions + 1, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT sign_count FROM admin_credential"));
        Assert.Equal(
            $"admin.credential.sign_count_regressed {adminId}",
            await host.ScalarAsync<string>(
                "SELECT type_code || ' ' || target_id FROM deployment_audit_event WHERE type_code IN ('admin.signin.failed', 'admin.credential.sign_count_regressed')"));
    }

    [Fact]
    public async Task Presented_Session_already_ended_or_expired_is_not_superseded()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        using var other = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator, other);

        var (ended, endedCsrf) = await host.SignInAsync(authenticator);
        using (var signedOut = await host.SendAsync(HttpMethod.Delete, SessionPath, ended, endedCsrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.NoContent, signedOut.StatusCode);
        }

        var (expired, _) = await host.SignInAsync(authenticator);
        var expiredHash = Convert.ToHexStringLower(AdminHost.Hash(expired));
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"UPDATE admin_session SET created_at = clock_timestamp() - interval '1 minute', idle_expires_at = clock_timestamp() - interval '1 second', absolute_expires_at = clock_timestamp() + interval '1 hour' WHERE id_hash = '\\x{expiredHash}'");

        await host.SignInAsync(authenticator, session: ended);
        await host.SignInAsync(authenticator, session: expired);

        Assert.Equal("signed_out", await host.ScalarAsync<string>(
            $"SELECT end_reason FROM admin_session WHERE id_hash = '\\x{Convert.ToHexStringLower(AdminHost.Hash(ended))}'"));
        Assert.True(await host.ScalarAsync<bool>($"SELECT ended_at IS NULL FROM admin_session WHERE id_hash = '\\x{expiredHash}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session WHERE end_reason = 'superseded'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.session.superseded'"));
    }

    [Fact]
    public async Task Admin_without_a_user_handle_is_refused_and_only_logged()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var authenticator = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(authenticator);
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        // Can't happen through the API, which makes the handle before any credential: set by hand.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            """
            ALTER TABLE admin DISABLE TRIGGER admin_guard_update;
            UPDATE admin SET webauthn_handle = NULL;
            ALTER TABLE admin ENABLE TRIGGER admin_guard_update;
            """);

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, authenticator.Assert(options, AdminHost.Origin));

        await AssertRefusedAsync(complete);
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
        Assert.True(await host.ScalarAsync<bool>("SELECT sign_count = 0 AND last_used_at IS NULL FROM admin_credential"));
    }

    [Fact]
    public async Task Unattributable_refusal_logs_its_fixed_name_and_trace_ID()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var admin = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(admin);
        using var stranger = new SoftwareAuthenticator { UserHandle = RandomNumberGenerator.GetBytes(64) };

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var complete = await host.CompleteSignInAsync(binding, stranger.Assert(options, AdminHost.Origin));

        await AssertRefusedAsync(complete);
        using var problem = JsonDocument.Parse(await complete.Content.ReadAsStringAsync(Cancellation));
        var traceId = problem.RootElement.GetProperty("traceId").GetString()!;
        Assert.Matches("^[0-9a-f]{32}$", traceId);

        // The host's log line names the fixed refusal and carries the trace ID; nothing is audited.
        await host.StopAsync();
        Assert.Contains($"signin_refused (Invalid, audited False), trace {traceId}", host.Output, StringComparison.Ordinal);
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {SignInEvents}"));
    }

    [Fact]
    public async Task Ending_a_Session_twice_audits_one_sign_out()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(first, second);
        var (cookie, _) = await host.SignInAsync(first);

        await using var source = NpgsqlDataSource.Create(host.AdminConnection);
        var sessions = AdminsContract.CreateSessions(AuditContract.CreateAppender());
        AdminSession session;
        await using (var scope = await DeploymentScope.BeginAsync(source, Cancellation))
        {
            session = (await sessions.AuthenticateAsync(scope.CreateCommandContext(), new Secret<string>(cookie), Cancellation))!;
            await scope.CommitAsync(Cancellation);
        }

        var ended = new List<bool>();
        for (var call = 0; call < 2; call++)
        {
            await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);
            ended.Add(await sessions.EndAsync(scope.CreateCommandContext(), session, Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal([true, false], ended);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.session.signed_out'"));
    }

    private static async Task AssertRefusedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("__Host-gk-admin=", StringComparison.Ordinal));
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["code", "traceId"], problem.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("signin_refused", problem.RootElement.GetProperty("code").GetString());
    }

    private static async Task AssertRateLimitedAsync(HttpResponseMessage response)
    {
        Assert.Equal((HttpStatusCode)429, response.StatusCode);
        var retryAfter = int.Parse(Assert.Single(response.Headers.GetValues("Retry-After")), System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(retryAfter, 1, 15 * 60);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("rate_limited", problem.RootElement.GetProperty("code").GetString());
    }
}
