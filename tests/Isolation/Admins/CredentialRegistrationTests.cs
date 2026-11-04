using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.22: registering the first Admin's two WebAuthn credentials on the real
/// <c>Host.Admin</c> and PostgreSQL, with a software authenticator. The options carry the Admin
/// RP ID, no attestation, required user verification, a required resident key, ES256 and RS256,
/// the Admin's random user handle and their credentials as the exclude list. The challenge is
/// stored as its SHA-256 for 5 minutes and used up by the finish. The second credential makes the
/// Session full and completes setup in its own transaction; until then nothing but setup is
/// reachable, whatever the Session's kind. Responses for another RP ID or origin, cross-origin,
/// without user verification, with no live challenge, replayed, or returning an excluded
/// credential are refused with nothing stored.
/// </summary>
public sealed class CredentialRegistrationTests(PostgresFixture postgres)
{
    private const string CapabilitiesPath = "/api/v1/deployment/capabilities";
    private const string SessionPath = "/api/v1/deployment/session";
    private const string RpId = "admin.gatekeep.test";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task First_credential_is_stored_the_Session_stays_setup_and_one_event_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            Assert.Equal("no-store", begin.Headers.CacheControl?.ToString());
        }

        Assert.Equal(RpId, options.GetProperty("rp").GetProperty("id").GetString());
        Assert.Equal("Gatekeep", options.GetProperty("rp").GetProperty("name").GetString());
        Assert.Equal("none", options.GetProperty("attestation").GetString());
        Assert.Equal("required", options.GetProperty("authenticatorSelection").GetProperty("userVerification").GetString());
        Assert.Equal("required", options.GetProperty("authenticatorSelection").GetProperty("residentKey").GetString());
        Assert.Equal([-7, -257], options.GetProperty("pubKeyCredParams").EnumerateArray().Select(p => p.GetProperty("alg").GetInt32()));
        Assert.All(options.GetProperty("pubKeyCredParams").EnumerateArray(), p => Assert.Equal("public-key", p.GetProperty("type").GetString()));
        Assert.Empty(options.GetProperty("excludeCredentials").EnumerateArray());

        // A random 64-byte handle, never the Admin's ID, stored once on the Admin.
        var handle = Base64Url.DecodeFromChars(options.GetProperty("user").GetProperty("id").GetString()!);
        Assert.Equal(64, handle.Length);
        Assert.DoesNotContain(adminId.ToString("N"), Convert.ToHexStringLower(handle), StringComparison.Ordinal);
        Assert.Equal(Convert.ToHexStringLower(handle), await host.ScalarAsync<string>("SELECT encode(webauthn_handle, 'hex') FROM admin"));

        // The challenge: 32 bytes, stored only as its SHA-256, for 5 minutes.
        var challenge = Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!);
        Assert.Equal(32, challenge.Length);
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(challenge)),
            await host.ScalarAsync<string>("SELECT encode(registration_challenge_sha256, 'hex') FROM admin_session"));
        Assert.True(await host.ScalarAsync<bool>(
            "SELECT registration_challenge_expires_at BETWEEN clock_timestamp() + interval '4 minutes' AND clock_timestamp() + interval '5 minutes' FROM admin_session"));

        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(options, AdminHost.Origin));

        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        Assert.Equal("""{"credentials":1,"setupComplete":false}""", await complete.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("setup", await host.ScalarAsync<string>("SELECT kind FROM admin_session"));
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL AND registration_challenge_expires_at IS NULL FROM admin_session"));
        Assert.True(await host.ScalarAsync<bool>("SELECT setup_completed_at IS NULL FROM admin"));
        Assert.Equal(
            $"{Convert.ToHexStringLower(authenticator.CredentialId)} 0 {authenticator.Aaguid} {{usb,internal}} {adminId}",
            await host.ScalarAsync<string>(
                "SELECT encode(credential_id, 'hex') || ' ' || sign_count || ' ' || aaguid || ' ' || transports::text || ' ' || admin_id FROM admin_credential"));
        Assert.True(await host.ScalarAsync<bool>("SELECT octet_length(public_key) > 64 AND last_used_at IS NULL FROM admin_credential"));
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.credential.registered'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.setup.completed'"));

        // Still held to setup: one credential isn't enough.
        using var capabilities = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie);
        Assert.Equal(HttpStatusCode.Forbidden, capabilities.StatusCode);
        using var session = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);
        using var json = JsonDocument.Parse(await session.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(1, json.RootElement.GetProperty("credentials").GetInt32());
        Assert.False(json.RootElement.GetProperty("setupComplete").GetBoolean());
    }

    [Fact]
    public async Task Second_credential_makes_the_Session_full_and_completes_setup_in_one_transaction()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId) = await host.ClaimedAsync();
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, first);

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();

        // The first credential is excluded, so the same authenticator isn't used twice.
        Assert.Equal(
            [Base64Url.EncodeToString(first.CredentialId)],
            options.GetProperty("excludeCredentials").EnumerateArray().Select(c => c.GetProperty("id").GetString()));
        Assert.All(options.GetProperty("excludeCredentials").EnumerateArray(), c => Assert.Equal("public-key", c.GetProperty("type").GetString()));
        Assert.Equal(
            ["usb", "internal"],
            options.GetProperty("excludeCredentials")[0].GetProperty("transports").EnumerateArray().Select(t => t.GetString()));

        // Another live setup Session of the same Admin, as a second tab's would be.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            """
            INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
            SELECT gen_random_uuid(), sha256('other tab'), admin_id, 'setup', now(), now() + interval '30 minutes', now() + interval '8 hours'
            FROM admin_session
            """);

        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, second.Attest(options, AdminHost.Origin));

        Assert.Equal(HttpStatusCode.OK, complete.StatusCode);
        Assert.Equal("""{"credentials":2,"setupComplete":true}""", await complete.Content.ReadAsStringAsync(Cancellation));
        // Every live Session of the Admin is full: none stays held to setup.
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session WHERE kind = 'full'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session WHERE kind = 'setup'"));
        Assert.True(await host.ScalarAsync<bool>("SELECT setup_completed_at IS NOT NULL FROM admin"));
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.credential.registered'"));
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.setup.completed'"));

        // The second credential, the full Session, completion and both of its events: one transaction.
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                $"""
                SELECT count(DISTINCT x) FROM (
                  SELECT xmin::text AS x FROM admin_credential WHERE credential_id = '\x{Convert.ToHexStringLower(second.CredentialId)}'
                  UNION ALL SELECT xmin::text FROM admin_session WHERE id_hash <> sha256('other tab')
                  UNION ALL SELECT xmin::text FROM admin
                  UNION ALL SELECT xmin::text FROM deployment_audit_event WHERE type_code = 'admin.setup.completed'
                  UNION ALL (SELECT xmin::text FROM deployment_audit_event WHERE type_code = 'admin.credential.registered' ORDER BY occurred_at DESC LIMIT 1)
                ) AS writes
                """));

        // Setup is over: the rest of the API opens, and the Session says so.
        using var capabilities = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie);
        Assert.Equal(HttpStatusCode.OK, capabilities.StatusCode);
        using var session = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);
        using var json = JsonDocument.Parse(await session.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("full", json.RootElement.GetProperty("kind").GetString());
        Assert.True(json.RootElement.GetProperty("setupComplete").GetBoolean());
        Assert.Equal(2, json.RootElement.GetProperty("credentials").GetInt32());
    }

    [Fact]
    public async Task Admin_with_two_credentials_adds_a_third_only_after_a_fresh_assertion()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        using var third = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, first);
        await host.RegisterAsync(cookie, csrf, second);

        // The Session is full now (Story 1.26): a third is an add, which needs a fresh assertion.
        var (begin, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (begin)
        {
            await FreshAssertionTests.AssertProblemAsync(begin, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        // No begin passed, so no challenge is pending to complete.
        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, third.Attest(RpId, Base64Url.EncodeToString(new byte[32]), AdminHost.Origin));
        await AssertRefusedAsync(complete);
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));
    }

    [Fact]
    public async Task A_challenge_begun_in_setup_is_voided_when_another_Session_reaches_the_floor()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (a, aCsrf, _) = await host.ClaimedAsync();
        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        using var third = new SoftwareAuthenticator();
        await host.RegisterAsync(a, aCsrf, first);

        // A second setup Session of the same Owner, as another tab's would be.
        var raw = RandomNumberGenerator.GetBytes(32);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
            SELECT gen_random_uuid(), '\x{Convert.ToHexStringLower(SHA256.HashData(raw))}', admin_id, 'setup', now(), now() + interval '30 minutes', now() + interval '8 hours'
            FROM admin_session
            """);
        var b = Base64Url.EncodeToString(raw);

        // A begins, unconfirmed as setup allows; then B reaches the floor.
        var (begin, options) = await host.BeginRegistrationAsync(a, aCsrf);
        begin.Dispose();
        await host.RegisterAsync(b, AdminHost.Csrf(b), second);

        Assert.True(await host.ScalarAsync<bool>(
            $"SELECT registration_challenge_sha256 IS NULL FROM admin_session WHERE id_hash <> '\\x{Convert.ToHexStringLower(SHA256.HashData(raw))}'"));
        using var late = await host.CompleteRegistrationAsync(a, aCsrf, third.Attest(options, AdminHost.Origin));
        await AssertRefusedAsync(late);
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
    }

    [Fact]
    public async Task A_setup_Session_that_meets_the_floor_elsewhere_is_refused_with_a_bodiless_403()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var first = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, first);

        // Its Admin reached two credentials through another Session; this one still says setup.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            """
            INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid)
            SELECT gen_random_uuid(), id, '\x0b0b', '\x01', 0, gen_random_uuid() FROM admin
            """);

        var (begin, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (begin)
        {
            Assert.Equal(HttpStatusCode.Forbidden, begin.StatusCode);
            Assert.Empty(await begin.Content.ReadAsByteArrayAsync(Cancellation));
        }
    }

    [Fact]
    public async Task Same_authenticator_returning_an_excluded_credential_is_refused_and_nothing_is_stored()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var first = new SoftwareAuthenticator();
        await host.RegisterAsync(cookie, csrf, first);

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        using var again = await host.CompleteRegistrationAsync(cookie, csrf, first.Attest(options, AdminHost.Origin));

        await AssertRefusedAsync(again);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.credential.registered'"));
        Assert.Equal("setup", await host.ScalarAsync<string>("SELECT kind FROM admin_session"));
    }

    [Fact]
    public async Task Another_Admins_credential_is_refused_Deployment_wide()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var shared = new SoftwareAuthenticator();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            INSERT INTO admin (id, deployment_owner) VALUES ('{Guid.CreateVersion7()}', false);
            INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid)
            SELECT gen_random_uuid(), id, '\x{Convert.ToHexStringLower(shared.CredentialId)}', '\x01', 0, gen_random_uuid()
            FROM admin WHERE NOT deployment_owner;
            """);

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, shared.Attest(options, AdminHost.Origin));

        await AssertRefusedAsync(complete);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
    }

    [Theory]
    [InlineData("setup", 0)]
    [InlineData("setup", 1)]
    [InlineData("full", 0)]
    [InlineData("full", 1)]
    public async Task Admin_with_fewer_than_two_credentials_reaches_only_setup(string kind, int credentials)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        string cookie;
        string csrf;
        if (kind == "setup")
        {
            (cookie, csrf, _) = await host.ClaimedAsync();
            for (var i = 0; i < credentials; i++)
            {
                using var authenticator = new SoftwareAuthenticator();
                await host.RegisterAsync(cookie, csrf, authenticator);
            }
        }
        else
        {
            (cookie, csrf, _) = await host.InsertFullSessionAsync(credentials);
        }

        using (var capabilities = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie))
        {
            Assert.Equal(HttpStatusCode.Forbidden, capabilities.StatusCode);
        }

        // Setup itself stays reachable.
        using (var session = await host.SendAsync(HttpMethod.Get, SessionPath, cookie))
        {
            Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        }

        var (begin, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (begin)
        {
            Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
        }

        // And so does signing out (Story 1.26): any Session can always end itself.
        using (var signOut = await host.SendAsync(HttpMethod.Delete, SessionPath, cookie, csrf, AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);
        }
    }

    public static TheoryData<string> RefusedResponses => [.. Refusals.Keys];

    private static readonly Dictionary<string, AttestationTweaks> Refusals = new()
    {
        { "another RP ID", new AttestationTweaks { RpId = "elsewhere.test" } },
        { "the parent domain as RP ID", new AttestationTweaks { RpId = "gatekeep.test" } },
        { "another origin", new AttestationTweaks { Origin = "https://elsewhere.test" } },
        { "the origin in other case", new AttestationTweaks { Origin = "https://ADMIN.gatekeep.test" } },
        { "the origin with its default port", new AttestationTweaks { Origin = "https://admin.gatekeep.test:443" } },
        { "the origin over http", new AttestationTweaks { Origin = "http://admin.gatekeep.test" } },
        { "crossOrigin true", new AttestationTweaks { CrossOrigin = true } },
        { "a top origin", new AttestationTweaks { TopOrigin = "https://admin.gatekeep.test" } },
        { "no user verification", new AttestationTweaks { UserVerified = false } },
        { "another challenge", new AttestationTweaks { Challenge = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)) } },
        { "an assertion's type", new AttestationTweaks { Type = "webauthn.get" } },
        { "an algorithm not offered", new AttestationTweaks { Algorithm = -35 } },
    };

    [Theory]
    [MemberData(nameof(RefusedResponses))]
    public async Task Response_the_ceremony_refuses_is_400_and_stores_nothing(string response)
    {
        var tweaks = Refusals[response];
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(options, AdminHost.Origin, tweaks));

        await AssertRefusedAsync(complete);
        await AssertNothingStoredAsync(host);

        // The challenge went with the refusal: the right response can't follow on it.
        using var retry = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(options, AdminHost.Origin));
        await AssertRefusedAsync(retry);
        await AssertNothingStoredAsync(host);
    }

    [Fact]
    public async Task Finish_with_no_begin_or_after_the_challenge_expires_is_refused()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();

        using (var none = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(RpId, Base64Url.EncodeToString(new byte[32]), AdminHost.Origin)))
        {
            await AssertRefusedAsync(none);
        }

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        await PostgresFixture.ExecuteAsync(host.Superuser, "UPDATE admin_session SET registration_challenge_expires_at = clock_timestamp() - interval '1 second'");

        using (var expired = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(options, AdminHost.Origin)))
        {
            await AssertRefusedAsync(expired);
        }

        await AssertNothingStoredAsync(host);
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));
    }

    [Fact]
    public async Task New_begin_replaces_the_pending_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();

        var (first, earlier) = await host.BeginRegistrationAsync(cookie, csrf);
        first.Dispose();
        var (second, later) = await host.BeginRegistrationAsync(cookie, csrf);
        second.Dispose();
        Assert.NotEqual(earlier.GetProperty("challenge").GetString(), later.GetProperty("challenge").GetString());

        using (var stale = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(earlier, AdminHost.Origin)))
        {
            await AssertRefusedAsync(stale);
        }

        // That refusal used the pending challenge up too.
        using var current = await host.CompleteRegistrationAsync(cookie, csrf, authenticator.Attest(later, AdminHost.Origin));
        await AssertRefusedAsync(current);
        await AssertNothingStoredAsync(host);
    }

    [Fact]
    public async Task Replayed_finish_is_refused()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();

        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        var body = authenticator.Attest(options, AdminHost.Origin);
        using (var accepted = await host.CompleteRegistrationAsync(cookie, csrf, body))
        {
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        }

        using var replayed = await host.CompleteRegistrationAsync(cookie, csrf, body);

        await AssertRefusedAsync(replayed);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'admin.credential.registered'"));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key"}""")]
    [InlineData("""{"id":"AQ","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"password","response":{"clientDataJSON":"e30","attestationObject":"oA"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"!!","attestationObject":"oA"}}""")]
    [InlineData("""{"id":"AA","rawId":"AA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}""")]
    public async Task Malformed_body_is_refused_and_uses_up_the_challenge(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        var (begin, _) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();

        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, body);

        await AssertRefusedAsync(complete);
        await AssertNothingStoredAsync(host);
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));
    }

    [Fact]
    public async Task Registration_needs_the_Session_the_exact_Origin_and_the_CSRF_token()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();

        using (var noSession = await host.SendAsync(HttpMethod.Post, AdminHost.RegistrationPath, origin: AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, noSession.StatusCode);
        }

        using (var noCsrf = await host.SendAsync(HttpMethod.Post, AdminHost.RegistrationPath, cookie, origin: AdminHost.Origin))
        {
            Assert.Equal(HttpStatusCode.Forbidden, noCsrf.StatusCode);
        }

        using (var foreign = await host.SendAsync(HttpMethod.Post, AdminHost.RegistrationPath, cookie, csrf, "https://elsewhere.test"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        }

        using (var noCsrfComplete = await host.SendAsync(HttpMethod.Post, AdminHost.RegistrationPath + "/complete", cookie, origin: AdminHost.Origin, body: "{}"))
        {
            Assert.Equal(HttpStatusCode.Forbidden, noCsrfComplete.StatusCode);
        }

        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt WHERE policy = 'admins.credential.register'"));
    }

    [Fact]
    public async Task Eleventh_attempt_in_15_minutes_is_429_with_Retry_After()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var (begin, _) = await host.BeginRegistrationAsync(cookie, csrf);
            begin.Dispose();
            using var complete = await host.CompleteRegistrationAsync(cookie, csrf, "{}");
            await AssertRefusedAsync(complete);
        }

        var (limited, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (limited)
        {
            Assert.Equal((HttpStatusCode)429, limited.StatusCode);
            var retryAfter = int.Parse(Assert.Single(limited.Headers.GetValues("Retry-After")), System.Globalization.CultureInfo.InvariantCulture);
            Assert.InRange(retryAfter, 1, 15 * 60);
            using var problem = JsonDocument.Parse(await limited.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal("rate_limited", problem.RootElement.GetProperty("code").GetString());
        }

        using var limitedComplete = await host.CompleteRegistrationAsync(cookie, csrf, "{}");
        Assert.Equal((HttpStatusCode)429, limitedComplete.StatusCode);

        // Per Session: another Admin's Session isn't limited by this one's attempts.
        var (other, _, _) = await host.InsertFullSessionAsync(credentials: 0);
        var (otherBegin, _) = await host.BeginRegistrationAsync(other, AdminHost.Csrf(other));
        using (otherBegin)
        {
            Assert.Equal(HttpStatusCode.OK, otherBegin.StatusCode);
        }
    }

    [Fact]
    public async Task Valid_attestation_sent_as_text_plain_is_refused_and_uses_up_the_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();
        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        var body = authenticator.Attest(options, AdminHost.Origin);

        using (var plain = await host.CompleteRegistrationAsync(cookie, csrf, body, "text/plain"))
        {
            await AssertRefusedAsync(plain);
        }

        await AssertNothingStoredAsync(host);
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));

        // The same attestation as JSON can't follow on the used challenge.
        using var json = await host.CompleteRegistrationAsync(cookie, csrf, body);
        await AssertRefusedAsync(json);
        await AssertNothingStoredAsync(host);
    }

    [Fact]
    public async Task Body_over_64_KiB_is_refused_and_uses_up_the_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();
        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        var valid = authenticator.Attest(options, AdminHost.Origin);
        var oversized = valid[..^1] + ",\"padding\":\"" + new string('x', 64 * 1024) + "\"}";

        using var complete = await host.CompleteRegistrationAsync(cookie, csrf, oversized);

        await AssertRefusedAsync(complete);
        await AssertNothingStoredAsync(host);
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));
    }

    [Theory]
    [InlineData("check_violation", HttpStatusCode.BadRequest)]
    [InlineData("raise_exception", HttpStatusCode.ServiceUnavailable)]
    public async Task Failure_after_the_challenge_is_taken_leaves_it_used_up(string errorCode, HttpStatusCode status)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();
        using var authenticator = new SoftwareAuthenticator();
        var (begin, options) = await host.BeginRegistrationAsync(cookie, csrf);
        begin.Dispose();
        var body = authenticator.Attest(options, AdminHost.Origin);

        // Stands in for a constraint or a fault at the insert, after verification passed.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $$"""
            CREATE FUNCTION test_fail_credential_insert() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN
              RAISE EXCEPTION 'refused by the test' USING ERRCODE = '{{errorCode}}';
            END
            $body$;
            CREATE TRIGGER test_fail_credential_insert BEFORE INSERT ON admin_credential
              FOR EACH ROW EXECUTE FUNCTION test_fail_credential_insert();
            """);

        using (var failed = await host.CompleteRegistrationAsync(cookie, csrf, body))
        {
            Assert.Equal(status, failed.StatusCode);
            if (status == HttpStatusCode.BadRequest)
            {
                await AssertRefusedAsync(failed);
            }
        }

        await AssertNothingStoredAsync(host);
        Assert.True(await host.ScalarAsync<bool>("SELECT registration_challenge_sha256 IS NULL FROM admin_session"));

        // With the fault gone, the same attestation still can't be used: its challenge is spent.
        await PostgresFixture.ExecuteAsync(host.Superuser, "DROP TRIGGER test_fail_credential_insert ON admin_credential");
        using var again = await host.CompleteRegistrationAsync(cookie, csrf, body);
        await AssertRefusedAsync(again);
        await AssertNothingStoredAsync(host);
    }

    private static async Task AssertRefusedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["code", "traceId"], problem.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("credential_refused", problem.RootElement.GetProperty("code").GetString());
    }

    private static async Task AssertNothingStoredAsync(AdminHost host)
    {
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code LIKE 'admin.%'"));
        Assert.Equal("setup", await host.ScalarAsync<string>("SELECT kind FROM admin_session"));
    }
}
