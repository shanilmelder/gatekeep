using System.Net;
using System.Text.Json;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21: the request checks in front of every <c>/api/v1/deployment</c> endpoint, on the real
/// <c>Host.Admin</c>. The setup Session from the claim reads the Session endpoint, which returns the
/// CSRF token derived from the Session ID, the same every time, and reaches nothing that isn't
/// setup-allowed, signing out included. A full Session's state-changing call needs the exact
/// Origin and its CSRF token. A missing, unknown, ended or expired Session is 401, a sent cookie is
/// cleared, and an expired Session is ended. Each authenticated request slides the idle expiry,
/// never past the absolute.
/// </summary>
public sealed class AdminSessionTests(PostgresFixture postgres)
{
    private const string SessionPath = "/api/v1/deployment/session";
    private const string CapabilitiesPath = "/api/v1/deployment/capabilities";
    private const string ClearedCookie = "__Host-gk-admin=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Setup_session_reads_the_Session_and_the_same_CSRF_token_every_time()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId) = await host.ClaimedAsync();

        for (var read = 0; read < 2; read++)
        {
            using var response = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.False(response.Headers.Contains("Set-Cookie"));
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            var root = body.RootElement;
            Assert.Equal(["adminId", "kind", "deploymentOwner", "setupComplete", "credentials", "csrfToken"], root.EnumerateObject().Select(p => p.Name));
            Assert.Equal(adminId, root.GetProperty("adminId").GetGuid());
            Assert.Equal("setup", root.GetProperty("kind").GetString());
            Assert.True(root.GetProperty("deploymentOwner").GetBoolean());
            Assert.False(root.GetProperty("setupComplete").GetBoolean());
            Assert.Equal(0, root.GetProperty("credentials").GetInt32());
            Assert.Equal(csrf, root.GetProperty("csrfToken").GetString());
        }

        // Nothing about the CSRF token is stored: it is derived from the Session ID.
        Assert.Equal(AdminHost.Csrf(cookie), csrf);
        Assert.Equal(
            0L,
            await host.ScalarAsync<long>(
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'admin_session' AND column_name LIKE '%csrf%'"));
        Assert.DoesNotContain(csrf, host.Output);
    }

    [Theory]
    [InlineData("GET", CapabilitiesPath)]
    [InlineData("DELETE", SessionPath)]
    public async Task Setup_session_on_an_endpoint_that_isnt_setup_allowed_is_403(string method, string path)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();

        // Signing out isn't setup-allowed: it would strand the only Deployment Owner.
        using var response = await host.SendAsync(new HttpMethod(method), path, cookie, csrf, AdminHost.Origin);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        Assert.True(await host.ScalarAsync<bool>("SELECT ended_at IS NULL FROM admin_session"));
    }

    [Fact]
    public async Task Full_session_reads_capabilities_as_an_object()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.InsertFullSessionAsync();

        using var response = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""{"capabilities":[]}""", await response.Content.ReadAsStringAsync(Cancellation));
    }

    [Fact]
    public async Task State_changing_call_needs_the_exact_Origin_and_the_Session_CSRF_token()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, sessionId) = await host.InsertFullSessionAsync();
        var (_, otherCsrf, _) = await host.InsertFullSessionAsync();

        (string? Csrf, string? Origin)[] refused =
        [
            (null, AdminHost.Origin),
            (string.Empty, AdminHost.Origin),
            (AdminHost.Unissued(), AdminHost.Origin),
            (otherCsrf, AdminHost.Origin),
            (cookie, AdminHost.Origin),
            (csrf + "A", AdminHost.Origin),
            (csrf, null),
            (csrf, "https://elsewhere.test"),
            (csrf, AdminHost.Origin + "/"),
        ];
        foreach (var (token, origin) in refused)
        {
            using var response = await host.SendAsync(HttpMethod.Delete, SessionPath, cookie, token, origin);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.True(await host.ScalarAsync<bool>($"SELECT ended_at IS NULL FROM admin_session WHERE id = '{sessionId}'"));

        using var signedOut = await host.SendAsync(HttpMethod.Delete, SessionPath, cookie, csrf, AdminHost.Origin);
        Assert.Equal(HttpStatusCode.NoContent, signedOut.StatusCode);
        Assert.Equal(ClearedCookie, Assert.Single(signedOut.Headers.GetValues("Set-Cookie")));
        Assert.Equal("signed_out", await host.ScalarAsync<string>($"SELECT end_reason FROM admin_session WHERE id = '{sessionId}' AND ended_at IS NOT NULL"));

        using var ended = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie);
        await AssertUnauthorizedAsync(ended, cleared: true);
    }

    public static TheoryData<string, string> StateChangingCalls => new()
    {
        { "DELETE", SessionPath },
        { "POST", AdminHost.RegistrationPath },
        { "POST", AdminHost.RegistrationPath + "/complete" },
    };

    /// <summary>
    /// Story 1.23, NFR-4: sign-out and both registration calls refuse a missing or wrong CSRF
    /// token, and a wrong, missing or duplicated Origin, with 403; the Session stays live, no
    /// challenge is set and no attempt is counted.
    /// </summary>
    [Theory]
    [MemberData(nameof(StateChangingCalls))]
    public async Task State_changing_call_with_a_bad_CSRF_token_or_Origin_is_403_and_changes_nothing(string method, string path)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        // Sign-out needs an Admin past setup; registration one still in it. Either way, only the checks refuse.
        var (cookie, csrf, sessionId) = await host.InsertFullSessionAsync(credentials: method == "DELETE" ? 2 : 1);
        var (_, otherCsrf, _) = await host.InsertFullSessionAsync();

        (string? Csrf, string? Origin, string? SecondOrigin)[] refused =
        [
            (null, AdminHost.Origin, null),
            (AdminHost.Unissued(), AdminHost.Origin, null),
            (otherCsrf, AdminHost.Origin, null),
            (csrf, null, null),
            (csrf, "https://elsewhere.test", null),
            (csrf, AdminHost.Origin, AdminHost.Origin),
            (csrf, AdminHost.Origin, "https://elsewhere.test"),
        ];
        foreach (var (token, origin, second) in refused)
        {
            using var response = await host.SendAsync(
                new HttpMethod(method),
                path,
                cookie,
                token,
                origin,
                body: path.EndsWith("/complete", StringComparison.Ordinal) ? "{}" : null,
                headers: second is null ? null : new[] { ("Origin", second) });
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.True(await host.ScalarAsync<bool>(
            $"SELECT ended_at IS NULL AND registration_challenge_sha256 IS NULL FROM admin_session WHERE id = '{sessionId}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code LIKE 'admin.%'"));
    }

    [Fact]
    public async Task Missing_session_is_401_and_a_stale_cookie_is_cleared()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.ClaimedAsync();

        foreach (var path in new[] { SessionPath, CapabilitiesPath })
        {
            using (var none = await host.SendAsync(HttpMethod.Get, path))
            {
                await AssertUnauthorizedAsync(none, cleared: false);
            }

            foreach (var sent in new[] { string.Empty, AdminHost.Unissued(), "abc", cookie + "=", cookie[..^1] })
            {
                using var response = await host.SendAsync(HttpMethod.Get, path, sent);
                await AssertUnauthorizedAsync(response, cleared: true);
            }
        }
    }

    [Theory]
    [InlineData("created_at = clock_timestamp() - interval '1 minute', idle_expires_at = clock_timestamp() - interval '1 second', absolute_expires_at = clock_timestamp() + interval '1 hour'")]
    [InlineData("created_at = clock_timestamp() - interval '8 hours', idle_expires_at = clock_timestamp() - interval '2 seconds', absolute_expires_at = clock_timestamp() - interval '1 second'")]
    public async Task Expired_session_is_401_cleared_and_ended_as_expired(string expiry)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.ClaimedAsync();
        await PostgresFixture.ExecuteAsync(host.Superuser, $"UPDATE admin_session SET {expiry}");

        using var response = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);

        await AssertUnauthorizedAsync(response, cleared: true);
        Assert.Equal("expired", await host.ScalarAsync<string>("SELECT end_reason FROM admin_session WHERE ended_at IS NOT NULL"));

        // Ended, it stays 401 whatever its times say.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "UPDATE admin_session SET created_at = clock_timestamp() - interval '1 hour', idle_expires_at = clock_timestamp() + interval '1 minute', absolute_expires_at = clock_timestamp() + interval '1 hour'");
        using var again = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);
        await AssertUnauthorizedAsync(again, cleared: true);
    }

    [Fact]
    public async Task Authenticated_request_slides_the_idle_expiry_never_past_the_absolute()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.ClaimedAsync();
        var before = await host.ScalarAsync<DateTime>("SELECT idle_expires_at FROM admin_session");

        await Task.Delay(TimeSpan.FromMilliseconds(50), Cancellation);
        using (var response = await host.SendAsync(HttpMethod.Get, SessionPath, cookie))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.True(await host.ScalarAsync<DateTime>("SELECT idle_expires_at FROM admin_session") > before);

        // Near the absolute expiry, the idle one stops at it.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "UPDATE admin_session SET idle_expires_at = clock_timestamp() + interval '10 seconds', absolute_expires_at = clock_timestamp() + interval '1 minute'");
        using (var response = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, cookie))
        {
            // Refused by the setup restriction, after the Session was authenticated and slid.
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        Assert.True(await host.ScalarAsync<bool>("SELECT idle_expires_at = absolute_expires_at FROM admin_session"));
    }

    private static async Task AssertUnauthorizedAsync(HttpResponseMessage response, bool cleared)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        if (cleared)
        {
            Assert.Equal(ClearedCookie, Assert.Single(response.Headers.GetValues("Set-Cookie")));
        }
        else
        {
            Assert.False(response.Headers.Contains("Set-Cookie"));
        }
    }
}
