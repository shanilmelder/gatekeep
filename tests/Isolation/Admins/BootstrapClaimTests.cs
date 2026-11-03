using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21: claiming bootstrap against the real <c>Host.Admin</c> and PostgreSQL. One claim of a
/// fresh token creates the first Admin as Deployment Owner, completes bootstrap, starts a setup
/// Session and writes <c>bootstrap.admin.created</c> in one transaction. Wrong, malformed and
/// expired tokens are refused and counted; the sixth refused attempt is rate limited; and once
/// bootstrap is complete, or before init, the claim and the Bootstrap page are the unknown-path 404.
/// </summary>
public sealed partial class BootstrapClaimTests(PostgresFixture postgres)
{
    private const string Policy = "admins.bootstrap.claim";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Valid_claim_creates_the_Owner_completes_bootstrap_and_starts_a_setup_session_in_one_transaction()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();

        using var response = await host.ClaimAsync(token);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        // A browser session cookie: host-only by its prefix, no Domain, Expires or Max-Age.
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"));
        Assert.Matches(SessionCookie(), setCookie);

        var (cookie, csrf, adminId) = await AdminHost.ReadClaimAsync(response);
        Assert.Matches(Secret(), csrf);
        Assert.NotEqual(cookie, csrf);
        using (var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)))
        {
            Assert.Equal(["csrfToken", "adminId"], body.RootElement.EnumerateObject().Select(p => p.Name));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin"));
        Assert.Equal(adminId, await host.ScalarAsync<Guid>("SELECT id FROM admin WHERE deployment_owner AND setup_completed_at IS NULL"));
        Assert.True(await host.ScalarAsync<bool>("SELECT completed_at IS NOT NULL FROM bootstrap_state"));

        await using (var connection = new NpgsqlConnection(host.Superuser))
        {
            await connection.OpenAsync(Cancellation);
            await using var command = new NpgsqlCommand(
                "SELECT admin_id, kind, id_hash, ended_at IS NULL, idle_expires_at - created_at, absolute_expires_at - created_at FROM admin_session",
                connection);
            await using var reader = await command.ExecuteReaderAsync(Cancellation);
            Assert.True(await reader.ReadAsync(Cancellation));
            Assert.Equal(adminId, reader.GetGuid(0));
            Assert.Equal("setup", reader.GetString(1));
            Assert.Equal(AdminHost.Hash(cookie), reader.GetFieldValue<byte[]>(2));
            Assert.Equal(AdminHost.Csrf(cookie), csrf);
            Assert.True(reader.GetBoolean(3));
            Assert.Equal(TimeSpan.FromMinutes(30), reader.GetTimeSpan(4));
            Assert.Equal(TimeSpan.FromHours(8), reader.GetTimeSpan(5));
            Assert.False(await reader.ReadAsync(Cancellation));
        }

        // One event, by and about the new Admin, after the issue event.
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'bootstrap.admin.created'"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'bootstrap.admin.created'"));

        // Every write in one transaction: the same xmin.
        Assert.Equal(
            1L,
            await host.ScalarAsync<long>(
                """
                SELECT count(DISTINCT x) FROM (
                  SELECT xmin::text AS x FROM admin
                  UNION ALL SELECT xmin::text FROM bootstrap_state
                  UNION ALL SELECT xmin::text FROM admin_session
                  UNION ALL SELECT xmin::text FROM deployment_audit_event WHERE type_code = 'bootstrap.admin.created'
                ) AS writes
                """));

        // The token, the Session ID and the CSRF token appear in no log line.
        Assert.DoesNotContain(token, host.Output);
        Assert.DoesNotContain(cookie, host.Output);
        Assert.DoesNotContain(csrf, host.Output);
    }

    [Fact]
    public async Task Token_with_surrounding_whitespace_is_claimed()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();

        using var response = await host.ClaimAsync($"  {token}\n");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    public static TheoryData<string> WrongBodies =>
    [
        // A wrong 64-hex token.
        JsonSerializer.Serialize(new { token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)) }),
        JsonSerializer.Serialize(new { token = "nope" }),
        JsonSerializer.Serialize(new { token = string.Empty }),
        JsonSerializer.Serialize(new { token = new string('Z', 64) }),
        """{"token": 5}""",
        """{"tokens": "x"}""",
        "[]",
        // A lone surrogate, which can't be read as UTF-8: refused, never a 500.
        """{"token":"\udc00"}""",
        """{"token":"\u0000\ud800x"}""",
        // An escape JSON doesn't have.
        """{"token":"\xff"}""",
        """{"token":"a","token":"b"}""",
        """{"token":{"nested":"x"}}""",
        "{{ not json",
        string.Empty,
        JsonSerializer.Serialize(new { token = new string('a', 8000) }),
    ];

    [Theory]
    [MemberData(nameof(WrongBodies))]
    public async Task Wrong_or_malformed_token_is_refused_counted_and_changes_nothing(string body)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.IssueTokenAsync();
        var before = await StateAsync(host);

        using var response = await host.ClaimBodyAsync(body);

        var traceId = await AssertProblemAsync(response, HttpStatusCode.BadRequest, "bootstrap_refused");
        Assert.Equal(1, await AttemptsAsync(host));
        Assert.Equal(before, await StateAsync(host));

        // The trace ID is the W3C one, and the host's log line names the problem code and carries it.
        Assert.Matches("^[0-9a-f]{32}$", traceId);
        await host.StopAsync();
        Assert.Contains($"refused with bootstrap_refused, trace {traceId}", host.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("application/json", " {}")]
    [InlineData("application/json", "x")]
    [InlineData("application/json", ",")]
    [InlineData("text/plain", "")]
    [InlineData("application/problem+json", "")]
    public async Task Right_token_with_trailing_content_or_not_sent_as_JSON_is_refused_and_counted(string contentType, string trailing)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();
        var before = await StateAsync(host);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/deployment/bootstrap")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { token }) + trailing, Encoding.UTF8, new MediaTypeHeaderValue(contentType)),
        };
        request.Headers.TryAddWithoutValidation("Origin", AdminHost.Origin);
        using var response = await host.Http.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertProblemAsync(response, HttpStatusCode.BadRequest, "bootstrap_refused");
        Assert.Equal(1, await AttemptsAsync(host));
        Assert.Equal(before, await StateAsync(host));
    }

    [Fact]
    public async Task Expired_token_is_refused_like_a_wrong_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();
        await host.ExpireTokenAsync();
        var before = await StateAsync(host);

        using var response = await host.ClaimAsync(token);

        await AssertProblemAsync(response, HttpStatusCode.BadRequest, "bootstrap_refused");
        Assert.Equal(1, await AttemptsAsync(host));
        Assert.Equal(before, await StateAsync(host));
    }

    [Fact]
    public async Task Sixth_refused_attempt_is_rate_limited_even_with_the_right_token()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            using var wrong = await host.ClaimAsync(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
            await AssertProblemAsync(wrong, HttpStatusCode.BadRequest, "bootstrap_refused");
            Assert.Equal(attempt, await AttemptsAsync(host));
        }

        using var limited = await host.ClaimAsync(token);

        await AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        var retryAfter = int.Parse(Assert.Single(limited.Headers.GetValues("Retry-After")), System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(retryAfter, 1, 15 * 60);
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin"));
        Assert.False(await host.ScalarAsync<bool>("SELECT completed_at IS NOT NULL FROM bootstrap_state"));
        Assert.Equal(6, await AttemptsAsync(host));
    }

    [Fact]
    public async Task Attempts_are_counted_per_forwarded_client_from_the_trusted_network_only()
    {
        await using var host = await AdminHost.StartAsync(postgres, null, "--Gatekeep:ForwardedBy=127.0.0.0/8");
        var token = await host.IssueTokenAsync();
        const string First = "203.0.113.9";

        for (var attempt = 1; attempt <= 6; attempt++)
        {
            using var wrong = await host.ClaimAsync("wrong", headers: [("X-Forwarded-For", First)]);
            Assert.Equal(attempt <= 5 ? HttpStatusCode.BadRequest : HttpStatusCode.TooManyRequests, wrong.StatusCode);
        }

        Assert.Equal(6, await AttemptsAsync(host, First));

        // Another client is counted on its own, and claims.
        using var other = await host.ClaimAsync(token, headers: [("X-Forwarded-For", "198.51.100.23")]);
        Assert.Equal(HttpStatusCode.Created, other.StatusCode);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("10.0.0.0/8")]
    public async Task Untrusted_peer_is_counted_as_itself_whatever_it_forwards(string forwardedBy)
    {
        await using var host = await AdminHost.StartAsync(postgres, null, $"--Gatekeep:ForwardedBy={forwardedBy}");
        await host.IssueTokenAsync();

        for (var attempt = 1; attempt <= 6; attempt++)
        {
            using var wrong = await host.ClaimAsync("wrong", headers: [("X-Forwarded-For", $"203.0.113.{attempt}")]);
            Assert.Equal(attempt <= 5 ? HttpStatusCode.BadRequest : HttpStatusCode.TooManyRequests, wrong.StatusCode);
        }

        Assert.Equal(6, await AttemptsAsync(host));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
    }

    [Fact]
    public async Task Trusted_peer_counts_the_address_it_saw_not_one_the_client_sent()
    {
        await using var host = await AdminHost.StartAsync(postgres, null, "--Gatekeep:ForwardedBy=127.0.0.0/8");
        await host.IssueTokenAsync();

        // Caddy appends the address it saw: the rightmost hop is the one believed.
        using var wrong = await host.ClaimAsync("wrong", headers: [("X-Forwarded-For", "198.51.100.7, 203.0.113.50")]);

        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal(1, await AttemptsAsync(host, "203.0.113.50"));
        Assert.Equal(0, await AttemptsAsync(host, "198.51.100.7"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
    }

    [Fact]
    public async Task IPv6_clients_in_one_64_share_one_count()
    {
        await using var host = await AdminHost.StartAsync(postgres, null, "--Gatekeep:ForwardedBy=127.0.0.0/8");
        await host.IssueTokenAsync();

        for (var attempt = 1; attempt <= 6; attempt++)
        {
            using var wrong = await host.ClaimAsync("wrong", headers: [("X-Forwarded-For", $"2001:db8::{attempt}")]);
            Assert.Equal(attempt <= 5 ? HttpStatusCode.BadRequest : HttpStatusCode.TooManyRequests, wrong.StatusCode);
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
        Assert.Equal(6, await AttemptsAsync(host, "2001:db8::/64"));
    }

    [Fact]
    public async Task Origin_setting_is_compared_in_the_form_browsers_send()
    {
        // Upper case and the default port, as an Operator might write it: browsers send neither.
        await using var host = await AdminHost.StartAsync(postgres, null, "--Gatekeep:PublicOrigin=https://ADMIN.gatekeep.test:443");
        var token = await host.IssueTokenAsync();

        using var claimed = await host.ClaimAsync(token, origin: "https://admin.gatekeep.test");

        Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
    }

    [Fact]
    public async Task Claim_after_success_is_the_unknown_path_404_and_creates_no_second_Admin()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();
        using (var claimed = await host.ClaimAsync(token))
        {
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
        }

        var attempts = await AttemptsAsync(host);
        var body = JsonSerializer.Serialize(new { token });
        using var unknown = await host.SendAsync(HttpMethod.Post, "/api/v1/nope", origin: AdminHost.Origin, body: body);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        var expected = await AdminHost.SnapshotAsync(unknown);

        foreach (var again in new[] { token, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)), "nope" })
        {
            using var response = await host.ClaimAsync(again);
            Assert.Equal(expected, await AdminHost.SnapshotAsync(response));
        }

        // Whatever the Origin or method: the route is gone.
        using (var foreign = await host.ClaimAsync(token, origin: "https://elsewhere.test"))
        {
            Assert.Equal(expected, await AdminHost.SnapshotAsync(foreign));
        }

        using (var get = await host.SendAsync(HttpMethod.Get, "/api/v1/deployment/bootstrap"))
        using (var unknownGet = await host.SendAsync(HttpMethod.Get, "/api/v1/nope"))
        {
            Assert.Equal(await AdminHost.SnapshotAsync(unknownGet), await AdminHost.SnapshotAsync(get));
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(attempts, await AttemptsAsync(host));
    }

    [Fact]
    public async Task Completed_bootstrap_is_the_404_after_a_restart_too()
    {
        await using var first = await AdminHost.StartAsync(postgres);
        var token = await first.IssueTokenAsync();
        using (var claimed = await first.ClaimAsync(token))
        {
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
        }

        await first.StopAsync();

        // A fresh host hasn't seen the claim: it reads completion from the database.
        await using var host = await AdminHost.StartAsync(postgres, first.Database);
        using var unknown = await host.SendAsync(HttpMethod.Post, "/api/v1/nope", origin: AdminHost.Origin, body: JsonSerializer.Serialize(new { token }));
        using var response = await host.ClaimAsync(token);
        using var page = await host.SendAsync(HttpMethod.Get, "/bootstrap");
        using var unknownPage = await host.SendAsync(HttpMethod.Get, "/api/v1/nope");

        Assert.Equal(await AdminHost.SnapshotAsync(unknown), await AdminHost.SnapshotAsync(response));
        Assert.Equal(await AdminHost.SnapshotAsync(unknownPage), await AdminHost.SnapshotAsync(page));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin"));
    }

    [Fact]
    public async Task Bootstrap_page_is_served_while_open_and_is_the_unknown_path_404_once_complete()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();

        using (var open = await host.SendAsync(HttpMethod.Get, "/bootstrap"))
        {
            Assert.Equal(HttpStatusCode.OK, open.StatusCode);
            Assert.Contains("<div id=\"root\">", await open.Content.ReadAsStringAsync(Cancellation));
        }

        using (var claimed = await host.ClaimAsync(token))
        {
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
        }

        using var unknown = await host.SendAsync(HttpMethod.Get, "/api/v1/nope");
        var expected = await AdminHost.SnapshotAsync(unknown);
        foreach (var path in new[] { "/bootstrap", "/bootstrap/" })
        {
            using var gone = await host.SendAsync(HttpMethod.Get, path);
            Assert.Equal(expected, await AdminHost.SnapshotAsync(gone));
        }

        // The rest of the bundle is still served, other casings of the path included: the match
        // is exact and case-sensitive, as the dashboard's own routing is.
        foreach (var path in new[] { "/", "/BOOTSTRAP" })
        {
            using var served = await host.SendAsync(HttpMethod.Get, path);
            Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        }
    }

    [Fact]
    public async Task Without_init_the_claim_and_page_are_the_unknown_path_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

        using var unknown = await host.SendAsync(HttpMethod.Post, "/api/v1/nope", origin: AdminHost.Origin, body: JsonSerializer.Serialize(new { token }));
        using var response = await host.ClaimAsync(token);
        using var page = await host.SendAsync(HttpMethod.Get, "/bootstrap");
        using var unknownPage = await host.SendAsync(HttpMethod.Get, "/api/v1/nope");

        Assert.Equal(await AdminHost.SnapshotAsync(unknown), await AdminHost.SnapshotAsync(response));
        Assert.Equal(await AdminHost.SnapshotAsync(unknownPage), await AdminHost.SnapshotAsync(page));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
    }

    [Fact]
    public async Task Concurrent_valid_claims_create_exactly_one_Admin()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();

        var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => host.ClaimAsync(token)));
        try
        {
            Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Created);
            Assert.All(responses.Where(r => r.StatusCode != HttpStatusCode.Created), r => Assert.Equal(HttpStatusCode.NotFound, r.StatusCode));
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'bootstrap.admin.created'"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://elsewhere.test")]
    [InlineData("http://admin.gatekeep.test")]
    [InlineData("https://admin.gatekeep.test:8443")]
    [InlineData("null")]
    public async Task Claim_with_a_missing_or_foreign_Origin_is_403_and_changes_nothing(string? origin)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();
        var before = await StateAsync(host);

        using var response = await host.ClaimAsync(token, origin);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.Equal(before, await StateAsync(host));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt"));
    }

    [Fact]
    public async Task Database_holds_the_token_only_as_its_hash()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();
        using (var claimed = await host.ClaimAsync(token))
        {
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
        }

        Assert.Equal(
            SHA256.HashData(Encoding.ASCII.GetBytes(token)),
            await host.ScalarAsync<byte[]>("SELECT token_sha256 FROM bootstrap_state"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE row_to_json(deployment_audit_event)::text LIKE '%{token}%'"));
    }

    /// <summary>Asserts a problem response with exactly <paramref name="code"/> and a trace ID, which it returns.</summary>
    internal static async Task<string> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["code", "traceId"], body.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(code, body.RootElement.GetProperty("code").GetString());
        var traceId = body.RootElement.GetProperty("traceId").GetString();
        Assert.False(string.IsNullOrWhiteSpace(traceId));
        return traceId!;
    }

    /// <summary>Everything a refused claim must leave as it was.</summary>
    internal static Task<string> StateAsync(AdminHost host) =>
        host.ScalarAsync<string>(
            """
            SELECT concat_ws(' | ',
              (SELECT encode(token_sha256, 'hex') || ' ' || issued_at || ' ' || expires_at || ' ' || coalesce(completed_at::text, '-') FROM bootstrap_state),
              (SELECT count(*) FROM admin),
              (SELECT count(*) FROM admin_session),
              (SELECT count(*) FROM deployment_audit_event))
            """);

    internal static async Task<int> AttemptsAsync(AdminHost host, string client = "127.0.0.1")
    {
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(client)));
        return await host.ScalarAsync<int?>(
            $"SELECT attempts FROM admin_attempt WHERE policy = '{Policy}' AND subject_hash = decode('{hash}', 'hex')") ?? 0;
    }

    [GeneratedRegex(@"\A__Host-gk-admin=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Strict\z")]
    private static partial Regex SessionCookie();

    [GeneratedRegex(@"\A[A-Za-z0-9_-]{43}\z")]
    private static partial Regex Secret();
}
