using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21: claims under load and under the row lock, on real <c>Host.Admin</c> processes. Each
/// claim is counted in its own committed transaction before the lock, so concurrent wrong claims
/// get exactly five comparisons; a process runs four claims at once and refuses more with 503; a
/// claim that waits past the lock timeout is a 503 with the AD-21 headers and changes nothing; and
/// claims racing across two processes create exactly one Admin.
/// </summary>
public sealed class BootstrapClaimLockTests(PostgresFixture postgres)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Concurrent_wrong_claims_from_one_client_get_exactly_five_comparisons()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.IssueTokenAsync();
        var statuses = new List<HttpStatusCode>();

        // Three waves of four at once, the most one process runs together.
        for (var wave = 0; wave < 3; wave++)
        {
            var responses = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => host.ClaimAsync(Wrong())));
            statuses.AddRange(responses.Select(r => r.StatusCode));
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Equal(5, statuses.Count(s => s == HttpStatusCode.BadRequest));
        Assert.Equal(7, statuses.Count(s => s == HttpStatusCode.TooManyRequests));
        Assert.Equal(6, await BootstrapClaimTests.AttemptsAsync(host));
    }

    [Fact]
    public async Task Claims_beyond_the_per_process_cap_get_a_fast_503_and_a_later_valid_claim_succeeds()
    {
        await using var host = await AdminHost.StartAsync(
            postgres, null, "--Gatekeep:BootstrapLockTimeoutMs=30000", "--Gatekeep:ForwardedBy=127.0.0.0/8");
        var token = await host.IssueTokenAsync();
        const string Client = "203.0.113.1";
        (string, string)[] From(string client) => [("X-Forwarded-For", client)];

        Task<HttpResponseMessage>[] waiting;
        await using (var held = await HeldLock.TakeAsync(host.Superuser))
        {
            waiting = [.. Enumerable.Range(0, 4).Select(_ => host.ClaimAsync(Wrong(), headers: From(Client)))];
            await held.WaitForWaitersAsync(4);

            // Each from its own client, so none is rate limited: the cap alone refuses them.
            var clock = Stopwatch.StartNew();
            for (var flood = 1; flood <= 6; flood++)
            {
                using var refused = await host.ClaimAsync(Wrong(), headers: From($"198.51.100.{flood}"));
                Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
                Assert.Empty(await refused.Content.ReadAsByteArrayAsync(Cancellation));
                Assert.Equal("no-store", refused.Headers.CacheControl?.ToString());
            }

            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"The flood took {clock.Elapsed}.");
        }

        foreach (var response in await Task.WhenAll(waiting))
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            response.Dispose();
        }

        // Each claim is counted before it takes a slot, the flood's too, each against its own client.
        Assert.Equal(1, await BootstrapClaimTests.AttemptsAsync(host, "198.51.100.1"));
        Assert.Equal(4, await BootstrapClaimTests.AttemptsAsync(host, Client));
        using var claimed = await host.ClaimAsync(token, headers: From(Client));
        Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
    }

    [Fact]
    public async Task Slow_senders_hold_no_claim_slot()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();

        // More slow senders than slots, each with its body half sent.
        var senders = new List<System.Net.Sockets.TcpClient>();
        try
        {
            for (var sender = 0; sender < 6; sender++)
            {
                var client = new System.Net.Sockets.TcpClient();
                senders.Add(client);
                await client.ConnectAsync(System.Net.IPAddress.Loopback, host.Port, Cancellation);
                var head = System.Text.Encoding.ASCII.GetBytes(
                    $"POST /api/v1/deployment/bootstrap HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: {AdminHost.Origin}\r\n" +
                    "Content-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"token\":");
                await client.GetStream().WriteAsync(head, Cancellation);
            }

            // A claim with its whole body still gets a slot while they wait.
            await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);
            using var claimed = await host.ClaimAsync(token);
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
        }
        finally
        {
            foreach (var client in senders)
            {
                client.Dispose();
            }
        }
    }

    [Fact]
    public async Task Lock_wait_past_the_timeout_is_a_503_with_the_AD_21_headers_and_changes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres, null, "--Gatekeep:BootstrapLockTimeoutMs=500");
        var token = await host.IssueTokenAsync();
        var before = await BootstrapClaimTests.StateAsync(host);

        HttpResponseMessage response;
        await using (var held = await HeldLock.TakeAsync(host.Superuser))
        {
            response = await host.ClaimAsync(token);
        }

        using (response)
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Cancellation));
            Assert.False(response.Headers.Contains("Set-Cookie"));
            Assert.Equal([SecurityHeaders.ContentSecurityPolicy], response.Headers.GetValues("Content-Security-Policy"));
            Assert.Equal([SecurityHeaders.ReferrerPolicy], response.Headers.GetValues("Referrer-Policy"));
            Assert.Equal([SecurityHeaders.FrameOptions], response.Headers.GetValues("X-Frame-Options"));
            Assert.Equal([SecurityHeaders.ContentTypeOptions], response.Headers.GetValues("X-Content-Type-Options"));
        }

        Assert.Equal(before, await BootstrapClaimTests.StateAsync(host));
        Assert.Equal(1, await BootstrapClaimTests.AttemptsAsync(host));

        await host.StopAsync();
        Assert.Contains("55P03", host.Output);
        Assert.DoesNotContain("lock timeout", host.Output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("   at ", host.Output);
    }

    [Fact]
    public async Task Valid_claims_racing_across_two_hosts_create_exactly_one_Admin()
    {
        await using var first = await AdminHost.StartAsync(postgres, null, "--Gatekeep:BootstrapLockTimeoutMs=30000");
        await using var second = await AdminHost.StartAsync(postgres, first.Database, "--Gatekeep:BootstrapLockTimeoutMs=30000");
        var token = await first.IssueTokenAsync();

        Task<HttpResponseMessage>[] claims;
        await using (var held = await HeldLock.TakeAsync(first.Superuser))
        {
            claims = [first.ClaimAsync(token), first.ClaimAsync(token), second.ClaimAsync(token), second.ClaimAsync(token)];
            await held.WaitForWaitersAsync(4);
        }

        var responses = await Task.WhenAll(claims);
        try
        {
            Assert.Single(responses, r => r.StatusCode == HttpStatusCode.Created);

            using var unknown = await first.SendAsync(
                HttpMethod.Post, "/api/v1/nope", origin: AdminHost.Origin, body: JsonSerializer.Serialize(new { token }));
            var expected = await AdminHost.SnapshotAsync(unknown);
            foreach (var loser in responses.Where(r => r.StatusCode != HttpStatusCode.Created))
            {
                Assert.Equal(expected, await AdminHost.SnapshotAsync(loser));
            }
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }

        Assert.Equal(1L, await first.ScalarAsync<long>("SELECT count(*) FROM admin"));
        Assert.Equal(1L, await first.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.Equal(1L, await first.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'bootstrap.admin.created'"));
    }

    [Fact]
    public async Task Elapsed_window_starts_counting_again_and_Retry_After_is_the_time_left()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.IssueTokenAsync();
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            using var wrong = await host.ClaimAsync(Wrong());
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        // Ten minutes into the window: about five left.
        await PostgresFixture.ExecuteAsync(host.Superuser, "UPDATE admin_attempt SET window_start = now() - interval '10 minutes'");
        using (var limited = await host.ClaimAsync(Wrong()))
        {
            await BootstrapClaimTests.AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
            var retryAfter = int.Parse(Assert.Single(limited.Headers.GetValues("Retry-After")), System.Globalization.CultureInfo.InvariantCulture);
            Assert.InRange(retryAfter, 295, 305);
        }

        // Past the window: counted from one again.
        await PostgresFixture.ExecuteAsync(host.Superuser, "UPDATE admin_attempt SET window_start = now() - interval '16 minutes'");
        using (var wrong = await host.ClaimAsync(Wrong()))
        {
            await BootstrapClaimTests.AssertProblemAsync(wrong, HttpStatusCode.BadRequest, "bootstrap_refused");
        }

        Assert.Equal(1, await BootstrapClaimTests.AttemptsAsync(host));
    }

    [Fact]
    public async Task Init_after_the_claim_refuses_and_the_claim_and_page_stay_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var token = await host.IssueTokenAsync();
        using (var claimed = await host.ClaimAsync(token))
        {
            Assert.Equal(HttpStatusCode.Created, claimed.StatusCode);
        }

        var directory = Directory.CreateTempSubdirectory("gatekeep-init-after-claim-").FullName;
        try
        {
            string File(string name, string contents)
            {
                var path = Path.Combine(directory, name);
                System.IO.File.WriteAllText(path, contents);
                return path;
            }

            var connection = new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Cli, host.Database)) { Password = null }.ConnectionString;
            var tokens = Directory.CreateDirectory(Path.Combine(directory, "tokens")).FullName;
            var result = await CliProcess.RunCapturedAsync(
                new Dictionary<string, string>
                {
                    ["GATEKEEP_CLI_CONNECTION_FILE"] = File("connection", connection),
                    ["GATEKEEP_CLI_PASSWORD_FILE"] = File("password", PostgresFixture.Password + "\n"),
                    ["GATEKEEP_CUSTODY_SOCKET"] = Path.Combine(directory, "no.sock"),
                    ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = File("role-id", Guid.NewGuid().ToString()),
                    ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = File("secret-id", Guid.NewGuid().ToString()),
                },
                "init",
                "--token-dir",
                tokens);

            Assert.Equal(1, result.ExitCode);
            Assert.Equal("Bootstrap is already complete, so init issues no token.\n", result.StandardError);
            Assert.Empty(Directory.EnumerateFileSystemEntries(tokens));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

        using var unknown = await host.SendAsync(HttpMethod.Post, "/api/v1/nope", origin: AdminHost.Origin, body: JsonSerializer.Serialize(new { token }));
        using var claim = await host.ClaimAsync(token);
        using var unknownPage = await host.SendAsync(HttpMethod.Get, "/api/v1/nope");
        using var page = await host.SendAsync(HttpMethod.Get, "/bootstrap");
        Assert.Equal(await AdminHost.SnapshotAsync(unknown), await AdminHost.SnapshotAsync(claim));
        Assert.Equal(await AdminHost.SnapshotAsync(unknownPage), await AdminHost.SnapshotAsync(page));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin"));
    }

    private static string Wrong() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    /// <summary>The superuser holding the <c>bootstrap_state</c> row lock until disposed, as a slow claim would.</summary>
    private sealed class HeldLock : IAsyncDisposable
    {
        private readonly NpgsqlConnection _connection;
        private readonly NpgsqlTransaction _transaction;
        private readonly string _superuser;

        private HeldLock(NpgsqlConnection connection, NpgsqlTransaction transaction, string superuser)
        {
            _connection = connection;
            _transaction = transaction;
            _superuser = superuser;
        }

        public static async Task<HeldLock> TakeAsync(string superuser)
        {
            var connection = new NpgsqlConnection(superuser);
            await connection.OpenAsync(Cancellation);
            var transaction = await connection.BeginTransactionAsync(Cancellation);
            await using (var command = new NpgsqlCommand("SELECT 1 FROM bootstrap_state WHERE id = 1 FOR UPDATE", connection, transaction))
            {
                Assert.Equal(1, await command.ExecuteScalarAsync(Cancellation));
            }

            return new HeldLock(connection, transaction, superuser);
        }

        /// <summary>Waits until <paramref name="count"/> sessions on this database wait for a lock.</summary>
        public async Task WaitForWaitersAsync(int count)
        {
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
            while (true)
            {
                var waiting = await PostgresFixture.ScalarAsync<long>(
                    _superuser,
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'");
                if (waiting >= count)
                {
                    return;
                }

                Assert.True(DateTimeOffset.UtcNow < deadline, $"Only {waiting} of {count} claims waited for the lock.");
                await Task.Delay(TimeSpan.FromMilliseconds(100), Cancellation);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _transaction.RollbackAsync(CancellationToken.None);
            await _transaction.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }
}
