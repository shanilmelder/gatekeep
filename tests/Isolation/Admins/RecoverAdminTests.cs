using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Cli;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.OffServer;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Admins.FreshAssertionTests;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.32: <c>gatekeep recover-admin</c> and its redemption, in process against PostgreSQL, the
/// AlertSink and, for the happy path, OpenBao and the MinIO Object Lock bucket. The Cli sends the
/// Security Alert, then writes the signed off-server record, then stores only the value's SHA-256
/// and prints the link once; any failure before the commit stores and prints nothing. Redemption
/// on the real <c>Host.Admin</c> is single use within 15 minutes, refuses an unknown, used or
/// expired value alike, ends every Session of the Admin as revoked, and starts a Session that
/// reaches only credential registration, so WebAuthn stays required.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class RecoverAdminTests(PostgresFixture postgres, OpenBaoFixture bao, ObjectLockFixture bucket) : IDisposable
{
    private const string Deployment = "admin.gatekeep-admin.test";
    private const string SessionPath = "/api/v1/deployment/session";
    private const string CapabilitiesPath = "/api/v1/deployment/capabilities";

    private static readonly Regex Link = new(
        @"^https://admin\.gatekeep-admin\.test/recover#(?<value>[A-Za-z0-9_-]{43})\r?$",
        RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex RecordKey = new(@"off-server record (?<key>records/admin_recovery/\S+\.json) written", RegexOptions.Compiled);

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-recover-admin-").FullName;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task Happy_path_alerts_then_records_then_stores_only_the_hash_and_prints_the_link_once()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (_, _, adminId, keys) = await host.OwnerWithCredentialsAsync();
        Array.ForEach(keys, k => k.Dispose());
        await using var sink = await AlertSinkFixture.StartAsync();
        using var cli = bao.Custody(OpenBaoFixture.Cli);
        using var store = bucket.Store();
        var steps = new List<string>();
        var rows = () => host.ScalarAsync<long>("SELECT count(*) FROM admin_enrolment");

        // Each step checks, as it happens, that the one before it was confirmed and nothing later happened yet.
        var alertHandler = new Watching(ObjectLockFixture.Permitted(), async () =>
        {
            Assert.Equal(0L, await rows());
            steps.Add("alert");
        });
        var watchedStore = new WatchingStore(store, async () =>
        {
            Assert.Single(sink.Requests);
            Assert.Equal(0L, await rows());
            steps.Add("record");
        });

        var run = await RecoverAsync(host, sink, cli, watchedStore, handler: alertHandler);

        Assert.True(run.Exit == 0, run.Error);
        Assert.Empty(run.Error);
        Assert.Equal(["alert", "record"], steps);
        var value = Assert.IsType<string>(run.Value);
        Assert.Single(Link.Matches(run.Output));
        Assert.Single(Regex.Matches(run.Output, Regex.Escape(value)));

        // One row, holding only the ID, the Admin, the SHA-256 and the times.
        Assert.Equal(
            "id,admin_id,value_sha256,created_at,expires_at,used_at",
            await host.ScalarAsync<string>(
                "SELECT string_agg(column_name, ',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_name = 'admin_enrolment'"));
        var row = await RowAsync(host);
        Assert.Equal(adminId, row.AdminId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Base64Url.DecodeFromChars(value))), row.Hash);
        Assert.Equal(TimeSpan.FromMinutes(15), row.ExpiresAt - row.CreatedAt);
        Assert.Null(row.UsedAt);
        Assert.Equal(7, row.Id.Version);
        Assert.Contains($"Enrolment {row.Id:D} for Admin {PublicId.Format(PublicIdType.Admin, adminId)}", run.Output, StringComparison.Ordinal);

        // The alert carries the Admin, the enrolment and its times, never the value or its hash.
        var request = Assert.Single(sink.Requests);
        var alert = JsonNode.Parse(request.Body)!.AsObject();
        Assert.Equal(
            ["adminId", "alertId", "code", "deployment", "enrolmentId", "expiresAt", "issuedAt", "raisedAt", "summary"],
            alert.Select(m => m.Key).Order(StringComparer.Ordinal));
        Assert.Equal("admin.recovery.started", (string?)alert["code"]);
        Assert.Equal(SecurityAlertCode.AdminRecovery.Summary, (string?)alert["summary"]);
        Assert.Equal(Deployment, (string?)alert["deployment"]);
        Assert.Equal(adminId.ToString("D"), (string?)alert["adminId"]);
        Assert.Equal(row.Id.ToString("D"), (string?)alert["enrolmentId"]);
        Assert.Equal(Timestamp(row.CreatedAt), (string?)alert["issuedAt"]);
        Assert.Equal(Timestamp(row.ExpiresAt), (string?)alert["expiresAt"]);
        Assert.Contains($"Security Alert {(string?)alert["alertId"]} delivered", run.Output, StringComparison.Ordinal);
        AssertAbsent(request.Text, value, row.Hash);

        // The record, signed with dep-records by the cli AppRole, in compliance mode, with the same references.
        var key = RecordKey.Match(run.Output).Groups["key"].Value;
        var version = Assert.Single(await bucket.VersionsAsync(key));
        Assert.Equal("COMPLIANCE", (await bucket.LockAsync(version)).Mode);
        var content = await bucket.ReadAsync(version);
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            Assert.True(await OffServerRecords.VerifyAsync(worker, Encoding.UTF8.GetBytes(content), Cancellation));
        }

        var record = JsonNode.Parse(content)!.AsObject();
        Assert.Equal(RecoverAdminCommand.RecordKind, (string?)record["kind"]);
        var payload = record["payload"]!.AsObject();
        Assert.Equal(["adminId", "enrolmentId", "expiresAt", "issuedAt"], payload.Select(m => m.Key).Order(StringComparer.Ordinal));
        Assert.Equal(adminId.ToString("D"), (string?)payload["adminId"]);
        Assert.Equal(row.Id.ToString("D"), (string?)payload["enrolmentId"]);
        Assert.Equal(Timestamp(row.CreatedAt), (string?)payload["issuedAt"]);
        Assert.Equal(Timestamp(row.ExpiresAt), (string?)payload["expiresAt"]);
        AssertAbsent(content, value, row.Hash);

        // The issue event: System, targeting the Admin.
        Assert.Equal(
            $"system  admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || coalesce(actor_id::text, '') || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.enrolment.issued'"));
    }

    public static TheoryData<int?> RefusedAlerts => new() { 500, 401, (int?)null };

    [Theory]
    [MemberData(nameof(RefusedAlerts))]
    public async Task A_refused_or_unreachable_alert_writes_no_record_stores_nothing_and_prints_nothing(int? status)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var sink = await AlertSinkFixture.StartAsync();
        var custody = new SigningCustody();
        var store = new MemoryStore();
        if (status is { } code)
        {
            sink.Status = code;
        }
        else
        {
            // Nothing listens there any more.
            await sink.DisposeAsync();
        }

        var run = await RecoverAsync(host, sink, custody, store);

        Assert.Equal(1, run.Exit);
        Assert.Empty(run.Output);
        Assert.Equal(status is null ? RecoverAdminCommand.AlertUnavailable : RecoverAdminCommand.AlertRejected, run.Error.Trim());
        Assert.Contains("Alert channel", run.Error, StringComparison.Ordinal);
        Assert.Empty(custody.Signed);
        Assert.Empty(store.Puts);
        await AssertNothingIssuedAsync(host);
        if (status is not null)
        {
            Assert.Single(sink.Requests);
            await sink.DisposeAsync();
        }
    }

    [Fact]
    public async Task A_refused_record_or_a_failed_signing_stores_nothing_and_prints_nothing_after_the_alert()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();

        foreach (var (custody, store, message) in new (SigningCustody, MemoryStore, string)[]
        {
            (new SigningCustody(), new MemoryStore { Fails = OffServerStoreFailure.Rejected }, RecoverAdminCommand.RecordRejected),
            (new SigningCustody(), new MemoryStore { Fails = OffServerStoreFailure.Unavailable }, RecoverAdminCommand.RecordUnavailable),
            (new SigningCustody { Fails = KeyCustodyFailure.Refused }, new MemoryStore(),
                "Key custody failed (Refused), so the off-server record wasn't signed or written. No enrolment was issued. The Security Alert was already sent."),
        })
        {
            await using var sink = await AlertSinkFixture.StartAsync();

            var run = await RecoverAsync(host, sink, custody, store);

            Assert.Equal(1, run.Exit);
            Assert.Empty(run.Output);
            Assert.Equal(message, run.Error.Trim());
            // The alert went out first, which is acceptable: it is a false alarm, and no access was issued.
            Assert.Single(sink.Requests);
            Assert.Empty(store.Puts);
            await AssertNothingIssuedAsync(host);
        }
    }

    [Fact]
    public async Task A_record_refused_by_the_real_bucket_stores_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        await using var sink = await AlertSinkFixture.StartAsync();
        using var cli = bao.Custody(OpenBaoFixture.Cli);
        var wrongSecret = Path.Combine(_directory, "wrong-secret");
        await System.IO.File.WriteAllTextAsync(wrongSecret, "wrong" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)), Cancellation);
        using var store = new Gatekeep.Adapters.ObjectLock.S3ObjectLockStore(
            ObjectLockFixture.Permitted(), bucket.Options(secretAccessKeyFile: wrongSecret), TimeProvider.System);

        var run = await RecoverAsync(host, sink, cli, store);

        Assert.Equal(1, run.Exit);
        Assert.Empty(run.Output);
        Assert.Equal(RecoverAdminCommand.RecordRejected, run.Error.Trim());
        await AssertNothingIssuedAsync(host);
    }

    [Fact]
    public async Task With_two_Admins_and_no_choice_it_refuses_listing_their_public_IDs_and_sends_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (_, _, owner) = await host.ClaimedAsync();
        var (_, _, other) = await host.InsertSetupAdminAsync();
        await using var sink = await AlertSinkFixture.StartAsync();
        var ids = new[] { PublicId.Format(PublicIdType.Admin, owner), PublicId.Format(PublicIdType.Admin, other) };

        foreach (var named in new string?[] { null, "adm_" + new string('a', 26), "ten_" + new string('a', 26), "not an id" })
        {
            var run = await RecoverAsync(host, sink, new SigningCustody(), new MemoryStore(), admin: named);

            Assert.Equal(1, run.Exit);
            Assert.Empty(run.Output);
            Assert.All(ids, id => Assert.Contains(id, run.Error, StringComparison.Ordinal));
            Assert.EndsWith("Nothing was issued.", run.Error.Trim(), StringComparison.Ordinal);
            Assert.Empty(sink.Requests);
            await AssertNothingIssuedAsync(host);
        }

        // Naming one issues it for that Admin only.
        var chosen = await RecoverAsync(host, sink, new SigningCustody(), new MemoryStore(), admin: ids[1]);
        Assert.True(chosen.Exit == 0, chosen.Error);
        Assert.Equal(other, (await RowAsync(host)).AdminId);
    }

    [Fact]
    public async Task Before_bootstrap_completes_it_refuses_pointing_to_init_and_sends_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.IssueTokenAsync();
        await using var sink = await AlertSinkFixture.StartAsync();

        var run = await RecoverAsync(host, sink, new SigningCustody(), new MemoryStore());

        Assert.Equal(1, run.Exit);
        Assert.Empty(run.Output);
        Assert.Equal(RecoverAdminCommand.NoAdmin, run.Error.Trim());
        Assert.Contains("gatekeep init", run.Error, StringComparison.Ordinal);
        Assert.Empty(sink.Requests);
        await AssertNothingIssuedAsync(host);

        // And its redemption route isn't there yet: the unknown-path 404.
        using var missing = await host.RedeemEnrolmentAsync(AdminHost.Unissued());
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task Redeem_ends_every_Session_starts_a_recovery_Session_once_and_one_registration_makes_it_full()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, adminId, keys) = await host.OwnerWithCredentialsAsync();
        Array.ForEach(keys, k => k.Dispose());
        var live = await host.ScalarAsync<long>($"SELECT count(*) FROM admin_session WHERE admin_id = '{adminId}' AND ended_at IS NULL");
        Assert.Equal(2L, live);
        var value = await IssuedAsync(host);

        using var redeemed = await host.RedeemEnrolmentAsync(value, session: cookie);

        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        var recovery = AdminHost.CookieValue(redeemed, AdminHost.Cookie)!;
        string csrf;
        using (var json = JsonDocument.Parse(await redeemed.Content.ReadAsStringAsync(Cancellation)))
        {
            Assert.Equal(adminId, json.RootElement.GetProperty("adminId").GetGuid());
            Assert.True(json.RootElement.GetProperty("setupComplete").GetBoolean());
            csrf = json.RootElement.GetProperty("csrfToken").GetString()!;
        }

        Assert.Equal(AdminHost.Csrf(recovery), csrf);
        Assert.Equal("recovery", (await SessionAsync(host, recovery)).GetProperty("kind").GetString());
        using (var old = await host.SendAsync(HttpMethod.Get, SessionPath, cookie))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
        }

        // Every prior Session ended as revoked, each with its event, and the enrolment is used up.
        Assert.Equal(
            "revoked,revoked",
            await host.ScalarAsync<string>(
                $"SELECT string_agg(end_reason, ',') FROM admin_session WHERE admin_id = '{adminId}' AND kind <> 'recovery'"));
        Assert.Equal(live, await CountAsync(host, "admin.session.revoked"));
        Assert.Equal(1L, await CountAsync(host, "admin.enrolment.used"));
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.enrolment.used'"));
        Assert.NotNull((await RowAsync(host)).UsedAt);

        // WebAuthn stays required: the recovery Session reaches only registration.
        foreach (var (method, path) in new[] { (HttpMethod.Get, CapabilitiesPath), (HttpMethod.Get, AdminHost.CredentialsPath), (HttpMethod.Post, AdminHost.AssertionsPath) })
        {
            using var refused = await host.SendAsync(method, path, recovery, csrf, AdminHost.Origin);
            Assert.True(refused.StatusCode == HttpStatusCode.Forbidden, $"{method} {path} answered {(int)refused.StatusCode}.");
        }

        using var fresh = new SoftwareAuthenticator();
        await host.RegisterAsync(recovery, csrf, fresh);
        Assert.Equal("full", (await SessionAsync(host, recovery)).GetProperty("kind").GetString());
        using (var capabilities = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, recovery))
        {
            Assert.Equal(HttpStatusCode.OK, capabilities.StatusCode);
        }

        // The new credential signs in.
        await host.SignInAsync(fresh);
    }

    [Fact]
    public async Task A_first_Admin_who_lost_their_setup_Session_gets_a_setup_Session_that_two_registrations_complete()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, adminId) = await host.ClaimedAsync();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"UPDATE admin_session SET ended_at = clock_timestamp(), end_reason = 'expired' WHERE admin_id = '{adminId}'");
        using (var lost = await host.SendAsync(HttpMethod.Get, SessionPath, cookie))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, lost.StatusCode);
        }

        var value = await IssuedAsync(host);
        using var redeemed = await host.RedeemEnrolmentAsync(value);

        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        var setup = AdminHost.CookieValue(redeemed, AdminHost.Cookie)!;
        var csrf = AdminHost.Csrf(setup);
        using (var json = JsonDocument.Parse(await redeemed.Content.ReadAsStringAsync(Cancellation)))
        {
            Assert.False(json.RootElement.GetProperty("setupComplete").GetBoolean());
        }

        Assert.Equal("setup", (await SessionAsync(host, setup)).GetProperty("kind").GetString());
        // The ended Session was already over, so nothing was revoked.
        Assert.Equal(0L, await CountAsync(host, "admin.session.revoked"));

        using var first = new SoftwareAuthenticator();
        using var second = new SoftwareAuthenticator();
        await host.RegisterAsync(setup, csrf, first);
        Assert.Equal("setup", (await SessionAsync(host, setup)).GetProperty("kind").GetString());
        using (var refused = await host.SendAsync(HttpMethod.Get, CapabilitiesPath, setup))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        await host.RegisterAsync(setup, csrf, second);
        var session = await SessionAsync(host, setup);
        Assert.Equal("full", session.GetProperty("kind").GetString());
        Assert.True(session.GetProperty("setupComplete").GetBoolean());
        Assert.Equal(1L, await CountAsync(host, "admin.setup.completed"));
    }

    [Fact]
    public async Task A_used_expired_unknown_or_malformed_value_gets_the_same_refusal_and_no_Session()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();

        var used = await IssuedAsync(host);
        using (var first = await host.RedeemEnrolmentAsync(used))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var expired = await IssuedAsync(host);
        // Past its 15 minutes: only the owner, with the guard set aside, can move the times.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            UPDATE admin_enrolment SET created_at = created_at - interval '16 minutes', expires_at = expires_at - interval '16 minutes'
            WHERE value_sha256 = '\x{Convert.ToHexStringLower(SHA256.HashData(Base64Url.DecodeFromChars(expired)))}';
            SET session_replication_role = DEFAULT;
            """);
        var events = await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");
        var sessions = await host.ScalarAsync<long>("SELECT count(*) FROM admin_session");

        var refusals = new List<string>();
        foreach (var value in new[]
        {
            used,
            expired,
            AdminHost.Unissued(),
            used[..42],
            used + "A",
            used[..42] + "!",
            // The same 32 bytes, spelled with the last character's unused bits set.
            NonCanonical(used),
        })
        {
            // Counted per client, five in 15 minutes: each refusal here starts a fresh window.
            await ResetAttemptsAsync(host);
            using var refused = await host.RedeemEnrolmentAsync(value);
            await AssertProblemAsync(refused, HttpStatusCode.BadRequest, "enrolment_refused");
            Assert.Null(AdminHost.CookieValue(refused, AdminHost.Cookie));
            refusals.Add(await ShapeAsync(refused));
        }

        foreach (var body in new[] { """{"other":1}""", "not json", """{"enrolment":42}""" })
        {
            await ResetAttemptsAsync(host);
            using var refused = await host.SendAsync(HttpMethod.Post, AdminHost.EnrolmentPath, origin: AdminHost.Origin, body: body);
            await AssertProblemAsync(refused, HttpStatusCode.BadRequest, "enrolment_refused");
            refusals.Add(await ShapeAsync(refused));
        }

        Assert.Single(refusals.Distinct(StringComparer.Ordinal));
        Assert.Equal(events, await host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        Assert.Equal(sessions, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session"));
        Assert.True(await host.ScalarAsync<bool>(
            $"SELECT used_at IS NULL FROM admin_enrolment WHERE value_sha256 = '\\x{Convert.ToHexStringLower(SHA256.HashData(Base64Url.DecodeFromChars(expired)))}'"));
    }

    [Fact]
    public async Task Sixth_redeem_from_one_client_in_15_minutes_is_429_before_the_value_is_looked_up()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var value = await IssuedAsync(host);

        for (var i = 0; i < 5; i++)
        {
            using var wrong = await host.RedeemEnrolmentAsync(AdminHost.Unissued());
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }

        using var limited = await host.RedeemEnrolmentAsync(value);
        await AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.True(int.Parse(limited.Headers.GetValues("Retry-After").Single(), System.Globalization.CultureInfo.InvariantCulture) >= 1);
        Assert.Null((await RowAsync(host)).UsedAt);
        Assert.Equal(6, await host.ScalarAsync<int>("SELECT attempts FROM admin_attempt WHERE policy = 'admins.enrolment.redeem'"));
        // The client is counted first: past its own 5 it spends none of the Deployment's 50.
        Assert.Equal(5, await host.ScalarAsync<int>("SELECT attempts FROM admin_attempt WHERE policy = 'admins.enrolment.deployment'"));
    }

    [Fact]
    public async Task Past_the_Deployment_wide_limit_every_redeem_is_429_before_the_value_is_looked_up()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var value = await IssuedAsync(host);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "INSERT INTO admin_attempt (policy, subject_hash, window_start, attempts) VALUES ('admins.enrolment.deployment', sha256(convert_to('deployment', 'UTF8')), now(), 50)");

        using var limited = await host.RedeemEnrolmentAsync(value);

        await AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.Null((await RowAsync(host)).UsedAt);
        Assert.Equal(1, await host.ScalarAsync<int>("SELECT attempts FROM admin_attempt WHERE policy = 'admins.enrolment.redeem'"));
        Assert.Equal(51, await host.ScalarAsync<int>("SELECT attempts FROM admin_attempt WHERE policy = 'admins.enrolment.deployment'"));
    }

    [Fact]
    public async Task Redeeming_one_enrolment_uses_up_the_Admins_other_unused_ones()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        var earlier = await IssuedAsync(host);
        var later = await IssuedAsync(host);

        using (var redeemed = await host.RedeemEnrolmentAsync(later))
        {
            Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        }

        // The leftover link from the earlier run can't run recovery again.
        using var leftover = await host.RedeemEnrolmentAsync(earlier);
        await AssertProblemAsync(leftover, HttpStatusCode.BadRequest, "enrolment_refused");
        Assert.Null(AdminHost.CookieValue(leftover, AdminHost.Cookie));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_enrolment WHERE used_at IS NULL"));
        Assert.Equal(1L, await CountAsync(host, "admin.enrolment.used"));
    }

    [Fact]
    public async Task Another_Admins_live_Session_presented_at_redeem_is_superseded()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (_, _, owner) = await host.ClaimedAsync();
        var (otherCookie, _, other) = await host.InsertSetupAdminAsync();
        var value = await IssuedAsync(host, PublicId.Format(PublicIdType.Admin, owner));

        using var redeemed = await host.RedeemEnrolmentAsync(value, session: otherCookie);

        Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        Assert.Equal("superseded", await host.ScalarAsync<string>($"SELECT end_reason FROM admin_session WHERE admin_id = '{other}'"));
        Assert.Equal(
            $"admin {owner} admin {other}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.session.superseded'"));
        using var stale = await host.SendAsync(HttpMethod.Get, SessionPath, otherCookie);
        Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
    }

    [Fact]
    public async Task A_database_failure_after_the_record_says_the_alert_and_the_record_already_went_out()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.ClaimedAsync();
        // The store, step 5, refuses the Cli: the alert and the record are already out.
        await PostgresFixture.ExecuteAsync(host.Superuser, "REVOKE INSERT ON admin_enrolment FROM gk_cli");
        await using var sink = await AlertSinkFixture.StartAsync();
        var store = new MemoryStore();

        var run = await RecoverAsync(host, sink, new SigningCustody(), store);

        Assert.Equal(1, run.Exit);
        Assert.Empty(run.Output);
        Assert.Equal(
            $"Recover-admin failed: PostgresException 42501. No enrolment was issued. {RecoverAdminCommand.AlertSent} {RecoverAdminCommand.RecordWritten}",
            run.Error.Trim());
        Assert.Single(sink.Requests);
        Assert.Single(store.Puts);
        await AssertNothingIssuedAsync(host);
    }

    [Fact]
    public async Task The_value_is_in_no_audit_table_log_alert_record_or_error()
    {
        await using var host = await AdminHost.StartAsync(postgres, null, "--Logging:LogLevel:Default=Trace", "--Logging:LogLevel:Microsoft=Trace");
        var (cookie, _, _) = await host.ClaimedAsync();
        await using var sink = await AlertSinkFixture.StartAsync();
        var store = new MemoryStore();

        var run = await RecoverAsync(host, sink, new SigningCustody(), store);
        Assert.True(run.Exit == 0, run.Error);
        var value = run.Value!;
        var hash = Convert.ToHexStringLower(SHA256.HashData(Base64Url.DecodeFromChars(value)));

        using (var redeemed = await host.RedeemEnrolmentAsync(value, session: cookie))
        {
            Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
            AssertAbsent(await redeemed.Content.ReadAsStringAsync(Cancellation), value, hash);
        }

        using (var again = await host.RedeemEnrolmentAsync(value))
        {
            AssertAbsent(await AdminHost.SnapshotAsync(again), value, hash);
        }

        // Every Deployment audit table, row by row as text.
        var tables = new List<string>();
        await using (var connection = new NpgsqlConnection(host.Superuser))
        {
            await connection.OpenAsync(Cancellation);
            await using var list = new NpgsqlCommand(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'deployment_audit%'",
                connection);
            await using (var reader = await list.ExecuteReaderAsync(Cancellation))
            {
                while (await reader.ReadAsync(Cancellation))
                {
                    tables.Add(reader.GetString(0));
                }
            }

            Assert.NotEmpty(tables);
            foreach (var table in tables)
            {
                await using var dump = new NpgsqlCommand($"SELECT coalesce(string_agg(t::text, E'\\n'), '') FROM {table} AS t", connection);
                AssertAbsent((string)(await dump.ExecuteScalarAsync(Cancellation))!, value, hash);
            }
        }

        Assert.Contains(tables, t => t == "deployment_audit_event");
        Assert.Equal(1L, await CountAsync(host, "admin.enrolment.issued"));
        Assert.Equal(1L, await CountAsync(host, "admin.enrolment.used"));

        await host.StopAsync();
        Assert.Matches(@"""LogLevel"":""(?:Trace|Debug)""", host.Output);
        AssertAbsent(host.Output, value, hash);
        AssertAbsent(Assert.Single(sink.Requests).Text, value, hash);
        AssertAbsent(Encoding.UTF8.GetString(Assert.Single(store.Puts).Content), value, hash);
        AssertAbsent(run.Error, value, hash);
    }

    [Fact]
    public async Task As_a_process_it_refuses_every_missing_setting_by_name_and_prints_no_link()
    {
        var environment = new Dictionary<string, string>
        {
            ["GATEKEEP_CLI_CONNECTION_FILE"] = File(new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Cli, "gatekeep")) { Password = null }.ConnectionString),
            ["GATEKEEP_CLI_PASSWORD_FILE"] = File(PostgresFixture.Password + "\n"),
        };

        var result = await CliProcess.RunCapturedAsync(environment, "recover-admin");

        Assert.Equal(1, result.ExitCode);
        Assert.Empty(result.StandardOutput);
        foreach (var variable in new[]
        {
            OffServerSettings.AlertUrlVariable,
            OffServerSettings.AlertTokenFileVariable,
            OffServerSettings.AlertDeploymentVariable,
            OffServerSettings.RecordsEndpointVariable,
            OffServerSettings.RecordsBucketVariable,
            "GATEKEEP_CUSTODY_SOCKET",
        })
        {
            Assert.Contains(variable, result.StandardError, StringComparison.Ordinal);
        }

        Assert.Contains("Nothing was sent or issued.", result.StandardError, StringComparison.Ordinal);

        // --admin needs its ID.
        var usage = await CliProcess.RunCapturedAsync(environment, "recover-admin", "--admin");
        Assert.Equal(2, usage.ExitCode);
        Assert.Contains("gatekeep recover-admin [--admin <public Admin ID>]", usage.StandardError, StringComparison.Ordinal);
    }

    private sealed record Run(int Exit, string Output, string Error, string? Value);

    private sealed record Row(Guid Id, Guid AdminId, string Hash, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? UsedAt);

    /// <summary>Runs the Cli's core as <c>gk_cli</c> on the host's database, alerting <paramref name="sink"/>.</summary>
    private async Task<Run> RecoverAsync(
        AdminHost host,
        AlertSinkFixture sink,
        IKeyCustody custody,
        IOffServerStore store,
        string? admin = null,
        HttpMessageHandler? handler = null)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = await RecoverAdminCommand.RunAsync(
            new RecoverAdminOptions
            {
                ConnectionString = postgres.RoleConnection(TableRegistry.Cli, host.Database),
                Admin = admin,
                Alerts = new WebhookAlertOptions { Url = sink.Url, TokenFile = File("token-" + Guid.NewGuid().ToString("N")) },
            },
            new AlertDeployment(Deployment),
            handler ?? ObjectLockFixture.Permitted(),
            custody,
            store,
            TimeProvider.System,
            output,
            error,
            Cancellation);

        var text = output.ToString();
        var link = Link.Match(text);
        return new Run(exit, text, error.ToString(), link.Success ? link.Groups["value"].Value : null);
    }

    /// <summary>A fresh enrolment for the Deployment's only Admin, through the Cli's core with stand-ins, and its value.</summary>
    private async Task<string> IssuedAsync(AdminHost host, string? admin = null)
    {
        await using var sink = await AlertSinkFixture.StartAsync();
        var run = await RecoverAsync(host, sink, new SigningCustody(), new MemoryStore(), admin);
        Assert.True(run.Exit == 0, run.Error);
        return run.Value!;
    }

    private static async Task<Row> RowAsync(AdminHost host)
    {
        await using var connection = new NpgsqlConnection(host.Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT id, admin_id, encode(value_sha256, 'hex'), created_at, expires_at, used_at FROM admin_enrolment ORDER BY created_at DESC LIMIT 1",
            connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        Assert.True(await reader.ReadAsync(Cancellation));
        return new Row(
            reader.GetGuid(0),
            reader.GetGuid(1),
            reader.GetString(2),
            reader.GetFieldValue<DateTimeOffset>(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5));
    }

    private static Task ResetAttemptsAsync(AdminHost host) => PostgresFixture.ExecuteAsync(host.Superuser, "DELETE FROM admin_attempt");

    private static async Task AssertNothingIssuedAsync(AdminHost host)
    {
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_enrolment"));
        Assert.Equal(0L, await CountAsync(host, "admin.enrolment.issued"));
    }

    /// <summary>A refusal as a client could compare it: status, headers but Date, and the body's members but the trace ID.</summary>
    private static async Task<string> ShapeAsync(HttpResponseMessage response)
    {
        var headers = response.Headers.Concat(response.Content.Headers)
            .Where(h => h.Key is not "Date" and not "Content-Length")
            .Select(h => $"{h.Key.ToLowerInvariant()}: {string.Join(", ", h.Value)}")
            .Order(StringComparer.Ordinal);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Cancellation))!.AsObject();
        body.Remove("traceId");
        return $"{(int)response.StatusCode}\n{string.Join("\n", headers)}\n{body.ToJsonString()}";
    }

    /// <summary>The value, its SHA-256 as hex and as base64, each absent from <paramref name="text"/>.</summary>
    private static void AssertAbsent(string text, string value, string hashHex)
    {
        var hash = Convert.FromHexString(hashHex);
        foreach (var form in new[] { value, hashHex, Convert.ToBase64String(hash), Base64Url.EncodeToString(hash), Convert.ToHexString(hash) })
        {
            Assert.DoesNotContain(form, text, StringComparison.Ordinal);
        }
    }

    /// <summary>The same 32 bytes as <paramref name="value"/>, with the last character's two unused bits set.</summary>
    private static string NonCanonical(string value)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var last = Alphabet.IndexOf(value[^1], StringComparison.Ordinal);
        return value[..^1] + Alphabet[(last & ~0b11) | 0b01];
    }

    private static string Timestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private string File(string contents)
    {
        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        System.IO.File.WriteAllText(path, contents);
        return path;
    }

    private static async Task<JsonElement> SessionAsync(AdminHost host, string cookie)
    {
        using var response = await host.SendAsync(HttpMethod.Get, SessionPath, cookie);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)).RootElement.Clone();
    }

    /// <summary>Runs <paramref name="before"/> as each request starts, then sends it on.</summary>
    private sealed class Watching(HttpMessageHandler inner, Func<Task> before) : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await before();
            return await base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>Runs <paramref name="before"/> as each write starts, then writes it.</summary>
    private sealed class WatchingStore(IOffServerStore inner, Func<Task> before) : IOffServerStore
    {
        public async Task PutAsync(string key, ReadOnlyMemory<byte> content, string contentType, CancellationToken cancellationToken)
        {
            await before();
            await inner.PutAsync(key, content, contentType, cancellationToken);
        }
    }
}
