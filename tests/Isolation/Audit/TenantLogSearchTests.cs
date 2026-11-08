using System.Globalization;
using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Tests.Architecture;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// Story 7.4, FR-40, AD-9, UX-DR12: <c>GET /api/v1/tenants/{tenantId}/logs</c> on the real
/// <c>Host.Admin</c> and PostgreSQL. Every filter (event type, User by UUID or email, Application,
/// outcome, time range) narrows the path Tenant's own Log only, newest first, 50 a page, with a
/// cursor; anything malformed is 400 <c>invalid_request</c>; no detail column ever reaches a
/// response. A refused request from an Admin holding no role in an existing path Tenant also goes
/// on that Tenant's Log, within the Deployment write's cap, and an unknown or malformed Tenant gets
/// the Deployment Log's event only.
/// </summary>
public sealed class TenantLogSearchTests(PostgresFixture postgres)
{
    private const string Rejected = "admin.cross_tenant.rejected";

    private const string Denied = "admin.access.denied";

    private const string Email = "u2@example.test";

    private static readonly DateTimeOffset Start = new(2026, 11, 6, 9, 0, 0, TimeSpan.Zero);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Each_filter_narrows_the_path_Tenants_Log_only_newest_first()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        var user1 = Guid.CreateVersion7();
        var user2 = Guid.CreateVersion7();
        var client = Guid.CreateVersion7();
        var admin = Guid.CreateVersion7();

        // The same shapes in both Tenants: B's must never be listed in A's.
        var events = new Dictionary<string, Guid>();
        foreach (var (tenant, prefix) in new[] { (a, "a"), (b, "b") })
        {
            events[$"{prefix}1"] = await InsertEventAsync(host, tenant, 1, "sessions.session.started", "user", user1, "user", user1);
            events[$"{prefix}2"] = await InsertEventAsync(host, tenant, 2, Rejected, "admin", admin, "tenant", tenant);
            events[$"{prefix}3"] = await InsertEventAsync(host, tenant, 3, "operations.job.dead", "system", null, null, null);
            events[$"{prefix}4"] = await InsertEventAsync(host, tenant, 4, "authentication.signin_transaction.started", "anonymous", null, "client", client);
            events[$"{prefix}5"] = await InsertEventAsync(host, tenant, 5, "sessions.access.revoked", "admin", admin, "user", user2);
            events[$"{prefix}6"] = await InsertEventAsync(host, tenant, 6, "sessions.session.started", "user", user2, "user", user2, Email, "198.51.100.7", "Agent/1.0");
        }

        string[] Ids(params string[] names) => [.. names.Select(n => PublicId.Format(PublicIdType.AuditEvent, events[n]))];

        Assert.Equal(Ids("a6", "a5", "a4", "a3", "a2", "a1"), await IdsAsync(host, cookie, a, ""));
        Assert.Equal(Ids("a2"), await IdsAsync(host, cookie, a, $"?type={Rejected}"));
        Assert.Equal(Ids("a1"), await IdsAsync(host, cookie, a, $"?user={user1}"));
        Assert.Equal(Ids("a6", "a5"), await IdsAsync(host, cookie, a, $"?user={Uri.EscapeDataString(Email)}"));
        Assert.Empty(await IdsAsync(host, cookie, a, $"?user={Uri.EscapeDataString("nobody@example.test")}"));
        Assert.Equal(Ids("a4"), await IdsAsync(host, cookie, a, $"?application={client}"));
        Assert.Equal(Ids("a3", "a2"), await IdsAsync(host, cookie, a, "?outcome=failure"));
        Assert.Equal(Ids("a6", "a5", "a4", "a1"), await IdsAsync(host, cookie, a, "?outcome=success"));
        Assert.Equal(Ids("a3", "a2"), await IdsAsync(host, cookie, a, $"?from={Instant(2)}&to={Instant(4)}"));
        Assert.Equal(Ids("a2"), await IdsAsync(host, cookie, a, $"?outcome=failure&type={Rejected}&from={Instant(2)}"));
        Assert.Empty(await IdsAsync(host, cookie, a, $"?outcome=success&type={Rejected}"));
        Assert.Empty(await IdsAsync(host, cookie, a, "?type=tests.never.written"));

        // The envelope and the catalogue summary only: no detail column, no other Tenant's ID.
        using var all = await host.SendAsync(HttpMethod.Get, PathFor(a), cookie);
        var body = await all.Content.ReadAsStringAsync(Cancellation);
        Assert.Equal("no-store", all.Headers.CacheControl?.ToString());
        Assert.DoesNotContain(Email, body, StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.7", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Agent/1.0", body, StringComparison.Ordinal);
        Assert.DoesNotContain(b.ToString(), body, StringComparison.Ordinal);
        Assert.DoesNotContain(PublicId.Format(PublicIdType.Tenant, b), body, StringComparison.Ordinal);

        using var json = JsonDocument.Parse(body);
        Assert.Equal(["events", "nextCursor"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("nextCursor").ValueKind);
        var rejection = json.RootElement.GetProperty("events").EnumerateArray().Single(e => e.GetProperty("type").GetString() == Rejected);
        Assert.Equal(["id", "occurredAt", "type", "outcome", "summary", "actor", "target"], rejection.EnumerateObject().Select(p => p.Name));
        Assert.Equal("failure", rejection.GetProperty("outcome").GetString());
        Assert.Equal(Summary(Rejected), rejection.GetProperty("summary").GetString());
        Assert.Equal(Start.AddSeconds(2), rejection.GetProperty("occurredAt").GetDateTimeOffset());
        Assert.Equal("admin", rejection.GetProperty("actor").GetProperty("kind").GetString());
        Assert.Equal(admin.ToString("D"), rejection.GetProperty("actor").GetProperty("id").GetString());
        Assert.Equal("tenant", rejection.GetProperty("target").GetProperty("kind").GetString());
        Assert.Equal(PublicId.Format(PublicIdType.Tenant, a), rejection.GetProperty("target").GetProperty("id").GetString());
        var system = json.RootElement.GetProperty("events").EnumerateArray().Single(e => e.GetProperty("type").GetString() == "operations.job.dead");
        Assert.Equal(JsonValueKind.Null, system.GetProperty("actor").GetProperty("id").ValueKind);
        Assert.Equal(JsonValueKind.Null, system.GetProperty("target").ValueKind);

        // Nothing read is audited.
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}'"));
    }

    [Fact]
    public async Task Pages_hold_50_newest_first_and_the_last_has_no_cursor()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        // 120 events whose IDs, like UUIDv7s, sort as they were written.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO audit_event (tenant_id, id, occurred_at, type_code, actor_kind)
            SELECT '{a}', (lpad(to_hex(n), 8, '0') || '-0000-7000-8000-000000000000')::uuid,
                   timestamptz '{Start:O}' + n * interval '1 second', 'operations.job.dead', 'system'
            FROM generate_series(1, 120) AS n;
            SET session_replication_role = DEFAULT;
            """);

        var seen = new List<string>();
        var sizes = new List<int>();
        string? cursor = null;
        do
        {
            using var page = await host.SendAsync(HttpMethod.Get, PathFor(a) + (cursor is null ? "" : $"?cursor={cursor}"), cookie);
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            using var json = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation));
            var ids = json.RootElement.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("id").GetString()!).ToList();
            sizes.Add(ids.Count);
            seen.AddRange(ids);
            var next = json.RootElement.GetProperty("nextCursor");
            cursor = next.ValueKind == JsonValueKind.Null ? null : next.GetString();
            if (cursor is not null)
            {
                Assert.Equal(ids[^1], cursor);
            }
        }
        while (cursor is not null && sizes.Count < 5);

        Assert.Equal([50, 50, 20], sizes);
        Assert.Equal(120, seen.Distinct().Count());

        // Newest first across pages: IDs, which sort by time, descend.
        var guids = seen.Select(id => PublicId.TryParse(PublicIdType.AuditEvent, id, out var g) ? g : Guid.Empty).ToList();
        Assert.Equal(guids.OrderByDescending(g => g.ToString("N"), StringComparer.Ordinal), guids);
    }

    [Fact]
    public async Task A_filtered_search_pages_with_its_cursor_through_matching_events_only()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        // 120 events, IDs sorting as written: odd n are 60 failures, even n 60 successes.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO audit_event (tenant_id, id, occurred_at, type_code, actor_kind)
            SELECT '{a}', (lpad(to_hex(n), 8, '0') || '-0000-7000-8000-000000000000')::uuid,
                   timestamptz '{Start:O}' + n * interval '1 second',
                   CASE WHEN n % 2 = 1 THEN 'operations.job.dead' ELSE 'keys.signing_key.rotated' END, 'system'
            FROM generate_series(1, 120) AS n;
            SET session_replication_role = DEFAULT;
            """);

        async Task<(List<(Guid Id, string Type)> Events, string? Next)> ReadAsync(string query)
        {
            using var response = await host.SendAsync(HttpMethod.Get, PathFor(a) + query, cookie);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            var events = json.RootElement.GetProperty("events").EnumerateArray()
                .Select(e => (
                    PublicId.TryParse(PublicIdType.AuditEvent, e.GetProperty("id").GetString(), out var id) ? id : Guid.Empty,
                    e.GetProperty("type").GetString()!))
                .ToList();
            var next = json.RootElement.GetProperty("nextCursor");
            return (events, next.ValueKind == JsonValueKind.Null ? null : next.GetString());
        }

        var (first, cursor) = await ReadAsync("?outcome=failure");
        Assert.Equal(50, first.Count);
        Assert.All(first, e => Assert.Equal("operations.job.dead", e.Type));
        Assert.NotNull(cursor);

        var (second, last) = await ReadAsync($"?outcome=failure&cursor={cursor}");
        Assert.Equal(10, second.Count);
        Assert.All(second, e => Assert.Equal("operations.job.dead", e.Type));
        Assert.Null(last);

        // Strictly older than the first page's last event, newest first, and the 60 failures in all.
        var oldestFirstPage = first[^1].Id.ToString("N");
        Assert.All(second, e => Assert.True(string.CompareOrdinal(e.Id.ToString("N"), oldestFirstPage) < 0));
        var all = first.Concat(second).Select(e => e.Id.ToString("N")).ToList();
        Assert.Equal(all.OrderByDescending(id => id, StringComparer.Ordinal), all);
        Assert.Equal(60, all.Distinct().Count());
    }

    public static TheoryData<string> MalformedQueries() =>
    [
        "?type=Admin.Access.Denied",
        "?type=admin.denied",
        "?type=",
        $"?type={Denied}&type={Denied}",
        "?user=not-an-id",
        "?user=00000000-0000-0000-0000-000000000000",
        "?user=a@b@c",
        "?user=%7B7c9e6679-7425-40de-944b-e07fc1f90ae7%7D",
        "?application=a@b.test",
        "?application=7c9e6679742540de944be07fc1f90ae7",
        "?outcome=Failure",
        "?outcome=unknown",
        "?from=2026-11-06",
        "?from=2026-11-06T09:00:00",
        "?from=yesterday",
        $"?from={Instant(4)}&to={Instant(2)}",
        $"?from={Instant(2)}&to={Instant(2)}",
        "?cursor=evt_x",
        $"?cursor={PublicId.Format(PublicIdType.Tenant, Guid.Parse("01900000-0000-7000-8000-0000000007a8"))}",
        $"?cursor={PublicId.Format(PublicIdType.AuditEvent, Guid.Parse("01900000-0000-7000-8000-0000000007a8")).ToUpperInvariant()}",
    ];

    [Theory]
    [MemberData(nameof(MalformedQueries))]
    public async Task Malformed_filter_cursor_or_range_is_400_invalid_request(string query)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a) + query, cookie);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await TenantRequests.CodeAsync(response));
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        Assert.Contains("A Log search was refused with invalid_request", host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cross_Tenant_refusal_goes_on_the_refused_Tenants_Log_and_the_Deployment_Log()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, admin) = await TenantRequests.RoleSessionAsync(host, a, "owner");
        var (ownerCookie, _, _) = await TenantRequests.RoleSessionAsync(host, b, "owner");

        // Any Tenant route: the capabilities, the label and the Logs themselves.
        foreach (var path in new[] { $"/api/v1/tenants/{TenantRequests.Id(b)}/capabilities", TenantRequests.LabelPath(b), PathFor(b) })
        {
            using var refused = await host.SendAsync(HttpMethod.Get, path, cookie);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("access_denied", await TenantRequests.CodeAsync(refused));
        }

        Assert.Equal(3L, await TenantRequests.TenantEventsAsync(host, b, Rejected));
        Assert.Equal(0L, await TenantRequests.TenantEventsAsync(host, a, Rejected));
        Assert.Equal(
            $"3 admin {admin} tenant {b}",
            await host.ScalarAsync<string>(
                $"""
                SELECT count(*) || ' ' || min(actor_kind) || ' ' || min(actor_id::text) || ' ' || min(target_kind) || ' ' || min(target_id::text)
                FROM audit_event WHERE tenant_id = '{b}' AND type_code = '{Rejected}'
                """));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_detail WHERE tenant_id = '{b}'"));

        // The Deployment Log keeps its own event for each, unchanged.
        Assert.Equal(3L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}' AND target_id = '{b}'"));

        // B's Owner finds them in B's Log, with the Admin as Actor; A's Log holds none.
        using (var bLog = await host.SendAsync(HttpMethod.Get, PathFor(b) + $"?type={Rejected}", ownerCookie))
        {
            using var json = JsonDocument.Parse(await bLog.Content.ReadAsStringAsync(Cancellation));
            var listed = json.RootElement.GetProperty("events").EnumerateArray().ToList();
            Assert.Equal(3, listed.Count);
            Assert.All(listed, e => Assert.Equal(admin.ToString("D"), e.GetProperty("actor").GetProperty("id").GetString()));
        }

        Assert.Empty(await IdsAsync(host, cookie, a, $"?type={Rejected}"));
    }

    [Fact]
    public async Task Unknown_malformed_or_role_holding_refusals_write_no_Tenant_event()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, csrf, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        var unknown = Guid.CreateVersion7();

        using (var refusedUnknown = await host.SendAsync(HttpMethod.Get, PathFor(unknown), cookie))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refusedUnknown.StatusCode);
        }

        using (var refusedMalformed = await host.SendAsync(HttpMethod.Get, "/api/v1/tenants/ten_nope/logs", cookie))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refusedMalformed.StatusCode);
        }

        // A Viewer refused an Owner capability in their own Tenant isn't a cross-Tenant attempt.
        using (var refusedRole = await TenantRequests.SetLabelAsync(host, cookie, csrf, a, "staging", TenantRequests.Id(a)))
        {
            Assert.Equal(HttpStatusCode.Forbidden, refusedRole.StatusCode);
        }

        Assert.Equal(3L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Rejected}'"));
    }

    [Fact]
    public async Task Refusals_past_the_cap_write_neither_event()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, admin) = await TenantRequests.RoleSessionAsync(host, a, "owner");
        var cap = Gatekeep.Kernel.Limits.SecurityLimits.AdminAccessDeniedAuditAttempts;

        for (var i = 0; i <= cap; i++)
        {
            using var refused = await host.SendAsync(HttpMethod.Get, PathFor(b), cookie);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        }

        Assert.Equal((long)cap, await TenantRequests.TenantEventsAsync(host, b, Rejected));
        Assert.Equal((long)cap, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}' AND actor_id = '{admin}'"));
        Assert.Contains("refused with access_denied for tenant.logs.read, audited False", host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tenant_write_failure_is_503_and_rolls_back_the_Deployment_write()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, admin) = await TenantRequests.RoleSessionAsync(host, a, "owner");
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            CREATE FUNCTION test_fail_rejection() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN
              IF NEW.type_code = '{Rejected}' THEN
                RAISE EXCEPTION 'refused by the test';
              END IF;
              RETURN NEW;
            END
            $body$;
            CREATE TRIGGER test_fail_rejection BEFORE INSERT ON audit_event
              FOR EACH ROW EXECUTE FUNCTION test_fail_rejection();
            """);

        using (var failed = await host.SendAsync(HttpMethod.Get, PathFor(b), cookie))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
            Assert.Empty(await failed.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_attempt WHERE policy = 'admins.access.denial_audit'"));

        await PostgresFixture.ExecuteAsync(host.Superuser, "DROP TRIGGER test_fail_rejection ON audit_event");
        using (var again = await host.SendAsync(HttpMethod.Get, PathFor(b), cookie))
        {
            Assert.Equal(HttpStatusCode.Forbidden, again.StatusCode);
        }

        Assert.Equal(1L, await TenantRequests.TenantEventsAsync(host, b, Rejected));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}' AND actor_id = '{admin}'"));
    }

    [Fact]
    public async Task A_database_failure_on_the_read_is_503()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        await PostgresFixture.ExecuteAsync(host.Superuser, "REVOKE SELECT ON audit_event FROM gk_admin");

        using (var failed = await host.SendAsync(HttpMethod.Get, PathFor(a), cookie))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
            Assert.Empty(await failed.Content.ReadAsByteArrayAsync(Cancellation));
        }

        await PostgresFixture.ExecuteAsync(host.Superuser, "GRANT SELECT ON audit_event TO gk_admin");
        using var ok = await host.SendAsync(HttpMethod.Get, PathFor(a), cookie);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Theory]
    [InlineData("viewer")]
    [InlineData("editor")]
    [InlineData("owner")]
    public async Task Every_Tenant_Role_reads_the_same_envelope_view(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, role);
        await InsertEventAsync(host, a, 1, "sessions.session.started", "user", Guid.CreateVersion7(), null, null, Email, "198.51.100.7", "Agent/1.0");

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.Contains("sessions.session.started", body, StringComparison.Ordinal);
        Assert.DoesNotContain(Email, body, StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.7", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Every_catalogued_code_is_listed_with_its_catalogue_summary_and_outcome()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        var catalogue = Catalogue();
        Assert.InRange(catalogue.Count, 1, 50);
        for (var i = 0; i < catalogue.Count; i++)
        {
            await InsertEventAsync(host, a, i + 1, catalogue[i].Code, "system", null, null, null);
        }

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a), cookie);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var listed = json.RootElement.GetProperty("events").EnumerateArray()
            .ToDictionary(e => e.GetProperty("type").GetString()!, e => (Summary: e.GetProperty("summary").GetString(), Outcome: e.GetProperty("outcome").GetString()));

        Assert.Equal(catalogue.Select(e => e.Code).Order(StringComparer.Ordinal), listed.Keys.Order(StringComparer.Ordinal));
        Assert.All(catalogue, e => Assert.Equal((e.Summary, e.Outcome.ToLowerInvariant()), listed[e.Code]));

        // An outcome search is exactly the catalogue's codes of that outcome.
        foreach (var outcome in new[] { "Success", "Failure" })
        {
            using var filtered = await host.SendAsync(HttpMethod.Get, PathFor(a) + $"?outcome={outcome.ToLowerInvariant()}", cookie);
            using var page = JsonDocument.Parse(await filtered.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(
                catalogue.Where(e => e.Outcome == outcome).Select(e => e.Code).Order(StringComparer.Ordinal),
                page.RootElement.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("type").GetString()!).Order(StringComparer.Ordinal));
        }
    }

    private static IReadOnlyList<CatalogueEvent> Catalogue() => AuditCatalogue.Load(BuildOutput.RepositoryRoot(), "tests/Isolation");

    private static string Summary(string code) => Catalogue().Single(e => e.Code == code).Summary;

    private static string PathFor(Guid tenant) => $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, tenant)}/logs";

    /// <summary><see cref="Start"/> plus <paramref name="seconds"/>, as a query's instant.</summary>
    private static string Instant(int seconds) =>
        Uri.EscapeDataString(Start.AddSeconds(seconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));

    private static async Task<List<string>> IdsAsync(AdminHost host, string cookie, Guid tenant, string query)
    {
        using var response = await host.SendAsync(HttpMethod.Get, PathFor(tenant) + query, cookie);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{query} answered {(int)response.StatusCode}.");
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return [.. json.RootElement.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("id").GetString()!)];
    }

    /// <summary>
    /// An event at <see cref="Start"/> plus <paramref name="seconds"/>, with a UUIDv7 ID of that
    /// time, and detail when an email, address or agent is given. As the superuser with triggers
    /// off, since the insert guard stamps the current time.
    /// </summary>
    private static async Task<Guid> InsertEventAsync(
        AdminHost host,
        Guid tenant,
        int seconds,
        string code,
        string actorKind,
        Guid? actorId,
        string? targetKind,
        Guid? targetId,
        string? email = null,
        string? ip = null,
        string? userAgent = null)
    {
        var at = Start.AddSeconds(seconds);
        var id = Guid.CreateVersion7(at);
        static string Text(object? value) => value is null ? "NULL" : $"'{value}'";
        var checkpoint = code == "audit.retention.checkpoint" ? "1, 1, '\\x00'" : "NULL, NULL, NULL";
        var detail = email is null && ip is null && userAgent is null
            ? string.Empty
            : $"INSERT INTO audit_detail (tenant_id, event_id, ip_address, user_agent, email) VALUES ('{tenant}', '{id}', {Text(ip)}::inet, {Text(userAgent)}, {Text(email)});";
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO audit_event (tenant_id, id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, checkpoint_epoch, checkpoint_seq, checkpoint_hash)
            VALUES ('{tenant}', '{id}', '{at:O}', '{code}', '{actorKind}', {Text(actorId)}, {Text(targetKind)}, {Text(targetId)}, {checkpoint});
            {detail}
            SET session_replication_role = DEFAULT;
            """);
        return id;
    }
}
