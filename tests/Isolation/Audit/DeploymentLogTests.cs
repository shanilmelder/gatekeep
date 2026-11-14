using System.Globalization;
using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// Story 7.7, FR-40: <c>GET /api/v1/deployment/logs</c> and <c>GET /api/v1/deployment/logs/{eventId}</c>
/// on the real <c>Host.Admin</c> and PostgreSQL. The Deployment Owner searches the Deployment Log by
/// event type, Admin, Tenant, outcome and time range, newest first, 50 a page, and opens any event
/// with its raw envelope, seal and detail. Bootstrap, Admin sign-in, recovery and Tenant events come
/// from their real flows; the upgrade, restore and configuration classes, not built yet, are
/// fixture rows. Any other Admin is 403 and audited, no Session is 401, a machine principal is
/// never allowed, and nothing read is audited.
/// </summary>
public sealed class DeploymentLogTests(PostgresFixture postgres)
{
    private const string LogsPath = "/api/v1/deployment/logs";

    private const string Denied = "admin.access.denied";

    /// <summary>Deployment classes no story writes yet (Epics 8 and 12): their codes are no catalogue's.</summary>
    private static readonly string[] FixtureCodes = ["deployment.upgrade.completed", "deployment.restore.completed", "deployment.configuration.changed"];

    private const string Email = "owner-detail@example.test";

    private const string Ip = "203.0.113.77";

    private const string UserAgent = "DeploymentAgent/7.7";

    private static readonly string PrevHash = string.Concat(Enumerable.Repeat("c3", 32));

    private static readonly string Hash = string.Concat(Enumerable.Repeat("d4", 32));

    private static readonly DateTimeOffset Start = new(2026, 11, 14, 8, 0, 0, TimeSpan.Zero);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Every_Deployment_class_is_found_by_its_type_and_the_unfiltered_list_has_them_all_newest_first()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var seeded = await SeedAsync(host);
        foreach (var code in FixtureCodes)
        {
            await InsertEventAsync(host, Guid.CreateVersion7(), code, "system", null, null, null);
        }

        string[] classes =
        [
            "bootstrap.token.issued",
            "bootstrap.admin.created",
            "admin.signin.succeeded",
            "admin.recovery_code.used",
            "tenancy.tenant.created",
            .. FixtureCodes,
        ];

        var all = await EventsAsync(host, seeded.Cookie, "");
        foreach (var code in classes)
        {
            var found = await EventsAsync(host, seeded.Cookie, $"?type={code}");
            Assert.NotEmpty(found);
            Assert.All(found, e => Assert.Equal(code, e.GetProperty("type").GetString()));
            Assert.Contains(all, e => e.GetProperty("type").GetString() == code);
        }

        // Newest first: IDs, UUIDv7s, descend.
        var ids = all.Select(e => EventId(e).ToString("N")).ToList();
        Assert.Equal(ids.OrderByDescending(id => id, StringComparer.Ordinal), ids);

        // A catalogued code has its summary and outcome; a code no catalogue declares is still listed, with neither.
        var created = all.First(e => e.GetProperty("type").GetString() == "bootstrap.admin.created");
        Assert.Equal("success", created.GetProperty("outcome").GetString());
        Assert.False(string.IsNullOrEmpty(created.GetProperty("summary").GetString()));
        foreach (var code in FixtureCodes)
        {
            var fixture = all.Single(e => e.GetProperty("type").GetString() == code);
            Assert.Equal(JsonValueKind.Null, fixture.GetProperty("summary").ValueKind);
            Assert.Equal(JsonValueKind.Null, fixture.GetProperty("outcome").ValueKind);
        }

        // The same envelope shape as a Tenant's Log, and the Tenant target as its ten_ ID.
        var tenantEvent = all.Single(e => e.GetProperty("type").GetString() == "tenancy.tenant.created");
        Assert.Equal(["id", "occurredAt", "type", "outcome", "summary", "actor", "target"], tenantEvent.EnumerateObject().Select(p => p.Name));
        Assert.Equal("admin", tenantEvent.GetProperty("actor").GetProperty("kind").GetString());
        Assert.Equal(seeded.Owner.ToString("D"), tenantEvent.GetProperty("actor").GetProperty("id").GetString());
        Assert.Equal("tenant", tenantEvent.GetProperty("target").GetProperty("kind").GetString());
        Assert.Equal(PublicId.Format(PublicIdType.Tenant, seeded.Tenant), tenantEvent.GetProperty("target").GetProperty("id").GetString());
    }

    [Fact]
    public async Task The_Admin_filter_matches_events_whose_Actor_or_target_is_that_Admin()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var seeded = await SeedAsync(host);

        var owners = await EventsAsync(host, seeded.Cookie, $"?admin={seeded.Owner}");
        Assert.NotEmpty(owners);
        Assert.All(owners, e => Assert.True(Names(e, "admin", seeded.Owner.ToString("D")), e.GetProperty("type").GetString()));
        Assert.Contains(owners, e => e.GetProperty("type").GetString() == "tenancy.tenant.created");
        Assert.DoesNotContain(owners, e => e.GetProperty("type").GetString() == "admin.recovery_code.used");

        var recovered = await EventsAsync(host, seeded.Cookie, $"?admin={seeded.Recovered}");
        Assert.Contains(recovered, e => e.GetProperty("type").GetString() == "admin.recovery_code.used");
        Assert.All(recovered, e => Assert.True(Names(e, "admin", seeded.Recovered.ToString("D")), e.GetProperty("type").GetString()));

        // Only the target names this one.
        var target = Guid.CreateVersion7();
        var targeted = await InsertEventAsync(host, Guid.CreateVersion7(), "admin.session.revoked", "system", null, "admin", target);
        Assert.Equal([targeted], (await EventsAsync(host, seeded.Cookie, $"?admin={target}")).Select(EventId));
        Assert.Empty(await EventsAsync(host, seeded.Cookie, $"?admin={Guid.CreateVersion7()}"));
    }

    [Fact]
    public async Task The_Tenant_filter_matches_events_whose_target_is_that_Tenant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var seeded = await SeedAsync(host);
        var other = await CreateTenantAsync(host, seeded.Cookie, seeded.Csrf, "other-co");

        var found = await EventsAsync(host, seeded.Cookie, $"?tenant={PublicId.Format(PublicIdType.Tenant, seeded.Tenant)}");
        Assert.NotEmpty(found);
        Assert.All(found, e => Assert.Equal(PublicId.Format(PublicIdType.Tenant, seeded.Tenant), e.GetProperty("target").GetProperty("id").GetString()));
        Assert.Contains(found, e => e.GetProperty("type").GetString() == "tenancy.tenant.created");

        var others = await EventsAsync(host, seeded.Cookie, $"?tenant={PublicId.Format(PublicIdType.Tenant, other)}");
        Assert.Single(others, e => e.GetProperty("type").GetString() == "tenancy.tenant.created");
        Assert.All(others, e => Assert.Equal(PublicId.Format(PublicIdType.Tenant, other), e.GetProperty("target").GetProperty("id").GetString()));

        Assert.Empty(await EventsAsync(host, seeded.Cookie, $"?tenant={PublicId.Format(PublicIdType.Tenant, Guid.CreateVersion7())}"));
    }

    [Fact]
    public async Task Outcome_and_range_filters_narrow_and_combine_as_in_a_Tenants_Log()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        var events = new Dictionary<int, Guid>();
        foreach (var (seconds, code) in new[] { (1, "admin.signin.failed"), (2, "admin.signin.succeeded"), (3, Denied), (4, "admin.session.signed_out") })
        {
            events[seconds] = await InsertEventAsync(host, Guid.CreateVersion7(Start.AddSeconds(seconds)), code, "anonymous", null, null, null, Start.AddSeconds(seconds));
        }

        var range = $"from={Instant(1)}&to={Instant(4)}";
        Assert.Equal([events[3], events[2], events[1]], (await EventsAsync(host, cookie, $"?{range}")).Select(EventId));
        Assert.Equal([events[3], events[1]], (await EventsAsync(host, cookie, $"?{range}&outcome=failure")).Select(EventId));
        Assert.Equal([events[2]], (await EventsAsync(host, cookie, $"?{range}&outcome=success")).Select(EventId));
        Assert.Equal([events[3]], (await EventsAsync(host, cookie, $"?{range}&outcome=failure&type={Denied}")).Select(EventId));
        Assert.Empty(await EventsAsync(host, cookie, $"?{range}&outcome=success&type={Denied}"));

        // Every failure listed has a Failure code, the real sign-in events included.
        Assert.All(await EventsAsync(host, cookie, "?outcome=failure"), e => Assert.Equal("failure", e.GetProperty("outcome").GetString()));
    }

    [Fact]
    public async Task Pages_hold_50_newest_first_and_the_last_has_no_cursor()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        // 120 fixture events whose IDs, like UUIDv7s, sort as they were written: older than the Owner's own.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO deployment_audit_event (id, occurred_at, type_code, actor_kind)
            SELECT (lpad(to_hex(n), 8, '0') || '-0000-7000-8000-000000000000')::uuid,
                   timestamptz '{Start:O}' + n * interval '1 second', 'deployment.paging.fixture', 'system'
            FROM generate_series(1, 120) AS n;
            SET session_replication_role = DEFAULT;
            """);

        var seen = new List<Guid>();
        var sizes = new List<int>();
        string? cursor = null;
        do
        {
            using var page = await host.SendAsync(HttpMethod.Get, $"{LogsPath}?type=deployment.paging.fixture" + (cursor is null ? "" : $"&cursor={cursor}"), cookie);
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            using var json = JsonDocument.Parse(await page.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(["events", "nextCursor"], json.RootElement.EnumerateObject().Select(p => p.Name));
            var ids = json.RootElement.GetProperty("events").EnumerateArray().Select(EventId).ToList();
            sizes.Add(ids.Count);
            seen.AddRange(ids);
            var next = json.RootElement.GetProperty("nextCursor");
            cursor = next.ValueKind == JsonValueKind.Null ? null : next.GetString();
            if (cursor is not null)
            {
                Assert.Equal(PublicId.Format(PublicIdType.AuditEvent, ids[^1]), cursor);
            }
        }
        while (cursor is not null && sizes.Count < 5);

        Assert.Equal([50, 50, 20], sizes);
        Assert.Equal(120, seen.Distinct().Count());
        var ordered = seen.Select(g => g.ToString("N")).ToList();
        Assert.Equal(ordered.OrderByDescending(g => g, StringComparer.Ordinal), ordered);

        // The unfiltered list pages too: the Owner's events first, then the fixtures.
        using var first = await host.SendAsync(HttpMethod.Get, LogsPath, cookie);
        using var firstJson = JsonDocument.Parse(await first.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(50, firstJson.RootElement.GetProperty("events").GetArrayLength());
        Assert.Equal(JsonValueKind.String, firstJson.RootElement.GetProperty("nextCursor").ValueKind);
    }

    public static TheoryData<string> MalformedQueries() =>
    [
        "?admin=not-a-uuid",
        "?admin=00000000-0000-0000-0000-000000000000",
        "?admin=0190000000007000800000000007a8aa",
        "?admin=a&admin=b",
        "?admin=",
        "?tenant=not-a-tenant",
        "?tenant=" + Guid.CreateVersion7().ToString("D"),
        "?tenant=" + PublicId.Format(PublicIdType.AuditEvent, Guid.CreateVersion7()),
        "?tenant=" + PublicId.Format(PublicIdType.Tenant, Guid.Parse("01900000-0000-7000-8000-0000000007a8")).ToUpperInvariant(),
        "?type=Not.A.Code",
        "?type=two.parts",
        "?outcome=maybe",
        "?from=2026-01-01",
        "?from=2026-11-14T10:00:00Z&to=2026-11-14T09:00:00Z",
        "?cursor=evt_x",
        "?cursor=" + PublicId.Format(PublicIdType.Tenant, Guid.CreateVersion7()),
    ];

    [Theory]
    [MemberData(nameof(MalformedQueries))]
    public async Task A_malformed_filter_is_400_invalid_request_before_anything_is_read(string query)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        await PostgresFixture.ExecuteAsync(host.Superuser, "REVOKE SELECT ON deployment_audit_event FROM gk_admin");
        try
        {
            // Nothing is read, so the missing grant can't turn the 400 into a 503.
            using var response = await host.SendAsync(HttpMethod.Get, LogsPath + query, cookie);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_request", await TenantRequests.CodeAsync(response));
        }
        finally
        {
            await PostgresFixture.ExecuteAsync(host.Superuser, "GRANT SELECT ON deployment_audit_event TO gk_admin");
        }
    }

    [Fact]
    public async Task The_Owner_opens_a_sealed_event_with_its_raw_envelope_hex_seal_and_detail()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, owner) = await host.OwnerSessionAsync();
        var id = Guid.CreateVersion7(Start);
        await InsertEventAsync(host, id, "admin.signin.succeeded", "admin", owner, "admin", owner, Start, seq: 2, detail: true);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(id), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var root = json.RootElement;
        Assert.Equal(["id", "occurredAt", "type", "outcome", "summary", "actor", "target", "raw"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal(PublicId.Format(PublicIdType.AuditEvent, id), root.GetProperty("id").GetString());
        Assert.Equal(Start, root.GetProperty("occurredAt").GetDateTimeOffset());
        Assert.Equal("success", root.GetProperty("outcome").GetString());
        Assert.False(string.IsNullOrEmpty(root.GetProperty("summary").GetString()));
        Assert.Equal(owner.ToString("D"), root.GetProperty("actor").GetProperty("id").GetString());

        var raw = root.GetProperty("raw");
        Assert.Equal(["id", "occurredAt", "type", "actor", "target", "seal", "detail"], raw.EnumerateObject().Select(p => p.Name));
        Assert.Equal("admin.signin.succeeded", raw.GetProperty("type").GetString());
        var seal = raw.GetProperty("seal");
        Assert.Equal(2L, seal.GetProperty("seq").GetInt64());
        Assert.Equal(PrevHash, seal.GetProperty("prevHash").GetString());
        Assert.Equal(Hash, seal.GetProperty("hash").GetString());
        var detail = raw.GetProperty("detail");
        Assert.Equal(["ipAddress", "userAgent", "email"], detail.EnumerateObject().Select(p => p.Name));
        Assert.Equal(Ip, detail.GetProperty("ipAddress").GetString());
        Assert.Equal(UserAgent, detail.GetProperty("userAgent").GetString());
        Assert.Equal(Email, detail.GetProperty("email").GetString());
    }

    [Fact]
    public async Task A_real_unsealed_event_without_detail_has_raw_with_null_seal_and_detail()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        var created = (await EventsAsync(host, cookie, "?type=bootstrap.admin.created")).Single();

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(EventId(created)), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var raw = json.RootElement.GetProperty("raw");
        Assert.Equal(JsonValueKind.Object, raw.ValueKind);
        Assert.Equal(JsonValueKind.Null, raw.GetProperty("seal").ValueKind);
        Assert.Equal(JsonValueKind.Null, raw.GetProperty("detail").ValueKind);
        Assert.Equal(created.GetProperty("id").GetString(), raw.GetProperty("id").GetString());
    }

    [Fact]
    public async Task An_unknown_event_and_a_Tenant_Log_event_are_404_and_a_malformed_ID_400()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        var tenant = await host.InsertTenantAsync();
        var tenantEvent = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{tenant}', '{tenantEvent}', 'operations.job.dead', 'system')");

        foreach (var id in new[] { Guid.CreateVersion7(), tenantEvent })
        {
            using var missing = await host.SendAsync(HttpMethod.Get, PathFor(id), cookie);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            Assert.Equal("not_found", await TenantRequests.CodeAsync(missing));
        }

        foreach (var malformed in new[] { "abc", "evt_x", PublicId.Format(PublicIdType.Tenant, tenant), tenantEvent.ToString("D") })
        {
            using var refused = await host.SendAsync(HttpMethod.Get, $"{LogsPath}/{Uri.EscapeDataString(malformed)}", cookie);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Equal("invalid_request", await TenantRequests.CodeAsync(refused));
        }
    }

    [Fact]
    public async Task Another_Admin_even_a_Tenant_Owner_is_refused_403_on_both_routes_and_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (ownerCookie, _, _) = await host.OwnerSessionAsync();
        var tenant = await host.InsertTenantAsync();
        var (cookie, _, admin) = await TenantRequests.RoleSessionAsync(host, tenant, "owner");
        var created = (await EventsAsync(host, ownerCookie, "?type=bootstrap.admin.created")).Single();

        foreach (var path in new[] { LogsPath, LogsPath + "?type=bootstrap.admin.created", PathFor(EventId(created)) })
        {
            using var refused = await host.SendAsync(HttpMethod.Get, path, cookie);
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            Assert.Equal("access_denied", await TenantRequests.CodeAsync(refused));
            var body = await refused.Content.ReadAsStringAsync(Cancellation);
            Assert.DoesNotContain("bootstrap.", body, StringComparison.Ordinal);
            Assert.DoesNotContain(created.GetProperty("id").GetString()!, body, StringComparison.Ordinal);
        }

        Assert.Equal(3L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}' AND actor_kind = 'admin' AND actor_id = '{admin}'"));
    }

    [Fact]
    public async Task No_Session_is_401_on_both_routes()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        await host.OwnerSessionAsync();

        foreach (var path in new[] { LogsPath, PathFor(Guid.CreateVersion7()) })
        {
            using var response = await host.SendAsync(HttpMethod.Get, path);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact]
    public void A_machine_principal_is_never_allowed_to_read_the_Deployment_Log()
    {
        var tenant = Guid.CreateVersion7();
        var machine = TestOnlyMachinePrincipal.For(tenant);

        Assert.False(AdminCapabilities.Allows(AdminCapabilities.DeploymentLogRead, machine, null, tenant));
        Assert.False(AdminCapabilities.Allows(AdminCapabilities.DeploymentLogRead, machine, null, null));
        Assert.False(AdminCapabilities.DeploymentLogRead.MachineAllowed);
    }

    [Fact]
    public async Task A_database_failure_is_503_and_reads_are_never_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _) = await host.OwnerSessionAsync();
        var created = (await EventsAsync(host, cookie, "?type=bootstrap.admin.created")).Single();
        var before = await host.ScalarAsync<long>("SELECT (SELECT count(*) FROM audit_event) + (SELECT count(*) FROM deployment_audit_event)");

        await EventsAsync(host, cookie, "");
        using (var opened = await host.SendAsync(HttpMethod.Get, PathFor(EventId(created)), cookie))
        {
            Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        }

        Assert.Equal(before, await host.ScalarAsync<long>("SELECT (SELECT count(*) FROM audit_event) + (SELECT count(*) FROM deployment_audit_event)"));

        await PostgresFixture.ExecuteAsync(host.Superuser, "REVOKE SELECT ON deployment_audit_detail FROM gk_admin");
        try
        {
            // The search never reads detail; the open read does, and its failure is the bodiless 503.
            using (var search = await host.SendAsync(HttpMethod.Get, LogsPath, cookie))
            {
                Assert.Equal(HttpStatusCode.OK, search.StatusCode);
            }

            using var failed = await host.SendAsync(HttpMethod.Get, PathFor(EventId(created)), cookie);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
            Assert.Empty(await failed.Content.ReadAsByteArrayAsync(Cancellation));
        }
        finally
        {
            await PostgresFixture.ExecuteAsync(host.Superuser, "GRANT SELECT ON deployment_audit_detail TO gk_admin");
        }
    }

    private static string PathFor(Guid eventId) => $"{LogsPath}/{PublicId.Format(PublicIdType.AuditEvent, eventId)}";

    private static Guid EventId(JsonElement e) =>
        PublicId.TryParse(PublicIdType.AuditEvent, e.GetProperty("id").GetString(), out var id) ? id : Guid.Empty;

    /// <summary>Whether the event's Actor or target is <paramref name="kind"/> with <paramref name="id"/>.</summary>
    private static bool Names(JsonElement e, string kind, string id)
    {
        static bool Is(JsonElement reference, string kind, string id) =>
            reference.ValueKind == JsonValueKind.Object
            && reference.GetProperty("kind").GetString() == kind
            && reference.GetProperty("id").GetString() == id;

        return Is(e.GetProperty("actor"), kind, id) || Is(e.GetProperty("target"), kind, id);
    }

    /// <summary><see cref="Start"/> plus <paramref name="seconds"/>, as a query's instant.</summary>
    private static string Instant(int seconds) =>
        Uri.EscapeDataString(Start.AddSeconds(seconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));

    private static async Task<List<JsonElement>> EventsAsync(AdminHost host, string cookie, string query)
    {
        using var response = await host.SendAsync(HttpMethod.Get, LogsPath + query, cookie);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{query} answered {(int)response.StatusCode}.");
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return [.. json.RootElement.GetProperty("events").EnumerateArray().Select(e => e.Clone())];
    }

    /// <summary>
    /// The Deployment Log as the real flows leave it: <c>gatekeep init</c>'s token, the bootstrap
    /// claim, credential registration and sign-in of the Deployment Owner, a second Admin's Recovery
    /// Code redeemed at sign-in, and a Tenant created through the API.
    /// </summary>
    private static async Task<(string Cookie, string Csrf, Guid Owner, Guid Recovered, Guid Tenant)> SeedAsync(AdminHost host)
    {
        var (cookie, csrf, owner) = await host.OwnerSessionAsync();
        var (_, _, recovered, code, authenticator) = await host.AdminWithRecoveryCodeAsync();
        authenticator.Dispose();
        using (var redeemed = await host.RedeemAsync(code))
        {
            Assert.Equal(HttpStatusCode.OK, redeemed.StatusCode);
        }

        var tenant = await CreateTenantAsync(host, cookie, csrf, "acme-logs");
        return (cookie, csrf, owner, recovered, tenant);
    }

    private static async Task<Guid> CreateTenantAsync(AdminHost host, string cookie, string csrf, string subdomain)
    {
        using var response = await host.SendAsync(
            HttpMethod.Post,
            "/api/v1/deployment/tenants",
            cookie,
            csrf,
            AdminHost.Origin,
            JsonSerializer.Serialize(new { name = subdomain, subdomain, label = "dev" }));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.True(PublicId.TryParse(PublicIdType.Tenant, json.RootElement.GetProperty("tenant").GetProperty("id").GetString(), out var tenant));
        return tenant;
    }

    /// <summary>
    /// A Deployment Log fixture row, at <paramref name="at"/> (now when null), sealed at
    /// <paramref name="seq"/> or unsealed, with the planted detail row when <paramref name="detail"/>.
    /// As the superuser with triggers off, since the insert guard stamps the time and refuses a seal.
    /// </summary>
    private static async Task<Guid> InsertEventAsync(
        AdminHost host,
        Guid id,
        string code,
        string actorKind,
        Guid? actorId,
        string? targetKind,
        Guid? targetId,
        DateTimeOffset? at = null,
        long? seq = null,
        bool detail = false)
    {
        static string Text(object? value) => value is null ? "NULL" : $"'{value}'";
        var seal = seq switch
        {
            null => "NULL, NULL, NULL, NULL",
            1 => $"1, 1, NULL, '\\x{Hash}'",
            { } n => $"1, {n}, '\\x{PrevHash}', '\\x{Hash}'",
        };
        var occurred = at is { } instant ? $"'{instant:O}'" : "clock_timestamp()";
        var detailRow = detail
            ? $"INSERT INTO deployment_audit_detail (event_id, ip_address, user_agent, email) VALUES ('{id}', '{Ip}'::inet, '{UserAgent}', '{Email}');"
            : string.Empty;
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO deployment_audit_event (id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, epoch, seq, prev_hash, hash)
            VALUES ('{id}', {occurred}, '{code}', '{actorKind}', {Text(actorId)}, {Text(targetKind)}, {Text(targetId)}, {seal});
            {detailRow}
            SET session_replication_role = DEFAULT;
            """);
        return id;
    }
}
