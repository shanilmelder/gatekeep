using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// Story 7.5, FR-39, FR-40, UX-DR18: <c>GET /api/v1/tenants/{tenantId}/logs/{eventId}</c> on the
/// real <c>Host.Admin</c> and PostgreSQL. Every Tenant Role reads the event's summary; only an
/// Editor or Owner, who holds <c>tenant.log_detail.read</c>, gets <c>raw</c>: the envelope, the
/// seal in lowercase hex and the detail row. A Viewer's response holds no detail value at all,
/// and no detail is read for them. Another Tenant's event is the same 404 as an unknown one; a
/// malformed ID is 400 <c>invalid_request</c>; nothing read is audited.
/// </summary>
public sealed class TenantLogEventTests(PostgresFixture postgres)
{
    private const string Code = "sessions.session.started";

    private const string Email = "detail-u1@example.test";

    private const string Ip = "198.51.100.23";

    private const string UserAgent = "DetailAgent/7.5";

    private const string Denied = "admin.access.denied";

    private const string Rejected = "admin.cross_tenant.rejected";

    /// <summary>The planted hashes, as lowercase hex.</summary>
    private static readonly string PrevHash = string.Concat(Enumerable.Repeat("a1", 32));

    private static readonly string Hash = string.Concat(Enumerable.Repeat("b2", 32));

    private static readonly DateTimeOffset At = new(2026, 11, 14, 9, 30, 0, TimeSpan.Zero);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("editor")]
    [InlineData("owner")]
    public async Task An_Editor_or_Owner_gets_the_summary_and_the_raw_envelope_seal_and_detail(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, role);
        var user = Guid.CreateVersion7();
        var id = await InsertEventAsync(host, a, user, seq: 2, detail: true);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var root = json.RootElement;
        Assert.Equal(["id", "occurredAt", "type", "outcome", "summary", "actor", "target", "raw"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal(PublicId.Format(PublicIdType.AuditEvent, id), root.GetProperty("id").GetString());
        Assert.Equal(At, root.GetProperty("occurredAt").GetDateTimeOffset());
        Assert.Equal(Code, root.GetProperty("type").GetString());
        Assert.Equal("success", root.GetProperty("outcome").GetString());
        Assert.False(string.IsNullOrEmpty(root.GetProperty("summary").GetString()));
        Assert.Equal("user", root.GetProperty("actor").GetProperty("kind").GetString());
        Assert.Equal(user.ToString("D"), root.GetProperty("actor").GetProperty("id").GetString());
        Assert.Equal("user", root.GetProperty("target").GetProperty("kind").GetString());

        var raw = root.GetProperty("raw");
        Assert.Equal(["id", "occurredAt", "type", "actor", "target", "seal", "detail"], raw.EnumerateObject().Select(p => p.Name));
        Assert.Equal(root.GetProperty("id").GetString(), raw.GetProperty("id").GetString());
        Assert.Equal(Code, raw.GetProperty("type").GetString());
        Assert.Equal(user.ToString("D"), raw.GetProperty("actor").GetProperty("id").GetString());

        var seal = raw.GetProperty("seal");
        Assert.Equal(["seq", "prevHash", "hash"], seal.EnumerateObject().Select(p => p.Name));
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
    public async Task A_Viewer_gets_the_summary_only_with_no_detail_value_in_the_body()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: 2, detail: true);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        foreach (var planted in new[] { Ip, UserAgent, Email, PrevHash, Hash, "ipAddress", "userAgent", "seal" })
        {
            Assert.DoesNotContain(planted, body, StringComparison.OrdinalIgnoreCase);
        }

        using var json = JsonDocument.Parse(body);
        Assert.Equal(["id", "occurredAt", "type", "outcome", "summary", "actor", "target", "raw"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("raw").ValueKind);
        Assert.Equal(Code, json.RootElement.GetProperty("type").GetString());
    }

    [Fact]
    public async Task An_Owner_elsewhere_who_is_only_a_Viewer_here_gets_no_raw_detail()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, admin) = await TenantRequests.RoleSessionAsync(host, b, "owner");
        await host.GrantTenantRoleAsync(a, admin, "viewer");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: 2, detail: true);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Cancellation);
        foreach (var planted in new[] { Ip, UserAgent, Email, PrevHash, Hash })
        {
            Assert.DoesNotContain(planted, body, StringComparison.OrdinalIgnoreCase);
        }

        using var json = JsonDocument.Parse(body);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("raw").ValueKind);
    }

    [Fact]
    public async Task A_Viewers_read_never_touches_audit_detail()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (viewer, _, _) = await TenantRequests.RoleSessionAsync(host, a, "viewer");
        var (editor, _, _) = await TenantRequests.RoleSessionAsync(host, a, "editor");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: 2, detail: true);
        await PostgresFixture.ExecuteAsync(host.Superuser, "REVOKE SELECT ON audit_detail FROM gk_admin");

        try
        {
            // Without the detail capability the detail table isn't queried, so its grant doesn't matter.
            using (var summary = await host.SendAsync(HttpMethod.Get, PathFor(a, id), viewer))
            {
                Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
            }

            // With it, the detail read fails, and the failure is the bodiless 503.
            using var failed = await host.SendAsync(HttpMethod.Get, PathFor(a, id), editor);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
            Assert.Empty(await failed.Content.ReadAsByteArrayAsync(Cancellation));
        }
        finally
        {
            await PostgresFixture.ExecuteAsync(host.Superuser, "GRANT SELECT ON audit_detail TO gk_admin");
        }
    }

    [Fact]
    public async Task An_event_without_a_detail_row_has_null_detail_and_the_first_in_a_chain_null_prevHash()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "editor");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: 1, detail: false);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var raw = json.RootElement.GetProperty("raw");
        Assert.Equal(JsonValueKind.Null, raw.GetProperty("detail").ValueKind);
        Assert.Equal(1L, raw.GetProperty("seal").GetProperty("seq").GetInt64());
        Assert.Equal(JsonValueKind.Null, raw.GetProperty("seal").GetProperty("prevHash").ValueKind);
        Assert.Equal(Hash, raw.GetProperty("seal").GetProperty("hash").GetString());
    }

    [Fact]
    public async Task An_unsealed_event_has_a_null_seal()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "editor");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: null, detail: true);

        using var response = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var raw = json.RootElement.GetProperty("raw");
        Assert.Equal(JsonValueKind.Null, raw.GetProperty("seal").ValueKind);
        Assert.Equal(Email, raw.GetProperty("detail").GetProperty("email").GetString());
    }

    [Fact]
    public async Task Another_Tenants_event_is_the_same_404_as_an_unknown_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "owner");
        var theirs = await InsertEventAsync(host, b, Guid.CreateVersion7(), seq: 2, detail: true);

        using var other = await host.SendAsync(HttpMethod.Get, PathFor(a, theirs), cookie);
        using var unknown = await host.SendAsync(HttpMethod.Get, PathFor(a, Guid.CreateVersion7()), cookie);

        foreach (var response in new[] { other, unknown })
        {
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("not_found", await TenantRequests.CodeAsync(response));
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        }

        var body = await other.Content.ReadAsStringAsync(Cancellation);
        Assert.DoesNotContain(Email, body, StringComparison.Ordinal);
        Assert.DoesNotContain(Ip, body, StringComparison.Ordinal);
        Assert.Equal(["code", "traceId"], ProblemMembers(body));
        Assert.Equal(ProblemMembers(body), ProblemMembers(await unknown.Content.ReadAsStringAsync(Cancellation)));
    }

    public static TheoryData<string> MalformedIds() =>
    [
        "abc",
        "evt_x",
        PublicId.Format(PublicIdType.Tenant, Guid.Parse("01900000-0000-7000-8000-0000000007a8")),
        PublicId.Format(PublicIdType.AuditEvent, Guid.Parse("01900000-0000-7000-8000-0000000007a8")).ToUpperInvariant(),
        Guid.Parse("01900000-0000-7000-8000-0000000007a8").ToString("D"),
    ];

    [Theory]
    [MemberData(nameof(MalformedIds))]
    public async Task A_malformed_event_ID_is_400_invalid_request(string eventId)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "editor");

        using var response = await host.SendAsync(HttpMethod.Get, $"{LogsPath(a)}/{Uri.EscapeDataString(eventId)}", cookie);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await TenantRequests.CodeAsync(response));
        Assert.Contains("A Log event read was refused with invalid_request", host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_Admin_with_no_role_in_the_Tenant_is_refused_403_and_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        var (cookie, _, admin) = await TenantRequests.RoleSessionAsync(host, b, "owner");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: 2, detail: true);

        using var refused = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("access_denied", await TenantRequests.CodeAsync(refused));
        var body = await refused.Content.ReadAsStringAsync(Cancellation);
        Assert.DoesNotContain(Email, body, StringComparison.Ordinal);
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Denied}' AND actor_id = '{admin}' AND target_id = '{a}'"));
        Assert.Equal(1L, await TenantRequests.TenantEventsAsync(host, a, Rejected));
    }

    [Fact]
    public async Task A_database_failure_is_503_and_reads_are_never_audited()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var a = await host.InsertTenantAsync();
        var (cookie, _, _) = await TenantRequests.RoleSessionAsync(host, a, "owner");
        var id = await InsertEventAsync(host, a, Guid.CreateVersion7(), seq: 2, detail: true);
        var before = await host.ScalarAsync<long>("SELECT (SELECT count(*) FROM audit_event) + (SELECT count(*) FROM deployment_audit_event)");

        using (var ok = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie))
        {
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        using (var missing = await host.SendAsync(HttpMethod.Get, PathFor(a, Guid.CreateVersion7()), cookie))
        {
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        }

        Assert.Equal(before, await host.ScalarAsync<long>("SELECT (SELECT count(*) FROM audit_event) + (SELECT count(*) FROM deployment_audit_event)"));

        await PostgresFixture.ExecuteAsync(host.Superuser, "REVOKE SELECT ON audit_event FROM gk_admin");
        try
        {
            using var failed = await host.SendAsync(HttpMethod.Get, PathFor(a, id), cookie);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
            Assert.Empty(await failed.Content.ReadAsByteArrayAsync(Cancellation));
        }
        finally
        {
            await PostgresFixture.ExecuteAsync(host.Superuser, "GRANT SELECT ON audit_event TO gk_admin");
        }
    }

    private static string LogsPath(Guid tenant) => $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, tenant)}/logs";

    private static string PathFor(Guid tenant, Guid eventId) => $"{LogsPath(tenant)}/{PublicId.Format(PublicIdType.AuditEvent, eventId)}";

    private static List<string> ProblemMembers(string body)
    {
        using var json = JsonDocument.Parse(body);
        return [.. json.RootElement.EnumerateObject().Select(p => p.Name)];
    }

    /// <summary>
    /// A <see cref="Code"/> event at <see cref="At"/> from and on <paramref name="user"/>, sealed at
    /// <paramref name="seq"/> (the first in its chain has no previous hash) or unsealed when null,
    /// with the planted detail row when <paramref name="detail"/>. As the superuser with triggers
    /// off, since the insert guard refuses a seal.
    /// </summary>
    private static async Task<Guid> InsertEventAsync(AdminHost host, Guid tenant, Guid user, long? seq, bool detail)
    {
        var id = Guid.CreateVersion7(At);
        var seal = seq switch
        {
            null => "NULL, NULL, NULL, NULL",
            1 => $"1, 1, NULL, '\\x{Hash}'",
            { } n => $"1, {n}, '\\x{PrevHash}', '\\x{Hash}'",
        };
        var detailRow = detail
            ? $"INSERT INTO audit_detail (tenant_id, event_id, ip_address, user_agent, email) VALUES ('{tenant}', '{id}', '{Ip}'::inet, '{UserAgent}', '{Email}');"
            : string.Empty;
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            SET session_replication_role = replica;
            INSERT INTO audit_event (tenant_id, id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, epoch, seq, prev_hash, hash)
            VALUES ('{tenant}', '{id}', '{At:O}', '{Code}', 'user', '{user}', 'user', '{user}', {seal});
            {detailRow}
            SET session_replication_role = DEFAULT;
            """);
        return id;
    }
}
