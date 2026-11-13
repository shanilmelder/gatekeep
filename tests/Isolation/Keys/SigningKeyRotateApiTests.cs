using System.Net;
using System.Text.Json;
using Gatekeep.Tests.Isolation.Admins;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 9.2 (FR-37, AD-5, AD-11, AD-19) on the real Host.Admin and PostgreSQL, with the OpenBao
/// stand-in creating the replacement key: <c>POST /api/v1/tenants/{tenantId}/signing-keys/rotate</c>.
/// Only the path Tenant's Owner rotates, and only a next key published for 15 minutes; a younger one
/// is 409 with the seconds left; custody down is 503; and nothing else, and no other Tenant, changes.
/// One test or more per API row of the story's matrix. No assertion prints a key name or version.
/// </summary>
public sealed class SigningKeyRotateApiTests(PostgresFixture postgres)
{
    private const string Rotated = "keys.signing_key.rotated";
    private const string Promoted = "keys.signing_key.promoted";
    private const string Created = "keys.signing_key.created";

    private const string Denied = "type_code = 'admin.access.denied'";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_Owner_rotates_an_aged_next_and_gets_the_keys_as_the_rotation_leaves_them()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var fresh = await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        await PublishedAsync(host, tenant, minutesAgo: 20);
        var management = await SnapshotAsync(host, tenant, "management");
        var (cookie, csrf, admin) = await RoleSessionAsync(host, tenant, "owner");

        await using var listener = await ListenAsync(host);
        using var response = await RotateAsync(host, cookie, csrf, tenant);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var keys = await KeysAsync(response);

        // The new next, then the old next as current, then the old current as previous.
        var created = Assert.Single(custody.Created);
        Assert.Equal(
            [($"{created}.v1", "next"), (fresh[0].KeyId, "current"), (fresh[1].KeyId, "previous")],
            keys.Select(k => (k.GetProperty("keyId").GetString()!, k.GetProperty("state").GetString()!)));
        Assert.StartsWith($"sig-{tenant:D}-", created, StringComparison.Ordinal);
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND state = 'next' AND purpose = 'signing' AND transit_name = '{created}'"));

        // Three events on the Tenant's own Log, each the Owner's; Management keys untouched; Host.Hosted told at commit.
        Assert.Equal(3L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code IN ('{Rotated}', '{Promoted}', '{Created}') AND actor_kind = 'admin' AND actor_id = '{admin}'"));
        Assert.Equal(management, await SnapshotAsync(host, tenant, "management"));
        Assert.Equal(tenant.ToString(), await listener.NextAsync());

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.DoesNotContain("mgmt-", body, StringComparison.Ordinal);
        Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_next_published_five_minutes_ago_is_409_with_the_seconds_left_and_changes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        await PublishedAsync(host, tenant, minutesAgo: 5);
        var before = await SnapshotAsync(host, tenant);
        var events = await EventCountAsync(host, tenant);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await RotateAsync(host, cookie, csrf, tenant);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("signing_key_not_ready", await CodeAsync(response));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var seconds = json.RootElement.GetProperty("retryAfterSeconds").GetInt32();
        Assert.InRange(seconds, 580, 600);
        Assert.Equal(seconds.ToString(System.Globalization.CultureInfo.InvariantCulture), Assert.Single(response.Headers.GetValues("Retry-After")));
        Assert.Equal(["code", "retryAfterSeconds", "traceId"], json.RootElement.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));

        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(host, tenant));
        Assert.Equal(events, await EventCountAsync(host, tenant));
    }

    [Fact]
    public async Task An_older_previous_stays_previous()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var (signing, _) = await SigningKeySeeds.EveryStateAsync(host.Superuser, tenant);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await RotateAsync(host, cookie, csrf, tenant);

        var keys = await KeysAsync(response);
        Assert.Equal(
            ["next", "current", "previous", "previous", "retired", "revoked", "retired"],
            keys.Select(k => k.GetProperty("state").GetString()));
        Assert.Equal("previous", await host.ScalarAsync<string>(
            $"SELECT state FROM signing_key WHERE tenant_id = '{tenant}' AND transit_name = '{signing[2].Key.Value}'"));
    }

    [Theory]
    [InlineData("editor")]
    [InlineData("viewer")]
    public async Task An_Editor_or_a_Viewer_is_403_audited_and_nothing_changes(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        await PublishedAsync(host, tenant, minutesAgo: 20);
        var before = await SnapshotAsync(host, tenant);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, role);

        using var response = await RotateAsync(host, cookie, csrf, tenant);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(host, tenant));
        Assert.Equal(0L, await EventCountAsync(host, tenant));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task Another_Tenants_Owner_is_403_and_neither_Tenant_changes()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, a);
        await SigningKeySeeds.FreshAsync(host.Superuser, b);
        await PublishedAsync(host, a, minutesAgo: 20);
        await PublishedAsync(host, b, minutesAgo: 20);
        var (aBefore, bBefore) = (await SnapshotAsync(host, a), await SnapshotAsync(host, b));
        var (cookie, csrf, _) = await RoleSessionAsync(host, b, "owner");

        using var response = await RotateAsync(host, cookie, csrf, a);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(aBefore, await SnapshotAsync(host, a));
        Assert.Equal(bBefore, await SnapshotAsync(host, b));
    }

    [Fact]
    public async Task Rotating_one_Tenant_leaves_anothers_rows_byte_identical()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, a);
        await SigningKeySeeds.FreshAsync(host.Superuser, b);
        await PublishedAsync(host, a, minutesAgo: 20);
        await PublishedAsync(host, b, minutesAgo: 20);
        var bBefore = await SnapshotAsync(host, b);
        var (cookie, csrf, admin) = await RoleSessionAsync(host, a, "owner");
        await host.GrantTenantRoleAsync(b, admin, "owner");

        using var response = await RotateAsync(host, cookie, csrf, a);

        Assert.Equal(3, (await KeysAsync(response)).Count);
        Assert.Equal(bBefore, await SnapshotAsync(host, b));
        Assert.Equal(0L, await EventCountAsync(host, b));
    }

    [Fact]
    public async Task Custody_refusing_the_create_is_503_and_nothing_is_written()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host) { RefuseCreate = true };
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        await PublishedAsync(host, tenant, minutesAgo: 20);
        var before = await SnapshotAsync(host, tenant);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        using var response = await RotateAsync(host, cookie, csrf, tenant);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(host, tenant));
        Assert.Equal(0L, await EventCountAsync(host, tenant));
        Assert.DoesNotContain("sig-", host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Two_rotations_at_once_leave_one_current_and_one_next()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        await PublishedAsync(host, tenant, minutesAgo: 20);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, "owner");

        var responses = await Task.WhenAll(RotateAsync(host, cookie, csrf, tenant), RotateAsync(host, cookie, csrf, tenant));
        try
        {
            // The one that waited on the lock finds a brand-new next: 409 not ready, never a second rotation.
            Assert.Contains(responses, r => r.StatusCode == HttpStatusCode.OK);
            Assert.All(responses, r => Assert.Contains(r.StatusCode, new[] { HttpStatusCode.OK, HttpStatusCode.Conflict }));
            Assert.Equal(1L, await host.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Rotated}'"));
            Assert.Equal("current/next", await host.ScalarAsync<string>(
                $"SELECT string_agg(state, '/' ORDER BY state) FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state IN ('current', 'next')"));
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }
    }

    [Fact]
    public async Task A_different_page_Tenant_is_409_tenant_mismatch_and_nothing_runs()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        await SigningKeySeeds.FreshAsync(host.Superuser, a);
        await PublishedAsync(host, a, minutesAgo: 20);
        var before = await SnapshotAsync(host, a);
        var (cookie, csrf, _) = await RoleSessionAsync(host, a, "owner");

        using var response = await RotateAsync(host, cookie, csrf, a, header: Id(b));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_mismatch", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(host, a));
    }

    [Fact]
    public async Task No_Session_is_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);

        using var response = await host.SendAsync(HttpMethod.Post, RotatePath(tenant), origin: AdminHost.Origin, headers: [(Header, Id(tenant))]);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static string RotatePath(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/signing-keys/rotate";

    private static Task<HttpResponseMessage> RotateAsync(AdminHost host, string cookie, string csrf, Guid tenant, string? header = null) =>
        host.SendAsync(HttpMethod.Post, RotatePath(tenant), cookie, csrf, AdminHost.Origin, headers: [(Header, header ?? Id(tenant))]);

    /// <summary>Backdates the Tenant's signing next's publication, as the superuser with the triggers off.</summary>
    private static Task PublishedAsync(AdminHost host, Guid tenant, int minutesAgo) =>
        PostgresFixture.ExecuteAsync(
            host.Superuser,
            "SET session_replication_role = replica; "
            + $"UPDATE signing_key SET published_at = now() - make_interval(mins => {minutesAgo}) WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'; "
            + "SET session_replication_role = DEFAULT");

    /// <summary>Every column of the Tenant's rows (of one purpose, if given), so any change shows.</summary>
    private static Task<string> SnapshotAsync(AdminHost host, Guid tenant, string? purpose = null) =>
        host.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(to_jsonb(s)::text, ',' ORDER BY id), '') FROM signing_key s WHERE tenant_id = '{tenant}'"
            + (purpose is null ? string.Empty : $" AND purpose = '{purpose}'"));

    private static Task<long> EventCountAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code LIKE 'keys.%'");

    private static async Task<List<JsonElement>> KeysAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["keys"], json.RootElement.EnumerateObject().Select(p => p.Name));
        return [.. json.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.Clone())];
    }

    private static async Task<Listener> ListenAsync(AdminHost host)
    {
        var connection = new NpgsqlConnection(host.Superuser);
        await connection.OpenAsync(Cancellation);
        await using (var command = new NpgsqlCommand("LISTEN gatekeep_signing_keys", connection))
        {
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        return new Listener(connection);
    }

    /// <summary>A superuser connection listening on the Signing Keys channel, as Host.Hosted's listener does.</summary>
    private sealed class Listener : IAsyncDisposable
    {
        private readonly NpgsqlConnection _connection;
        private string? _payload;

        public Listener(NpgsqlConnection connection)
        {
            _connection = connection;
            _connection.Notification += (_, e) => _payload = e.Payload;
        }

        /// <summary>The payload of the notification already sent, or of the next within 10 seconds.</summary>
        public async Task<string?> NextAsync()
        {
            if (_payload is null)
            {
                await _connection.WaitAsync(TimeSpan.FromSeconds(10), Cancellation);
            }

            return _payload;
        }

        public ValueTask DisposeAsync() => _connection.DisposeAsync();
    }
}
