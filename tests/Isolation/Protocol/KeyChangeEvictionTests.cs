using System.Net;
using System.Text.Json;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Xunit;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Story 2.4: a committed rotation's <c>NOTIFY</c> drops that Tenant's kept runtime in Host.Hosted,
/// so its JWKS shows the new set on the next request, well inside the 5-second lifetime. The clock
/// is a manual one that never moves, so only the notification can drop a runtime here. Another
/// Tenant's runtime is untouched. A lost listening connection reconnects and drops every runtime.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class KeyChangeEvictionTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private static readonly TimeSpan NotificationWait = TimeSpan.FromSeconds(15);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Committed_rotation_shows_in_the_Tenants_jwks_at_once_and_leaves_another_Tenants_runtime()
    {
        var (database, a, b) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, new ManualTimeProvider());

        var aBefore = await KidsAsync(host, a.RpId);
        var bBody = await BodyAsync(host, b.RpId);
        var bRuntime = await host.TenantOptions.GetAsync(b, Cancellation);
        Assert.Equal(2, Kept(host));

        await database.BackdateAsync(
            $"UPDATE signing_key SET created_at = now() - interval '150 days' WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'current'; "
            + $"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'next'");
        Assert.True(await database.RotateAsync(bao, a.TenantId));

        // The clock never moves: only A's notification can drop A's runtime.
        await WaitUntilAsync(() => Kept(host) == 1);

        var aAfter = await KidsAsync(host, a.RpId);
        Assert.Equal(3, aAfter.Count);
        Assert.Equal(await database.KeyIdsAsync(a.TenantId, "signing"), aAfter.Order(StringComparer.Ordinal));
        Assert.All(aBefore, kid => Assert.Contains(kid, aAfter));

        Assert.Same(bRuntime, await host.TenantOptions.GetAsync(b, Cancellation));
        Assert.Equal(bBody, await BodyAsync(host, b.RpId));
    }

    [Fact]
    public async Task Run_that_only_retires_a_previous_key_drops_the_runtime_and_the_key_leaves_the_jwks()
    {
        var (database, a, _) = await TwoTenantsAsync();
        await database.BackdateAsync(
            $"UPDATE signing_key SET created_at = now() - interval '150 days' WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'current'; "
            + $"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'next'");
        Assert.True(await database.RotateAsync(bao, a.TenantId));
        var previous = await database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'previous'");

        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, new ManualTimeProvider());
        Assert.Contains(previous, await KidsAsync(host, a.RpId));
        Assert.Equal(1, Kept(host));

        // Nothing is due to rotate now; the only change is the retirement.
        await database.BackdateAsync(
            $"UPDATE signing_key SET rotated_at = now() - interval '76 minutes' WHERE tenant_id = '{a.TenantId}' AND state = 'previous'");
        Assert.True(await database.RotateAsync(bao, a.TenantId));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}' AND type_code = 'keys.signing_key.rotated'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}' AND type_code = 'keys.signing_key.retired'"));

        await WaitUntilAsync(() => Kept(host) == 0);

        var after = await KidsAsync(host, a.RpId);
        Assert.DoesNotContain(previous, after);
        Assert.Equal(2, after.Count);
    }

    [Fact]
    public async Task Rolled_back_rotation_drops_nothing()
    {
        var (database, a, _) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, new ManualTimeProvider());
        await KidsAsync(host, a.RpId);

        // The notification is sent inside a transaction that never commits, so it is never delivered.
        await database.ExecuteAsync($"BEGIN; SELECT pg_notify('gatekeep_signing_keys', '{a.TenantId}'); ROLLBACK;");

        // A committed one for a Tenant nobody asked for proves the listener is up meanwhile.
        await database.ExecuteAsync($"SELECT pg_notify('gatekeep_signing_keys', '{Guid.CreateVersion7()}')");
        await database.ExecuteAsync("SELECT pg_notify('gatekeep_signing_keys', 'not-a-tenant')");
        await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);

        Assert.Equal(1, Kept(host));
    }

    [Fact]
    public async Task Lost_listener_connection_reconnects_and_drops_every_runtime()
    {
        var (database, a, b) = await TwoTenantsAsync();
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao, new ManualTimeProvider());
        await KidsAsync(host, a.RpId);
        await KidsAsync(host, b.RpId);
        Assert.Equal(2, Kept(host));

        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = '{database.Name}' AND usename = 'gk_hosted' AND query LIKE 'LISTEN %'"));

        // Notifications sent while it was down are lost, so its reconnect drops every runtime.
        await WaitUntilAsync(() => Kept(host) == 0);

        // Listening again: a rotation's notification still reaches it.
        await KidsAsync(host, a.RpId);
        await WaitUntilAsync(async () => await database.ScalarAsync<long>(
            $"SELECT count(*) FROM pg_stat_activity WHERE datname = '{database.Name}' AND usename = 'gk_hosted' AND query LIKE 'LISTEN %'") == 1);
        await database.ExecuteAsync($"SELECT pg_notify('gatekeep_signing_keys', '{a.TenantId}')");
        await WaitUntilAsync(() => Kept(host) == 0);
        Assert.Contains("Signing Key change listener lost its connection on", string.Join('\n', host.Logs.Lines));
    }

    private async Task<(ProtocolDatabase Database, ResolvedTenant A, ResolvedTenant B)> TwoTenantsAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync($"a{Guid.NewGuid():N}.listen.test");
        var b = await database.AddTenantAsync($"b{Guid.NewGuid():N}.listen.test");
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(bao, b.TenantId));
        return (database, a, b);
    }

    private static int Kept(ProtocolHost host) =>
        (int)host.TenantOptions.GetType().GetProperty("Kept")!.GetValue(host.TenantOptions)!;

    private static Task WaitUntilAsync(Func<bool> done) => WaitUntilAsync(() => Task.FromResult(done()));

    /// <summary>A notification arrives on its own connection, so the test polls for its effect, bounded.</summary>
    private static async Task WaitUntilAsync(Func<Task<bool>> done)
    {
        var deadline = DateTimeOffset.UtcNow + NotificationWait;
        while (!await done() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), Cancellation);
        }

        Assert.True(await done(), "The expected change didn't arrive in time.");
    }

    private static async Task<string> BodyAsync(ProtocolHost host, string tenantHost)
    {
        using var response = await host.Http.GetAsync(new Uri($"http://{tenantHost}{ProtocolContract.JsonWebKeySetPath}"), Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Cancellation);
    }

    private static async Task<List<string>> KidsAsync(ProtocolHost host, string tenantHost)
    {
        using var document = JsonDocument.Parse(await BodyAsync(host, tenantHost));
        return [.. document.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()!)];
    }
}
