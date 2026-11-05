using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Jobs;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.29 (FR-7, FR-8, AD-4): deleting one Tenant leaves every other Tenant's data, keys and
/// Logs unchanged. Two Tenants are seeded in every registry table, given their six secret class
/// keys in the real OpenBao and events on their chains; one is deleted through the real Operation
/// with the real <c>host-worker</c> policy; every row of the other, in every registry table, its
/// keys with their versions, and its chain are identical before and after.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class TenantDeletionIsolationTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    [Fact]
    public async Task Deleting_one_Tenant_leaves_the_others_data_keys_and_Logs_unchanged()
    {
        var database = await CreateAsync(postgres, registry: null);
        var superuser = postgres.SuperuserConnection(database.Name);
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await TestTenants.InsertAsync(superuser, a, TestTenants.Host(a));
        await TestTenants.InsertAsync(superuser, b, TestTenants.Host(b), label: "prod");
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        foreach (var tenant in new[] { a, b })
        {
            await TenantSeeds.SeedAsync(superuser, tenant);
            await KeysContract.CreateSecretClassKeysAsync(worker, tenant, Cancellation);
            await AppendAsync(database, tenant);
        }

        await worker.RotateAsync(KeyName.ForTenant(TenantKeyClass.Payload, b), Cancellation);
        var rowsOfB = await TenantSeeds.SnapshotAsync(superuser, b);
        var keysOfB = await VersionsAsync(b);
        var chainOfA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}'");
        Assert.Equal(6, keysOfB.Count);
        Assert.Contains(rowsOfB, r => r.Key == "user_session" && r.Value.Length > 0);

        await TenantPurgeRegistryTests.DeleteAsync(database, a, TestTenants.Host(a));
        await DrainAsync(database, worker);

        // The deleted Tenant: a tombstone with no data and no keys, and its whole chain kept.
        Assert.Equal("deleted", await database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{a}'"));
        Assert.Empty(await TenantSeeds.RowsLeftAsync(superuser, a));
        Assert.Empty(await VersionsAsync(a));
        Assert.Equal(chainOfA + 1, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_host WHERE tenant_id = '{a}'"));

        // The other: every row, every key version and its chain, unchanged; still active, so it still resolves.
        Assert.Equal(rowsOfB, await TenantSeeds.SnapshotAsync(superuser, b));
        Assert.Equal(keysOfB, await VersionsAsync(b));
        Assert.Equal("active", await database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{b}'"));

        // The real resolution middleware, as gk_hosted: the other Tenant still resolves, the deleted one is the fixed 404.
        await using var probe = await TenantResolutionTests.ProbeServer.StartAsync(postgres.RoleConnection(TableRegistry.Hosted, database.Name));
        using (var other = await TenantResolutionTests.SendAsync(probe.Http, probe.Port, TestTenants.Host(b), HttpMethod.Get, "/probe"))
        {
            Assert.Equal(System.Net.HttpStatusCode.OK, other.StatusCode);
            using var body = JsonDocument.Parse(await other.Content.ReadAsStringAsync(Cancellation));
            Assert.Equal(b, body.RootElement.GetProperty("tenantId").GetGuid());
        }

        using (var gone = await TenantResolutionTests.SendAsync(probe.Http, probe.Port, TestTenants.Host(a), HttpMethod.Get, "/probe"))
        {
            Assert.Equal(System.Net.HttpStatusCode.NotFound, gone.StatusCode);
        }

        Assert.Equal(1, probe.Calls);
    }

    [Fact]
    public async Task Keys_already_destroyed_count_as_destroyed()
    {
        var database = await CreateAsync(postgres, registry: null);
        var superuser = postgres.SuperuserConnection(database.Name);
        var a = Guid.CreateVersion7();
        await TestTenants.InsertAsync(superuser, a, TestTenants.Host(a));
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await KeysContract.CreateSecretClassKeysAsync(worker, a, Cancellation);
        await worker.DeleteAsync(KeyName.ForTenant(TenantKeyClass.Totp, a), Cancellation);
        await worker.DeleteAsync(KeyName.ForTenant(TenantKeyClass.Hmac, a), Cancellation);

        var started = await TenantPurgeRegistryTests.DeleteAsync(database, a, TestTenants.Host(a));
        await DrainAsync(database, worker);

        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{started.Operation!.Id}'"));
        Assert.Equal("deleted", await database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{a}'"));
        Assert.Empty(await VersionsAsync(a));
    }

    [Theory]
    [InlineData(OpenBaoFixture.Admin)]
    [InlineData(OpenBaoFixture.Hosted)]
    public async Task A_host_policy_other_than_the_Workers_fails_the_destroy_step_and_keeps_the_keys(string role)
    {
        var database = await CreateAsync(postgres, registry: null);
        var superuser = postgres.SuperuserConnection(database.Name);
        var a = Guid.CreateVersion7();
        await TestTenants.InsertAsync(superuser, a, TestTenants.Host(a));
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        using var other = bao.Custody(role);
        await KeysContract.CreateSecretClassKeysAsync(worker, a, Cancellation);

        var started = await TenantPurgeRegistryTests.DeleteAsync(database, a, TestTenants.Host(a));
        await DrainAsync(database, other);

        Assert.Equal(
            "succeeded/failed:custody_refused",
            await database.ScalarAsync<string>(
                "SELECT string_agg(status || CASE WHEN status = 'failed' THEN ':' || result_code ELSE '' END, '/' ORDER BY position) " +
                $"FROM operation_step WHERE operation_id = '{started.Operation!.Id}'"));
        Assert.Equal("deleting", await database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{a}'"));
        Assert.Equal(6, (await VersionsAsync(a)).Count);
    }

    private static async Task AppendAsync(JobDatabase database, Guid tenant) =>
        await database.InScopeAsync(TableRegistry.Worker, tenant, async context =>
        {
            await AuditContract.CreateAppender().AppendAsync(
                context,
                new AuditEvent(TenancyEvents.LabelChanged.Code, Actor.System, AuditTargetKind.Tenant, tenant),
                null,
                Cancellation);
            return 0;
        });

    private static async Task DrainAsync(JobDatabase database, IKeyCustody custody)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry, custody);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }

    /// <summary>Each of the Tenant's secret class keys that exists, and its latest version, read as the Worker.</summary>
    private async Task<Dictionary<string, int>> VersionsAsync(Guid tenant)
    {
        var token = await bao.LoginAsync(OpenBaoFixture.Worker);
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);

        var versions = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var key in KeysContract.SecretClassKeys(tenant))
        {
            using var response = await http.GetAsync($"v1/transit/keys/{key.Value}", Cancellation);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                continue;
            }

            response.EnsureSuccessStatusCode();
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
            versions[key.Value] = body.RootElement.GetProperty("data").GetProperty("latest_version").GetInt32();
        }

        return versions;
    }
}
