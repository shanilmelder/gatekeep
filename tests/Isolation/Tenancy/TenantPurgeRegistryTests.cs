using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Gatekeep.Tests.Isolation.Operations;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.29 (AD-3, AD-27, AD-30): the registry decides what a deletion must purge. Every
/// <c>tenant</c> table the registry lists, but Audit's, has a seed; a Tenant seeded in all of them
/// and deleted through the real Operation keeps no row in any; and both checks report the table
/// that breaks them, so a table a later story adds fails here until its seed and its purge exist.
/// </summary>
public sealed class TenantPurgeRegistryTests(PostgresFixture postgres)
{
    [Fact]
    public void Every_purged_registry_table_has_a_seed()
    {
        Assert.Contains("user_session", TenantSeeds.PurgedTables(TableRegistry.Tables));
        Assert.DoesNotContain("audit_event", TenantSeeds.PurgedTables(TableRegistry.Tables));
        Assert.Empty(TenantSeeds.Unseeded(TableRegistry.Tables));
    }

    [Fact]
    public void A_registry_table_with_no_seed_is_reported()
    {
        var widget = new TableEntry("widget", TableClass.Tenant, "Widgets", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>());
        var kept = new TableEntry("audit_widget", TableClass.Tenant, TenantSeeds.KeptOwner, TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>());

        Assert.Equal(["widget"], TenantSeeds.Unseeded([.. TableRegistry.Tables, widget, kept]));
    }

    /// <summary>Review item: every purged table refuses a row for a Tenant being deleted, through its row guard, which the catalogue test holds the database to.</summary>
    [Fact]
    public void Every_purged_registry_table_has_the_row_guard()
    {
        Assert.Empty(Unguarded(TableRegistry.Tables));
    }

    [Fact]
    public void A_purged_table_with_no_row_guard_is_reported()
    {
        var widget = new TableEntry("widget", TableClass.Tenant, "Widgets", TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>());
        var kept = new TableEntry("audit_widget", TableClass.Tenant, TenantSeeds.KeptOwner, TableUse.Runtime, new Dictionary<string, IReadOnlyList<string>>());

        Assert.Equal(["widget"], Unguarded([.. TableRegistry.Tables, widget, kept]));
    }

    private static List<string> Unguarded(IEnumerable<TableEntry> registry)
    {
        var entries = registry.ToList();
        return [.. TenantSeeds.PurgedTables(entries)
            .Where(name => !(entries.First(e => e.Name == name).Triggers ?? []).Contains("tenant_row_guard"))];
    }

    [Fact]
    public async Task Deletion_leaves_no_row_of_its_Tenant_in_any_purged_table()
    {
        var database = await JobDatabase.CreateAsync(postgres, registry: null);
        var superuser = postgres.SuperuserConnection(database.Name);
        await TenantSeeds.SeedAsync(superuser, TenantA);
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"SET session_replication_role = replica; INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('{TestTenants.Host(TenantA)}', '{TenantA}', 'subdomain'); SET session_replication_role = DEFAULT");
        Assert.Equal(TenantSeeds.Seeds.Select(s => s.Table), await TenantSeeds.RowsLeftAsync(superuser, TenantA));

        await DeleteAsync(database, TenantA, TestTenants.Host(TenantA));
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody()))
        {
            while (await runner.RunOnceAsync(Cancellation))
            {
            }
        }

        Assert.Equal("deleted", await database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{TenantA}'"));
        Assert.Empty(await TenantSeeds.RowsLeftAsync(superuser, TenantA));
    }

    [Fact]
    public async Task A_seeded_table_no_purge_empties_is_reported_by_name()
    {
        var database = await JobDatabase.CreateAsync(postgres, registry: null);
        var superuser = postgres.SuperuserConnection(database.Name);
        await TenantSeeds.SeedAsync(superuser, TenantA);

        // Every module's purge but Identity's, as a story that forgot one would leave it.
        await database.SuperuserAsync($"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{TenantA}'; SET session_replication_role = DEFAULT");
        await database.InScopeAsync(TableRegistry.Worker, TenantA, async context =>
        {
            await Gatekeep.Modules.Sessions.Contracts.SessionsContract.TenantPurge.PurgeAsync(context, Cancellation);
            await Gatekeep.Modules.Authentication.Contracts.AuthenticationContract.TenantPurge.PurgeAsync(context, Cancellation);
            await Gatekeep.Modules.Keys.Contracts.KeysContract.TenantPurge.PurgeAsync(context, Cancellation);
            await Gatekeep.Modules.Tenancy.Contracts.TenancyContract.TenantPurge.PurgeAsync(context, Cancellation);
            return 0;
        });

        Assert.Equal(["job_payload", "user"], await TenantSeeds.RowsLeftAsync(superuser, TenantA));
    }

    [Fact]
    public async Task Each_purge_is_idempotent_and_refuses_a_Deployment_context()
    {
        var database = await JobDatabase.CreateAsync(postgres, registry: null);
        await TenantSeeds.SeedAsync(postgres.SuperuserConnection(database.Name), TenantA);
        await database.SuperuserAsync($"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{TenantA}'; SET session_replication_role = DEFAULT");
        ITenantPurge[] purges =
        [
            Gatekeep.Modules.Sessions.Contracts.SessionsContract.TenantPurge,
            Gatekeep.Modules.Authentication.Contracts.AuthenticationContract.TenantPurge,
            IdentityPurge(),
            Gatekeep.Modules.Keys.Contracts.KeysContract.TenantPurge,
            Gatekeep.Modules.Tenancy.Contracts.TenancyContract.TenantPurge,
        ];

        for (var run = 0; run < 2; run++)
        {
            await database.InScopeAsync(TableRegistry.Worker, TenantA, async context =>
            {
                foreach (var purge in purges)
                {
                    await purge.PurgeAsync(context, Cancellation);
                }

                return 0;
            });
        }

        Assert.Equal(["job_payload"], await TenantSeeds.RowsLeftAsync(postgres.SuperuserConnection(database.Name), TenantA));
        foreach (var purge in purges)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => database.InScopeAsync(TableRegistry.Worker, null, async context =>
            {
                await purge.PurgeAsync(context, Cancellation);
                return 0;
            }));
        }
    }

    /// <summary>Identity's purge, by reflection: this project references Identity only through Operations.</summary>
    private static ITenantPurge IdentityPurge() =>
        (ITenantPurge)Type.GetType("Gatekeep.Modules.Identity.Contracts.IdentityContract, Gatekeep.Modules.Identity", throwOnError: true)!
            .GetProperty("TenantPurge")!.GetValue(null)!;

    /// <summary>Starts the Tenant's deletion as its Deployment Owner would, through Management, in a Deployment scope as gk_admin.</summary>
    internal static async Task<TenantDeletionResult> DeleteAsync(JobDatabase database, Guid tenant, string host)
    {
        var admin = Guid.CreateVersion7();
        await database.SuperuserAsync($"INSERT INTO admin (id, deployment_owner) VALUES ('{admin}', true)");
        var management = ManagementContract.CreateTenants(AuditContract.CreateAppender(), new TenantAddressing(TestTenants.Zone));

        var result = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            management.DeleteAsync(context, new AdminPrincipal(admin, true), tenant, host, Cancellation));

        Assert.Equal(TenantDeletionStatus.Started, result.Status);
        return result;
    }
}
