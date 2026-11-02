using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Xunit;
using static Gatekeep.Tests.Isolation.Audit.AuditChains;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// AD-16: a deleted Tenant's chain stays until its retention ends, then the
/// <c>audit.chain.purge</c> Operation deletes it whole, as <c>gk_retention</c>.
/// </summary>
public sealed class PurgeTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Purge_deletes_a_whole_chain_past_retention_and_its_detail_only()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA, TenantB);
        await chains.SealedChainAsync(TenantA, 3, 1, 2, 3);
        await chains.SealedChainAsync(TenantB, 2, 1, 2);

        Assert.True(await chains.PurgeAsync(TenantA));

        Assert.Equal(0, await chains.CountAsync("audit_event", TenantA));
        Assert.Equal(0, await chains.CountAsync("audit_detail", TenantA));
        Assert.Equal(2, await chains.CountAsync("audit_event", TenantB));
        Assert.Equal(2, await chains.CountAsync("audit_detail", TenantB));

        // Nothing is left, so a rerun is done too.
        Assert.True(await chains.PurgeAsync(TenantA));
    }

    [Fact]
    public async Task Purge_inside_retention_deletes_nothing()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3, 1, 2);

        Assert.False(await chains.PurgeAsync(TenantA));

        Assert.Equal(3, await chains.CountAsync("audit_event", TenantA));
        Assert.Equal(3, await chains.CountAsync("audit_detail", TenantA));
    }

    [Fact]
    public async Task Purge_with_an_unsealed_row_deletes_nothing()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 2, 1, 2);
        await chains.AppendAsync(TenantA, 1);
        await chains.SuperuserAsync(
            """
            SET session_replication_role = replica;
            UPDATE audit_event SET occurred_at = occurred_at - interval '100 days' WHERE seq IS NULL;
            """);

        Assert.False(await chains.PurgeAsync(TenantA));
        Assert.Equal(3, await chains.CountAsync("audit_event", TenantA));
    }

    [Fact]
    public async Task Deployment_chain_is_never_purged()
    {
        var chains = await AuditChains.CreateAsync(postgres);

        await Assert.ThrowsAsync<InvalidOperationException>(() => chains.InScopeAsync(TableRegistry.Retention, null, context =>
            AuditContract.CreateRetention().PurgeAsync(context, Cancellation)));
    }

    [Fact]
    public async Task Started_purge_Operation_past_retention_leaves_the_Tenant_no_audit_rows()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA, TenantB);
        await chains.SealedChainAsync(TenantA, 3, 1, 2, 3);
        await chains.SealedChainAsync(TenantB, 1);

        var started = await StartPurgeAsync(chains, TenantA);
        await DrainAsync(chains);

        Assert.Equal(0, await chains.CountAsync("audit_event", TenantA));
        Assert.Equal(0, await chains.CountAsync("audit_detail", TenantA));
        Assert.Equal(1, await chains.CountAsync("audit_event", TenantB));

        var operation = await chains.InScopeAsync(TableRegistry.Admin, null, context =>
            OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry).GetAsync(context, started.Id, Cancellation));
        Assert.Equal(OperationStatus.Succeeded, operation!.Status);
        Assert.Equal(
            "done",
            await chains.ScalarAsync<string>($"SELECT status FROM job WHERE type = '{OperationsContract.PurgeChain}' AND tenant_id = '{TenantA}'"));
    }

    [Fact]
    public async Task Purge_job_inside_retention_waits_then_fails_with_a_fixed_code_and_deletes_nothing()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 2);

        await StartPurgeAsync(chains, TenantA);
        await DrainAsync(chains);

        // The job is due once the newest event is 90 days old, so it isn't run yet.
        var purgeJob = $"FROM job WHERE type = '{OperationsContract.PurgeChain}' AND tenant_id = '{TenantA}'";
        Assert.Equal("pending", await chains.ScalarAsync<string>($"SELECT status {purgeJob}"));
        Assert.True(await chains.ScalarAsync<bool>($"SELECT run_after > now() + interval '89 days' {purgeJob}"));

        // Run early anyway, it throws: a fixed code, a retry, and nothing deleted.
        await chains.SuperuserAsync($"UPDATE job SET run_after = now() WHERE type = '{OperationsContract.PurgeChain}'");
        await using (var runner = Runner(chains))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal(
            "pending|handler_failed|1",
            await chains.ScalarAsync<string>($"SELECT status || '|' || failure_code || '|' || attempts {purgeJob}"));
        Assert.Equal(2, await chains.CountAsync("audit_event", TenantA));
        Assert.Equal(2, await chains.CountAsync("audit_detail", TenantA));
    }

    private static Task<OperationResource> StartPurgeAsync(AuditChains chains, Guid tenantId) =>
        chains.InScopeAsync(TableRegistry.Admin, null, context =>
            OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry).StartAsync(
                context,
                OperationsContract.PurgeChainOperation,
                tenantId,
                [new OperationStepPlan(OperationsContract.PurgeChainStage, tenantId)],
                Cancellation));

    private static IJobRunner Runner(AuditChains chains) => OperationsContract.CreateRunner(
        OperationsContract.ProductionRegistry,
        new JobDatabases(
            chains.Connection(TableRegistry.Dispatch),
            chains.Connection(TableRegistry.Worker),
            chains.Connection(TableRegistry.Sealer),
            chains.Connection(TableRegistry.Retention)),
        JobDatabase.FastOptions,
        custody: null,
        logger: null);

    /// <summary>Runs every due job, the Operation's fan-out included, until none is left.</summary>
    private static async Task DrainAsync(AuditChains chains)
    {
        await using var runner = Runner(chains);

        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }
}
