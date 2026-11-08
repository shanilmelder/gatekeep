using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Gatekeep.Tests.Isolation.Tenancy;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Operations;

/// <summary>
/// Story 1.29 (AD-10, AD-16, AD-30): <c>tenancy.tenant.delete</c> through the real job path. Its
/// purge stage calls every module's purge in the Tenant's own scope, its destroy stage destroys the
/// six secret class keys through the Worker's custody, and its completion purges the job payloads,
/// marks the Tenant deleted with <c>tenancy.tenant.deleted</c> on its own chain and schedules the
/// chain's purge 90 days after that event, whatever the label. Each stage re-checks the Tenant is
/// deleting; a failed stage is retried alone; and the chain itself is never purged with the data.
/// </summary>
public sealed class TenantDeletionOperationTests(PostgresFixture postgres)
{
    private const string Deleted = "tenancy.tenant.deleted";

    private static readonly string[] SecretClassPrefixes = ["totp", "social", "email", "payload", "hmac", "tpk"];

    [Theory]
    [InlineData("dev")]
    [InlineData("staging")]
    [InlineData("prod")]
    public async Task Operation_purges_destroys_and_marks_the_Tenant_deleted_whatever_its_label(string label)
    {
        var (database, tenant, _) = await ActiveAsync(label);
        await TenantSeeds.SeedAsync(Superuser(database), tenant);
        var events = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'");
        // Story 2.8: its creation wrote its system Application, which only this purge may delete.
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND kind = 'system'"));
        var (operation, _) = await DeleteAsync(database, tenant);
        var custody = new RecordingCustody();

        await DrainAsync(database, custody);

        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("succeeded/succeeded", await StepsAsync(database, operation));
        Assert.Equal("deleted", await StatusAsync(database, tenant));
        Assert.Empty(await TenantSeeds.RowsLeftAsync(Superuser(database), tenant));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}'"));
        // The six secret class keys first, then only this Tenant's Signing and Management keys (Story 2.3).
        Assert.Equal([.. SecretClassPrefixes.Select(p => $"{p}-{tenant:D}")], custody.Deleted.Take(6));
        Assert.All(custody.Deleted.Skip(6), name => Assert.True(KeyName.TryParseRowKey(name, out var key) && key.TenantId == tenant, name));

        // The deletion's own event closes the chain, and every earlier event is kept.
        Assert.Equal(
            1L,
            await database.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Deleted}' AND actor_kind = 'system' AND target_kind = 'tenant' AND target_id = '{tenant}'"));
        Assert.Equal(events + 1, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}'"));

        // One purge job, due no sooner than 90 days after the deleted event: the label isn't read.
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = 'audit.chain.purge' AND tenant_id = '{tenant}' AND status = 'pending'"));
        Assert.True(await database.ScalarAsync<bool>(
            $"SELECT j.run_after >= e.occurred_at + interval '90 days' FROM job j, audit_event e " +
            $"WHERE j.type = 'audit.chain.purge' AND j.tenant_id = '{tenant}' AND e.tenant_id = '{tenant}' AND e.type_code = '{Deleted}'"));
        Assert.Equal(label, await database.ScalarAsync<string>($"SELECT label FROM tenant WHERE id = '{tenant}'"));
    }

    [Fact]
    public async Task Operation_leaves_the_other_Tenants_rows_and_their_creation_alone()
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        await TenantSeeds.SeedAsync(Superuser(database), TenantB);
        var before = await TenantSeeds.SnapshotAsync(Superuser(database), TenantB);
        await DeleteAsync(database, tenant);

        await DrainAsync(database, new RecordingCustody());

        Assert.Equal(before, await TenantSeeds.SnapshotAsync(Superuser(database), TenantB));
        Assert.Equal("active", await StatusAsync(database, TenantB));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Custody_down_fails_only_the_destroy_step_and_leaves_the_Tenant_deleting(bool configured)
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        var (operation, _) = await DeleteAsync(database, tenant);

        await DrainAsync(database, configured ? new RecordingCustody { Fail = true } : null);

        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("succeeded/failed:custody_unavailable", await StepsAsync(database, operation, withCodes: true));
        Assert.Equal("deleting", await StatusAsync(database, tenant));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Deleted}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'audit.chain.purge'"));
    }

    [Fact]
    public async Task Retry_reruns_only_the_failed_step_then_deletes_once()
    {
        var (database, tenant, admin) = await ActiveAsync("dev");
        var (operation, _) = await DeleteAsync(database, tenant, admin);
        await DrainAsync(database, custody: null);

        var retried = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().RetryDeletionAsync(context, new AdminPrincipal(admin, true), tenant, Cancellation));
        Assert.Equal(OperationRetryStatus.Retried, retried.Status);
        Assert.Equal(["succeeded", "pending"], retried.Operation!.Steps.Select(s => s.Status.ToString().ToLowerInvariant()));
        Assert.Equal(
            1L,
            await database.ScalarAsync<long>(
                $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried' AND actor_id = '{admin}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));

        await DrainAsync(database, new RecordingCustody());

        Assert.Equal("deleted", await StatusAsync(database, tenant));
        Assert.Equal("1/2", await database.ScalarAsync<string>(
            $"SELECT string_agg(attempts::text, '/' ORDER BY position) FROM operation_step WHERE operation_id = '{operation}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Deleted}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'audit.chain.purge'"));
    }

    /// <summary>A rerun of a stage, and of the completion's marking, deletes, destroys and writes nothing more.</summary>
    [Fact]
    public async Task Rerun_stages_and_completion_change_nothing_more()
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        var (operation, _) = await DeleteAsync(database, tenant);
        await DrainAsync(database, new RecordingCustody { Fail = true });

        // The purge stage ran once and succeeded. Reopen both steps, as a crash before its commit
        // would have left them, and run the Operation again: the purge finds nothing left.
        await database.SuperuserAsync(
            $"UPDATE operation_step SET status = 'pending', result_code = NULL WHERE operation_id = '{operation}'; " +
            $"UPDATE operation SET status = 'running', finished_at = NULL WHERE id = '{operation}'; " +
            $"SET session_replication_role = replica; INSERT INTO job (id, type, deployment_wide, operation_id) VALUES (gen_random_uuid(), 'operations.operation.run', true, '{operation}'); " +
            "SET session_replication_role = DEFAULT");
        var custody = new RecordingCustody();
        await DrainAsync(database, custody);

        Assert.Equal("deleted", await StatusAsync(database, tenant));
        Assert.Equal([.. SecretClassPrefixes.Select(p => $"{p}-{tenant:D}")], custody.Deleted.Take(6));

        // The completion's marking again: the Tenant is deleted already, so nothing is written.
        var tenants = TenancyContract.CreateTenants(AuditContract.CreateAppender());
        Assert.False(await database.InScopeAsync(TableRegistry.Worker, tenant, context => tenants.MarkDeletedAsync(context, tenant, Cancellation)));

        // And the destroy stage on keys already gone succeeds.
        await Gatekeep.Modules.Keys.Contracts.KeysContract.DestroySecretClassKeysAsync(custody, tenant, Cancellation);

        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Deleted}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'audit.chain.purge'"));
    }

    /// <summary>
    /// The completion ends the deleted Tenant's other pending jobs dead as <c>tenant_deleted</c>, so
    /// none is left orphaned, deletes their payloads, and keeps the chain's purge it schedules.
    /// </summary>
    [Fact]
    public async Task Completion_ends_the_Tenants_pending_jobs_dead_and_keeps_its_chain_purge()
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        await TenantSeeds.SeedAsync(Superuser(database), tenant);
        var pending = await database.ScalarAsync<Guid>($"SELECT id FROM job WHERE tenant_id = '{tenant}' AND type = 'audit.retention.apply' AND status = 'pending'");
        // A retired key's pending destruction (Story 2.4) ends dead with the rest: its row is purged.
        var destroy = Guid.CreateVersion7();
        await database.SuperuserAsync(
            $"SET session_replication_role = replica; INSERT INTO job (id, type, tenant_id, deployment_wide, run_after) VALUES ('{destroy}', 'keys.signing_key.destroy', '{tenant}', false, now() + interval '1 day'); SET session_replication_role = DEFAULT");
        await DeleteAsync(database, tenant);

        await DrainAsync(database, new RecordingCustody());

        Assert.Equal("dead|tenant_deleted", await database.ScalarAsync<string>($"SELECT status || '|' || failure_code FROM job WHERE id = '{pending}'"));
        Assert.Equal("dead|tenant_deleted", await database.ScalarAsync<string>($"SELECT status || '|' || failure_code FROM job WHERE id = '{destroy}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job_payload WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{tenant}' AND status IN ('pending', 'running') AND type <> 'audit.chain.purge'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{tenant}' AND type = 'audit.chain.purge' AND status = 'pending'"));
    }

    /// <summary>The whole completion handler again, for a Tenant it already marked deleted: nothing is written.</summary>
    [Fact]
    public async Task Completion_run_again_writes_nothing()
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        var (operation, _) = await DeleteAsync(database, tenant);
        await DrainAsync(database, new RecordingCustody());
        var before = await TenantSeeds.SnapshotAsync(Superuser(database), tenant);
        var jobs = await database.ScalarAsync<string>($"SELECT string_agg(id::text || status, ',' ORDER BY id) FROM job WHERE tenant_id = '{tenant}'");

        var handler = OperationsContract.ProductionOperationRegistry.Find(OperationsContract.TenantDeletionOperation)!.OnSucceeded!;
        await database.InScopeAsync(TableRegistry.Worker, tenant, async context =>
        {
            var completion = (OperationCompletion)Activator.CreateInstance(
                typeof(OperationCompletion),
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                binder: null,
                args: [operation, tenant, context],
                culture: null)!;
            await handler(completion, Cancellation);
            return 0;
        });

        Assert.Equal(before, await TenantSeeds.SnapshotAsync(Superuser(database), tenant));
        Assert.Equal(jobs, await database.ScalarAsync<string>($"SELECT string_agg(id::text || status, ',' ORDER BY id) FROM job WHERE tenant_id = '{tenant}'"));
    }

    /// <summary>
    /// A deleted Tenant's chain purge is never lost: the daily sweep schedules it again when its job
    /// went dead, or was never enqueued, and leaves a purged chain alone.
    /// </summary>
    [Theory]
    [InlineData("dead")]
    [InlineData("missing")]
    public async Task Sweep_schedules_a_deleted_Tenants_chain_purge_again(string state)
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        await DeleteAsync(database, tenant);
        await DrainAsync(database, new RecordingCustody());
        await database.SuperuserAsync(state == "dead"
            ? $"UPDATE job SET status = 'dead', finished_at = now(), failure_code = 'handler_failed' WHERE tenant_id = '{tenant}' AND type = 'audit.chain.purge'"
            : $"DELETE FROM job WHERE tenant_id = '{tenant}' AND type = 'audit.chain.purge'");

        await database.InScopeAsync(TableRegistry.Worker, null, context =>
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null)
                .EnqueueAsync(context, OperationsContract.SweepRetention, operationId: null, runAfter: null, Cancellation));
        await DrainAsync(database, new RecordingCustody());

        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{tenant}' AND type = 'audit.chain.purge' AND status = 'pending'"));
        Assert.True(await database.ScalarAsync<bool>(
            $"SELECT j.run_after >= e.occurred_at + interval '90 days' FROM job j, audit_event e " +
            $"WHERE j.type = 'audit.chain.purge' AND j.status = 'pending' AND j.tenant_id = '{tenant}' AND e.tenant_id = '{tenant}' AND e.type_code = '{Deleted}'"));

        // A live Tenant gets no purge, and a deleted one whose chain is gone gets none either.
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{TenantB}' AND type = 'audit.chain.purge'"));
        await database.SuperuserAsync(
            $"DELETE FROM job WHERE tenant_id = '{tenant}' AND type = 'audit.chain.purge'; " +
            $"SET session_replication_role = replica; DELETE FROM audit_detail WHERE tenant_id = '{tenant}'; DELETE FROM audit_event WHERE tenant_id = '{tenant}'; SET session_replication_role = DEFAULT");
        await database.InScopeAsync(TableRegistry.Worker, null, context =>
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null)
                .EnqueueAsync(context, OperationsContract.SweepRetention, operationId: null, runAfter: null, Cancellation));
        await DrainAsync(database, new RecordingCustody());
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job WHERE tenant_id = '{tenant}' AND type = 'audit.chain.purge'"));
    }

    /// <summary>A deletion Operation for a Tenant that isn't deleting, built by a test: both stages refuse it.</summary>
    [Fact]
    public async Task Stages_refuse_a_Tenant_that_isnt_deleting()
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        await TenantSeeds.SeedAsync(Superuser(database), tenant);
        var operation = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry).StartAsync(
                context,
                OperationsContract.TenantDeletionOperation,
                tenant,
                [
                    new OperationStepPlan(OperationsContract.TenantPurgeStage, tenant),
                    new OperationStepPlan(OperationsContract.SecretClassKeysDestroyStage, tenant),
                ],
                Cancellation));
        var custody = new RecordingCustody();

        await DrainAsync(database, custody);

        Assert.Equal("failed:tenant_not_deleting/failed:tenant_not_deleting", await StepsAsync(database, operation.Id, withCodes: true));
        Assert.Equal("active", await StatusAsync(database, tenant));
        Assert.Empty(custody.Deleted);
        Assert.Equal(TenantSeeds.Seeds.Select(s => s.Table), await TenantSeeds.RowsLeftAsync(Superuser(database), tenant));
    }

    [Fact]
    public async Task Deletion_is_one_Operation_per_Tenant_and_starts_only_scoped_to_it()
    {
        var (database, tenant, _) = await ActiveAsync("dev");
        var operations = OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry);

        // Its completion runs in its own Tenant's scope, so a Deployment-scoped start is refused.
        await Assert.ThrowsAsync<ArgumentException>(() => database.InScopeAsync(TableRegistry.Admin, null, context =>
            operations.StartAsync(context, OperationsContract.TenantDeletionOperation, null, [new OperationStepPlan(OperationsContract.TenantPurgeStage, tenant)], Cancellation)));

        var (operation, _) = await DeleteAsync(database, tenant);
        var latest = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            operations.FindLatestAsync(context, OperationsContract.TenantDeletionOperation, tenant, Cancellation));
        Assert.Equal(operation, latest!.Id);
        Assert.Equal(2, latest.Steps.Count);
    }

    private static ITenantManagement Management() =>
        ManagementContract.CreateTenants(AuditContract.CreateAppender(), new TenantAddressing("gatekeep.test"));

    private string Superuser(JobDatabase database) => postgres.SuperuserConnection(database.Name);

    /// <summary>A fresh database with a Deployment Owner who has created Acme and whose creation has run: the Tenant is active.</summary>
    private async Task<(JobDatabase Database, Guid Tenant, Guid Admin)> ActiveAsync(string label)
    {
        var database = await CreateAsync(postgres, registry: null);
        var admin = Guid.CreateVersion7();
        await database.SuperuserAsync($"INSERT INTO admin (id, deployment_owner) VALUES ('{admin}', true)");

        var result = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().CreateAsync(context, new AdminPrincipal(admin, true), new CreateTenantInput("Acme", "acme", label), Cancellation));
        Assert.Equal(TenantCreationStatus.Created, result.Status);

        await DrainAsync(database, new RecordingCustody());
        Assert.Equal("active", await StatusAsync(database, result.Tenant!.Id));
        return (database, result.Tenant.Id, admin);
    }

    private static async Task<(Guid Operation, Guid Admin)> DeleteAsync(JobDatabase database, Guid tenant, Guid? admin = null)
    {
        var owner = admin ?? await database.ScalarAsync<Guid>("SELECT id FROM admin WHERE deployment_owner LIMIT 1");
        var host = await database.ScalarAsync<string>($"SELECT host FROM tenant_host WHERE tenant_id = '{tenant}'");
        var result = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().DeleteAsync(context, new AdminPrincipal(owner, true), tenant, host, Cancellation));
        Assert.Equal(TenantDeletionStatus.Started, result.Status);
        return (result.Operation!.Id, owner);
    }

    private static async Task DrainAsync(JobDatabase database, Gatekeep.Kernel.Secrets.IKeyCustody? custody)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry, custody);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }

    private static Task<string> StatusAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{tenant}'");

    private static Task<string> StepsAsync(JobDatabase database, Guid operation, bool withCodes = false) =>
        database.ScalarAsync<string>(
            "SELECT string_agg(status" + (withCodes ? " || CASE WHEN status = 'failed' THEN ':' || coalesce(result_code, '') ELSE '' END" : string.Empty) +
            $", '/' ORDER BY position) FROM operation_step WHERE operation_id = '{operation}'");
}
