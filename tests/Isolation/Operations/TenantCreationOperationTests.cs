using System.Collections.Concurrent;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Operations;

/// <summary>
/// Story 1.27 (AD-10, AD-30): <c>tenancy.tenant.create</c> through the real job path. Its first stage
/// creates the six secret class keys through the Worker's custody, and from Story 2.3 its second the
/// Signing and Management keys and the wrapped token protection key; its completion handler, in the
/// transaction that marks it succeeded and in the Tenant's own scope, inserts the settings row,
/// makes the Tenant active and writes <c>tenancy.tenant.activated</c>, exactly once. A dead run or
/// step job fails its steps, so the Operation fails and Retry applies.
/// </summary>
public sealed class TenantCreationOperationTests(PostgresFixture postgres)
{
    private const string Activated = "tenancy.tenant.activated";

    private static readonly string[] SecretClassPrefixes = ["totp", "social", "email", "payload", "hmac", "tpk"];

    [Fact]
    public async Task Operation_creates_the_keys_then_the_settings_and_activates_the_Tenant()
    {
        var (database, tenant, operation, _) = await CreatedAsync();
        var custody = new RecordingCustody();

        Assert.Equal("creating", await StatusAsync(database, tenant));
        await DrainAsync(database, custody);

        Assert.Superset(SecretClassPrefixes.Select(p => $"{p}-{tenant:D}").ToHashSet(), custody.Created.ToHashSet());
        Assert.Equal(2, custody.Created.Count(n => n.StartsWith($"sig-{tenant:D}-", StringComparison.Ordinal)));
        Assert.Equal(2, custody.Created.Count(n => n.StartsWith($"mgmt-{tenant:D}-", StringComparison.Ordinal)));
        Assert.Equal(KeyRows, await KeyRowsAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal(Both("succeeded/succeeded"), await StepAsync(database, operation));
        Assert.Equal("active", await StatusAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(
            1L,
            await database.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Activated}' AND actor_kind = 'system' AND target_id IS NULL"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{Activated}'"));

        // Story 2.8: exactly one bare system Application, with no secret and no event of its own.
        var system = await SystemApplicationAsync(database, tenant);
        Assert.Equal(
            1L,
            await database.ScalarAsync<long>(
                $"SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND id = '{system}' AND name = '{DirectoryContract.SystemApplicationName}' AND grant_types = '{{}}' AND audiences = '{{}}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM client_secret WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE target_id = '{system}'"));

        // Story 3.6: the built-in Management API with its 18 Permissions, and no event of its own.
        await AssertBuiltInApiAsync(database, tenant);
    }

    /// <summary>Story 3.6: the Tenant's one built-in Management API, with exactly Directory's Management Permissions and no event.</summary>
    private static async Task AssertBuiltInApiAsync(JobDatabase database, Guid tenant)
    {
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM api WHERE tenant_id = '{tenant}' AND built_in AND name = '{DirectoryContract.ManagementApiName}' AND identifier = '{DirectoryContract.ManagementApiIdentifier}' AND NOT offline_access AND NOT rbac"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{tenant}'"));
        Assert.Equal(
            string.Join(",", DirectoryContract.ManagementPermissions.Order(StringComparer.Ordinal)),
            await database.ScalarAsync<string>($"SELECT string_agg(value, ',' ORDER BY value COLLATE \"C\") FROM permission WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND target_kind = 'api'"));
    }

    /// <summary>Story 2.8: the whole completion handler again, for the Tenant it already activated: still one system Application.</summary>
    [Fact]
    public async Task Completion_run_again_keeps_the_one_system_Application()
    {
        var (database, tenant, operation, _) = await CreatedAsync();
        await DrainAsync(database, new RecordingCustody());
        var system = await SystemApplicationAsync(database, tenant);

        await RunCompletionAsync(database, operation, tenant);

        Assert.Equal(system, await SystemApplicationAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Activated}'"));
        await AssertBuiltInApiAsync(database, tenant);
    }

    /// <summary>Story 2.8: a completion for a Tenant whose deletion started activates nothing, so no system Application is written.</summary>
    [Fact]
    public async Task Completion_for_a_deleting_Tenant_writes_no_system_Application()
    {
        var (database, tenant, operation, _) = await CreatedAsync();
        await database.SuperuserAsync($"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{tenant}'; SET session_replication_role = DEFAULT");

        await RunCompletionAsync(database, operation, tenant);

        Assert.Equal("deleting", await StatusAsync(database, tenant));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}'"));
    }

    [Fact]
    public async Task Step_rerun_after_a_crash_keeps_the_keys_and_activates_once()
    {
        var (database, tenant, operation, _) = await CreatedAsync();

        // The keys.signing step creates its first Signing Key in Transit, then outlives its lease:
        // its transaction rolls back, and the Transit key it made is left unnamed. Jobs run until
        // that step has hung, whichever order the two step jobs are claimed in.
        var custody = new RecordingCustody { HangOn = n => n.StartsWith("sig-", StringComparison.Ordinal) };
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, custody, options: FastOptions with { Lease = TimeSpan.FromSeconds(2) }))
        {
            for (var i = 0; i < 3 && !custody.Hung; i++)
            {
                Assert.True(await runner.RunOnceAsync(Cancellation));
            }
        }

        Assert.True(custody.Hung);
        Assert.Single(custody.Created, n => n.StartsWith("sig-", StringComparison.Ordinal));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}'"));
        Assert.Equal("creating", await StatusAsync(database, tenant));
        Assert.Equal("running", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        await database.SuperuserAsync("UPDATE job SET run_after = now() WHERE status = 'pending'");

        custody.HangOn = null;
        await DrainAsync(database, custody);

        Assert.All(custody.Versions.Values, v => Assert.Equal(1, v));
        Assert.Equal("active", await StatusAsync(database, tenant));
        // Exactly one current and one next per purpose, whatever the crashed attempt made in Transit.
        Assert.Equal(KeyRows, await KeyRowsAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = 'keys.tenant_keys.provisioned'"));
        // The crashed attempt rolled back with its transaction; its job counts both.
        Assert.Equal("1,1", await database.ScalarAsync<string>($"SELECT string_agg(attempts::text, ',' ORDER BY position) FROM operation_step WHERE operation_id = '{operation}'"));
        Assert.Equal(2, await database.ScalarAsync<int>("SELECT max(attempts) FROM job WHERE type = 'operations.operation.step'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Activated}'"));
    }

    [Fact]
    public async Task Two_runners_finish_and_activate_exactly_once()
    {
        var (database, tenant, operation, _) = await CreatedAsync();
        var custody = new RecordingCustody();

        await using var first = database.Runner(OperationsContract.ProductionRegistry, custody);
        await using var second = database.Runner(OperationsContract.ProductionRegistry, custody);
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        limit.CancelAfter(TimeSpan.FromSeconds(60));

        async Task RunAsync(IJobRunner runner)
        {
            while (await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'") == "running")
            {
                if (!await runner.RunOnceAsync(limit.Token))
                {
                    await Task.Delay(20, limit.Token);
                }
            }
        }

        await Task.WhenAll(RunAsync(first), RunAsync(second));

        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("active", await StatusAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Activated}'"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Custody_down_fails_the_step_and_leaves_the_Tenant_creating(bool configured)
    {
        var (database, tenant, operation, _) = await CreatedAsync();

        await DrainAsync(database, configured ? new RecordingCustody { Fail = true } : null);

        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal(Both("failed/custody_unavailable"), await StepAsync(database, operation));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal("creating", await StatusAsync(database, tenant));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Activated}'"));
    }

    /// <summary>Story 1.29: a creation stage for a Tenant whose deletion started creates no key, and nothing activates it.</summary>
    [Fact]
    public async Task Creation_stage_for_a_deleting_Tenant_creates_no_key()
    {
        var (database, tenant, operation, _) = await CreatedAsync();
        await database.SuperuserAsync($"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{tenant}'; SET session_replication_role = DEFAULT");
        var custody = new RecordingCustody();

        await DrainAsync(database, custody);

        Assert.Empty(custody.Created);
        // Both stages, the Signing Keys too (after Story 2.3): no row and no key.
        Assert.Equal(Both("failed/tenant_not_creating"), await StepAsync(database, operation));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("deleting", await StatusAsync(database, tenant));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}'"));
    }

    /// <summary>Story 1.29: activation locks the Tenant and does nothing, settings included, to one that isn't creating.</summary>
    [Theory]
    [InlineData("deleting")]
    [InlineData("deleted")]
    public async Task Activation_of_a_Tenant_that_isnt_creating_writes_nothing(string status)
    {
        var (database, tenant, _, _) = await CreatedAsync();
        await database.SuperuserAsync($"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{tenant}'; SET session_replication_role = DEFAULT");
        if (status == "deleted")
        {
            await database.SuperuserAsync($"SET session_replication_role = replica; UPDATE tenant SET status = 'deleted' WHERE id = '{tenant}'; SET session_replication_role = DEFAULT");
        }

        var activated = await database.InScopeAsync(TableRegistry.Worker, tenant, context =>
            Gatekeep.Modules.Tenancy.Contracts.TenancyContract.CreateTenants(AuditContract.CreateAppender()).ActivateAsync(context, tenant, Cancellation));

        Assert.False(activated);
        Assert.Equal(status, await StatusAsync(database, tenant));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_settings WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{Activated}'"));
    }

    [Fact]
    public async Task Retry_reruns_only_the_failed_step_and_then_activates()
    {
        var (database, tenant, operation, admin) = await CreatedAsync();
        await DrainAsync(database, custody: null);
        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));

        var retried = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().RetryCreationAsync(context, new AdminPrincipal(admin, true), operation, Cancellation));

        Assert.Equal(OperationRetryStatus.Retried, retried.Status);
        Assert.Equal(ManagedOperationStatus.Running, retried.Operation!.Status);
        Assert.Equal(
            1L,
            await database.ScalarAsync<long>(
                $"SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.operation.retried' AND actor_id = '{admin}' AND target_kind = 'tenant' AND target_id = '{tenant}'"));

        var again = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().RetryCreationAsync(context, new AdminPrincipal(admin, true), operation, Cancellation));
        Assert.Equal(OperationRetryStatus.NotFailed, again.Status);

        await DrainAsync(database, new RecordingCustody());

        Assert.Equal(Both("succeeded/succeeded"), await StepAsync(database, operation));
        Assert.Equal("active", await StatusAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Activated}'"));
    }

    [Fact]
    public async Task Dead_run_job_fails_the_open_steps_and_Retry_works()
    {
        var (database, tenant, operation, admin) = await CreatedAsync();

        // The run job's last attempt was claimed and lost: the next claim finds it out of attempts.
        await database.SuperuserAsync("UPDATE job SET attempts = 5 WHERE type = 'operations.operation.run'");
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody()))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("dead", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'operations.operation.run'"));
        Assert.Equal(Both("failed/job_dead"), await StepAsync(database, operation));
        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.job.dead'"));

        var retried = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().RetryCreationAsync(context, new AdminPrincipal(admin, true), operation, Cancellation));
        Assert.Equal(OperationRetryStatus.Retried, retried.Status);

        await DrainAsync(database, new RecordingCustody());
        Assert.Equal("active", await StatusAsync(database, tenant));
    }

    [Fact]
    public async Task Dead_step_job_fails_its_step_and_the_Operation()
    {
        var (database, tenant, operation, _) = await CreatedAsync();

        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody()))
        {
            // The run job dispatches the step job, which then has no attempt left.
            Assert.True(await runner.RunOnceAsync(Cancellation));
            await database.SuperuserAsync("UPDATE job SET attempts = 5 WHERE type = 'operations.operation.step'");
            // Both step jobs, one per creation stage.
            Assert.True(await runner.RunOnceAsync(Cancellation));
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("dead", await database.ScalarAsync<string>("SELECT string_agg(DISTINCT status, ',') FROM job WHERE type = 'operations.operation.step'"));
        Assert.Equal(Both("failed/job_dead"), await StepAsync(database, operation));
        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("creating", await StatusAsync(database, tenant));
        Assert.Equal(2L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = 'operations.job.dead'"));
    }

    [Fact]
    public async Task Dead_job_of_another_kind_leaves_Operations_alone()
    {
        var (database, _, operation, _) = await CreatedAsync();
        await database.InScopeAsync(TableRegistry.Worker, null, "INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), 'operations.job.purge', true)");
        await database.SuperuserAsync("UPDATE job SET attempts = 5, run_after = now() - interval '1 hour' WHERE type = 'operations.job.purge'");

        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody()))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("dead", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'operations.job.purge'"));
        Assert.Equal(Both("pending/"), await StepAsync(database, operation));
        Assert.Equal("running", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
    }

    [Fact]
    public async Task Creation_is_one_Operation_per_Tenant_and_the_list_finds_it()
    {
        var (database, tenant, operation, admin) = await CreatedAsync();

        var page = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().ListAsync(context, new AdminPrincipal(admin, true), after: null, limit: 50, Cancellation));

        // The fixture's own Tenants have no host, so only the created one is listed.
        var created = Assert.Single(page!.Tenants);
        Assert.Equal(tenant, created.Id);
        Assert.Equal("creating", created.Status);
        Assert.Equal("acme-dev.gatekeep.test", created.Host);
        Assert.Equal(operation, created.Creation!.OperationId);
        Assert.Equal(ManagedOperationStatus.Running, created.Creation.Status);
        Assert.Null(page.NextAfter);
    }

    [Fact]
    public async Task Dead_run_job_leaves_a_dispatched_step_to_its_own_job()
    {
        var (database, tenant, operation, _) = await CreatedAsync();
        await using var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody());

        // The run job dispatches the step; then a second run job for the Operation dies.
        Assert.True(await runner.RunOnceAsync(Cancellation));
        await database.SuperuserAsync(
            "SET session_replication_role = replica; " +
            $"INSERT INTO job (id, type, deployment_wide, operation_id, status, attempts, run_after) VALUES (gen_random_uuid(), 'operations.operation.run', true, '{operation}', 'pending', 5, now() - interval '1 hour'); " +
            "SET session_replication_role = DEFAULT");
        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'operations.operation.run' AND status = 'dead'"));
        Assert.Equal(Both("running/"), await StepAsync(database, operation));
        Assert.Equal("running", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));

        // The step job still runs it, and the creation succeeds.
        while (await runner.RunOnceAsync(Cancellation))
        {
        }

        Assert.Equal(Both("succeeded/succeeded"), await StepAsync(database, operation));
        Assert.Equal("active", await StatusAsync(database, tenant));
    }

    [Fact]
    public async Task Dead_step_job_without_its_payload_fails_its_Operations_open_steps()
    {
        var (database, tenant, operation, _) = await CreatedAsync();

        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody()))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
            Assert.Equal(operation, await database.ScalarAsync<Guid>("SELECT operation_id FROM job WHERE type = 'operations.operation.step'"));
            await database.SuperuserAsync(
                "DELETE FROM job_payload; UPDATE job SET attempts = 5 WHERE type = 'operations.operation.step'");
            // Both step jobs, one per creation stage.
            Assert.True(await runner.RunOnceAsync(Cancellation));
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("dead", await database.ScalarAsync<string>("SELECT string_agg(DISTINCT status, ',') FROM job WHERE type = 'operations.operation.step'"));
        Assert.Equal(Both("failed/job_dead"), await StepAsync(database, operation));
        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal("creating", await StatusAsync(database, tenant));
    }

    [Fact]
    public async Task A_failure_failing_the_steps_never_keeps_the_job_from_dying()
    {
        var (database, _, operation, _) = await CreatedAsync();
        await database.SuperuserAsync(
            """
            CREATE FUNCTION test_refuse_job_dead() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.result_code = 'job_dead' THEN RAISE EXCEPTION 'test refusal'; END IF;
              RETURN NEW;
            END $$;
            CREATE TRIGGER test_refuse_job_dead BEFORE UPDATE ON operation_step FOR EACH ROW EXECUTE FUNCTION test_refuse_job_dead();
            UPDATE job SET attempts = 5 WHERE type = 'operations.operation.run';
            """);

        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, new RecordingCustody()))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));

            // Dead, and not claimed again.
            Assert.False(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("dead", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'operations.operation.run'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event WHERE type_code = 'operations.job.dead'"));
        Assert.Equal(Both("pending/"), await StepAsync(database, operation));
        await database.SuperuserAsync("DROP TRIGGER test_refuse_job_dead ON operation_step");
    }

    [Fact]
    public async Task Creation_starts_only_scoped_to_one_Tenant_with_its_steps_for_it()
    {
        var database = await CreateAsync(postgres, registry: null);
        var operations = OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry);

        foreach (var (tenantId, steps) in new (Guid?, OperationStepPlan[])[]
        {
            (null, [new(OperationsContract.TenantCreationStage, TenantA)]),
            (TenantA, [new(OperationsContract.TenantCreationStage, TenantB)]),
        })
        {
            await database.InScopeAsync(TableRegistry.Admin, null, async context =>
            {
                await Assert.ThrowsAsync<ArgumentException>(
                    () => operations.StartAsync(context, OperationsContract.TenantCreationOperation, tenantId, steps, Cancellation));
                return 0;
            });
        }

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM operation"));
    }

    [Fact]
    public async Task Completion_that_throws_rolls_its_finish_back_and_runs_once_on_the_next_attempt()
    {
        var completion = new FlakyCompletion { FailFirst = 1 };
        var database = await CreateAsync(postgres, registry: null);
        var operation = await StartFlakyAsync(database, completion);

        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, operations: completion.Registry))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        // The handler threw: the step's success, the finish and what the handler wrote all rolled back.
        Assert.Equal(1, completion.Calls);
        Assert.Equal("running", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.NotEqual("succeeded/succeeded", await StepAsync(database, operation));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM tenant_settings"));

        await DrainDueAsync(database, completion.Registry, () => completion.Succeeded > 0);

        Assert.Equal(2, completion.Calls);
        Assert.Equal(1, completion.Succeeded);
        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM tenant_settings"));
    }

    [Fact]
    public async Task Completion_that_always_throws_kills_the_job_and_Retry_succeeds_once_it_stops()
    {
        var completion = new FlakyCompletion { FailFirst = int.MaxValue };
        var database = await CreateAsync(postgres, registry: null);
        var operation = await StartFlakyAsync(database, completion);

        await DrainDueAsync(
            database,
            completion.Registry,
            () => database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'operations.operation.step'").GetAwaiter().GetResult() == "dead");

        Assert.Equal("failed/job_dead", await StepAsync(database, operation));
        Assert.Equal("failed", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
        Assert.Equal(0, completion.Succeeded);

        completion.FailFirst = 0;
        await database.InScopeAsync(TableRegistry.Admin, null, context =>
            OperationsContract.CreateOperations(completion.Registry).RetryAsync(context, operation, Cancellation));
        await DrainDueAsync(database, completion.Registry, () => completion.Succeeded > 0);

        Assert.Equal(1, completion.Succeeded);
        Assert.Equal("succeeded", await database.ScalarAsync<string>($"SELECT status FROM operation WHERE id = '{operation}'"));
    }

    [Fact]
    public async Task Retry_of_an_Operation_that_isnt_failed_is_its_own_refusal()
    {
        var (database, _, operation, _) = await CreatedAsync();

        await database.InScopeAsync(TableRegistry.Admin, null, async context =>
        {
            var refused = await Assert.ThrowsAsync<OperationNotFailedException>(() =>
                OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry).RetryAsync(context, operation, Cancellation));
            Assert.Equal(operation, refused.OperationId);
            return 0;
        });
    }

    private static async Task<Guid> StartFlakyAsync(JobDatabase database, FlakyCompletion completion) =>
        await database.InScopeAsync(TableRegistry.Admin, null, async context =>
            (await OperationsContract.CreateOperations(completion.Registry)
                .StartAsync(context, FlakyCompletion.Type, TenantA, [new(FlakyCompletion.Stage, TenantA)], Cancellation)).Id);

    /// <summary>Runs due jobs, making retried ones due at once, until <paramref name="done"/> or a bound.</summary>
    private static async Task DrainDueAsync(JobDatabase database, OperationRegistry registry, Func<bool> done)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry, operations: registry);
        for (var i = 0; i < 40 && !done(); i++)
        {
            if (!await runner.RunOnceAsync(Cancellation))
            {
                await database.SuperuserAsync("UPDATE job SET run_after = now() WHERE status = 'pending'");
            }
        }

        Assert.True(done(), "The jobs didn't reach the expected state.");
    }

    /// <summary>
    /// A test Operation type whose one Tenant stage succeeds and whose completion handler writes the
    /// Tenant's settings row, then throws on its first <see cref="FailFirst"/> calls.
    /// </summary>
    private sealed class FlakyCompletion
    {
        public static readonly OperationType Type = new("tests.operation.complete");

        public static readonly OperationCode Stage = new("tenant.complete");

        private int _calls;
        private int _succeeded;

        public FlakyCompletion() => Registry = new OperationRegistry(
        [
            new OperationDefinition(
                Type,
                [new OperationStage(Stage, OperationStageKind.Tenant, (_, _) => Task.FromResult(OperationStepResult.Success()))],
                CompleteAsync),
        ]);

        public OperationRegistry Registry { get; }

        public int FailFirst { get; set; }

        public int Calls => Volatile.Read(ref _calls);

        public int Succeeded => Volatile.Read(ref _succeeded);

        private async Task CompleteAsync(OperationCompletion completion, CancellationToken cancellationToken)
        {
            await using (var command = completion.Context.CreateCommand())
            {
                command.CommandText = $"INSERT INTO tenant_settings (tenant_id) VALUES ('{completion.TenantId}') ON CONFLICT DO NOTHING";
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            if (Interlocked.Increment(ref _calls) <= FailFirst)
            {
                throw new InvalidOperationException("Test completion failure.");
            }

            Interlocked.Increment(ref _succeeded);
        }
    }

    private ITenantManagement Management() =>
        ManagementContract.CreateTenants(AuditContract.CreateAppender(), new TenantAddressing("gatekeep.test"));

    /// <summary>A fresh database with a Deployment Owner who has just created Acme Dev: its Tenant, its Operation and the Owner.</summary>
    private async Task<(JobDatabase Database, Guid Tenant, Guid Operation, Guid Admin)> CreatedAsync()
    {
        var database = await CreateAsync(postgres, registry: null);
        var admin = Guid.CreateVersion7();
        await database.SuperuserAsync($"INSERT INTO admin (id, deployment_owner) VALUES ('{admin}', true)");

        var result = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Management().CreateAsync(context, new AdminPrincipal(admin, true), new CreateTenantInput("Acme Dev", "acme-dev", "dev"), Cancellation));

        Assert.Equal(TenantCreationStatus.Created, result.Status);
        return (database, result.Tenant!.Id, result.Operation!.Id, admin);
    }

    private static async Task DrainAsync(JobDatabase database, IKeyCustody? custody)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry, custody);
        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }

    private static Task<string> StatusAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{tenant}'");

    /// <summary>The Tenant's one system Application (Story 2.8): fails unless there is exactly one.</summary>
    private static async Task<Guid> SystemApplicationAsync(JobDatabase database, Guid tenant)
    {
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{tenant}' AND kind = 'system'"));
        return await database.ScalarAsync<Guid>($"SELECT id FROM application WHERE tenant_id = '{tenant}' AND kind = 'system'");
    }

    /// <summary>The production creation completion handler, called directly in the Tenant's own scope as <c>gk_worker</c>.</summary>
    private static async Task RunCompletionAsync(JobDatabase database, Guid operation, Guid tenant)
    {
        var handler = OperationsContract.ProductionOperationRegistry.Find(OperationsContract.TenantCreationOperation)!.OnSucceeded!;
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
    }

    /// <summary>Each step's status and result code, in plan order, comma-separated.</summary>
    private static Task<string> StepAsync(JobDatabase database, Guid operation) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(status || '/' || coalesce(result_code, ''), ',' ORDER BY position) FROM operation_step WHERE operation_id = '{operation}'");

    /// <summary>The same outcome for both creation steps: the secret class keys and the Signing Keys.</summary>
    private static string Both(string step) => $"{step},{step}";

    /// <summary>A new Tenant's key rows (AD-11): one current and one next per purpose.</summary>
    private const string KeyRows = "management/current,management/next,signing/current,signing/next";

    private static Task<string> KeyRowsAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}'");
}

/// <summary>
/// A stand-in for Transit key creation: creating a name that exists returns it unchanged, as
/// OpenBao does, and a signing key comes back with its one version. It wraps a fresh data key as
/// a Transit-shaped ciphertext. It can fail every call, or hang on a key name until cancelled, as
/// a body that outlives its lease does.
/// </summary>
internal sealed class RecordingCustody : IKeyCustody
{
    private readonly ConcurrentQueue<string> _created = new();

    private bool _hung;

    public ConcurrentDictionary<string, int> Versions { get; } = new();

    public IReadOnlyList<string> Created => [.. _created];

    public bool Fail { get; init; }

    public Func<string, bool>? HangOn { get; set; }

    /// <summary>Whether a create has hung on <see cref="HangOn"/>.</summary>
    public bool Hung => Volatile.Read(ref _hung);

    public async Task<IReadOnlyList<KeyPublicVersion>> CreateKeyAsync(KeyName key, CancellationToken cancellationToken)
    {
        if (Fail)
        {
            throw new KeyCustodyException(key.Value, KeyOperation.Create, KeyCustodyFailure.Unavailable);
        }

        _created.Enqueue(key.Value);
        Versions.TryAdd(key.Value, 1);

        if (HangOn is { } hang && hang(key.Value))
        {
            Volatile.Write(ref _hung, true);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        return key.Kind == KeyKind.Signing ? [new KeyPublicVersion(1, string.Empty)] : [];
    }

    public Task<KeySignature> SignAsync(KeyName key, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<bool> VerifyAsync(KeyName key, ReadOnlyMemory<byte> data, KeySignature signature, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<KeyCiphertext> EncryptAsync(KeyName key, Guid? tenantId, Secret<byte[]> plaintext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<Secret<byte[]>> DecryptAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<KeyHmac> HmacAsync(KeyName key, Secret<byte[]> input, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> CreateWrappedDataKeyAsync(KeyName key, Guid tenantId, CancellationToken cancellationToken) =>
        Fail
            ? throw new KeyCustodyException(key.Value, KeyOperation.WrapDataKey, KeyCustodyFailure.Unavailable)
            : Task.FromResult(new KeyCiphertext("vault:v1:" + Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(60))));

    public Task RotateAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> RewrapAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    /// <summary>Every destroy, in order: a key that doesn't exist counts as destroyed, as the adapter does (Story 1.29).</summary>
    public IReadOnlyList<string> Deleted => [.. _deleted];

    private readonly ConcurrentQueue<string> _deleted = new();

    public Task DeleteAsync(KeyName key, CancellationToken cancellationToken)
    {
        if (Fail)
        {
            throw new KeyCustodyException(key.Value, KeyOperation.Delete, KeyCustodyFailure.Unavailable);
        }

        _deleted.Enqueue(key.Value);
        Versions.TryRemove(key.Value, out _);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<KeyPublicVersion>> GetPublicKeysAsync(KeyName key, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    /// <summary>The row keys created and not yet destroyed, as the adapter lists them (Story 2.4).</summary>
    public Task<IReadOnlyList<ListedKey>> ListRowKeysAsync(CancellationToken cancellationToken)
    {
        if (Fail)
        {
            throw new KeyCustodyException("list", KeyOperation.List, KeyCustodyFailure.Unavailable);
        }

        IReadOnlyList<ListedKey> listed = [.. Versions.Keys
            .Select(name => KeyName.TryParseRowKey(name, out var key) ? key : null)
            .OfType<KeyName>()
            .Select(key => new ListedKey(key, DateTimeOffset.UnixEpoch))];
        return Task.FromResult(listed);
    }
}
