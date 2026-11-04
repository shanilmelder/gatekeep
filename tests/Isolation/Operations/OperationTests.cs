using System.Collections.Concurrent;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Operations;

/// <summary>AD-30 Operations: start, run through the job path, partial failure, retry and reads.</summary>
public sealed class OperationTests(PostgresFixture postgres)
{
    private const string CheckViolation = "23514";
    private const string PermissionDenied = "42501";

    private const string Canary = "canary-operation-failure-5d2e";

    private static readonly OperationType Sync = new("tests.operation.sync");
    private static readonly OperationCode TenantStage = new("tenant.sync");
    private static readonly OperationCode DeploymentStage = new("deployment.sync");
    private static readonly OperationCode Unreachable = new("tenant.unreachable");

    private static readonly IReadOnlyList<OperationStepPlan> ThreeSteps =
    [
        new(TenantStage, TenantA),
        new(TenantStage, TenantB),
        new(DeploymentStage),
    ];

    private readonly ConcurrentQueue<StageCall> _calls = new();

    /// <summary>Tenants whose step fails, and how. <see cref="Guid.Empty"/> is the Deployment step.</summary>
    private readonly ConcurrentDictionary<Guid, Failure> _failing = new();

    /// <summary>When set, Tenant step handlers wait here until both have arrived, so they finish together.</summary>
    private TaskCompletionSource? _bothArrived;

    private int _arrived;

    /// <summary>How long the Deployment step's handler takes, so two run jobs can overlap it.</summary>
    private TimeSpan _deploymentDelay = TimeSpan.Zero;

    private enum Failure
    {
        Returns,
        Throws,
        ReturnsNull,
    }

    private OperationRegistry Registry => new(
    [
        new OperationDefinition(
            Sync,
            [
                new OperationStage(TenantStage, OperationStageKind.Tenant, HandleAsync),
                new OperationStage(DeploymentStage, OperationStageKind.Deployment, HandleAsync),
            ]),
    ]);

    [Fact]
    public async Task Start_writes_a_running_Operation_with_pending_steps_and_one_run_job()
    {
        var database = await CreateAsync(postgres, registry: null);

        var operation = await StartAsync(database, null, ThreeSteps);

        Assert.Equal(OperationStatus.Running, operation.Status);
        Assert.Equal(Sync, operation.Type);
        Assert.Null(operation.TenantId);
        Assert.Null(operation.FinishedAt);
        Assert.Equal(3, operation.Steps.Count);
        Assert.All(operation.Steps, s => Assert.Equal(OperationStepStatus.Pending, s.Status));
        Assert.All(operation.Steps, s => Assert.Null(s.ResultCode));
        Assert.Equal(new Guid?[] { TenantA, TenantB, null }, operation.Steps.Select(s => s.TenantId));
        Assert.Equal(
            1L,
            await database.ScalarAsync<long>(
                $"SELECT count(*) FROM job WHERE type = 'operations.operation.run' AND deployment_wide AND operation_id = '{operation.Id}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Second_start_is_refused_while_one_is_active_and_nothing_is_written(bool failedFirst)
    {
        var database = await CreateAsync(postgres, registry: null);
        var first = await StartAsync(database, null, ThreeSteps);

        if (failedFirst)
        {
            _failing[TenantB] = Failure.Returns;
            await DrainAsync(database);
            Assert.Equal(OperationStatus.Failed, (await GetAsync(database, first.Id))!.Status);
        }

        var jobs = await database.ScalarAsync<long>("SELECT count(*) FROM job");

        var refused = await database.InScopeAsync(TableRegistry.Admin, null, async context =>
        {
            var error = await Assert.ThrowsAsync<OperationAlreadyActiveException>(
                () => Operations().StartAsync(context, Sync, null, ThreeSteps, Cancellation));

            // The caller's transaction is still usable after the refusal.
            await using var command = context.CreateCommand();
            command.CommandText = "SELECT count(*) FROM operation";
            Assert.Equal(1L, (long)(await command.ExecuteScalarAsync(Cancellation))!);
            return error;
        });

        Assert.Equal(Sync, refused.Type);
        Assert.Null(refused.TenantId);
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM operation"));
        Assert.Equal(3L, await database.ScalarAsync<long>("SELECT count(*) FROM operation_step"));
        Assert.Equal(jobs, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Same_type_starts_once_per_scope()
    {
        var database = await CreateAsync(postgres, registry: null);

        await StartAsync(database, TenantA, [new(TenantStage, TenantA)]);
        await StartAsync(database, TenantB, [new(TenantStage, TenantB)]);
        await StartAsync(database, null, ThreeSteps);

        await Assert.ThrowsAsync<OperationAlreadyActiveException>(() => StartAsync(database, TenantA, [new(TenantStage, TenantA)]));
        Assert.Equal(3L, await database.ScalarAsync<long>("SELECT count(*) FROM operation"));
    }

    [Fact]
    public async Task All_steps_succeed_and_a_new_start_is_allowed()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);

        await DrainAsync(database);

        var operation = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Succeeded, operation.Status);
        Assert.NotNull(operation.FinishedAt);
        Assert.All(operation.Steps, s => Assert.Equal(OperationStepStatus.Succeeded, s.Status));
        Assert.All(operation.Steps, s => Assert.Equal(OperationResultCodes.Succeeded, s.ResultCode));
        Assert.All(operation.Steps, s => Assert.Equal(1, s.Attempts));
        Assert.Equal(3, _calls.Count);

        var next = await StartAsync(database, null, ThreeSteps);
        Assert.Equal(OperationStatus.Running, next.Status);
    }

    [Fact]
    public async Task Each_Tenant_step_runs_in_its_own_Tenant_through_the_step_job_and_the_Deployment_step_in_none()
    {
        var database = await CreateAsync(postgres, registry: null);
        await StartAsync(database, null, ThreeSteps);

        await DrainAsync(database);

        var tenantCalls = _calls.Where(c => c.Stage == TenantStage).OrderBy(c => c.TenantId).ToList();
        Assert.Equal(new Guid?[] { TenantA, TenantB }, tenantCalls.Select(c => c.TenantId));
        Assert.All(tenantCalls, c => Assert.Equal(c.TenantId, c.ContextTenantId));
        Assert.All(tenantCalls, c => Assert.Equal($"{TableRegistry.Worker}|{c.TenantId}", c.Session));

        var deployment = Assert.Single(_calls, c => c.Stage == DeploymentStage);
        Assert.Null(deployment.TenantId);
        Assert.Null(deployment.ContextTenantId);
        Assert.Equal($"{TableRegistry.Worker}|", deployment.Session);

        Assert.Equal(
            $"{TenantA}|{TenantB}",
            await database.ScalarAsync<string>(
                "SELECT string_agg(tenant_id::text, '|' ORDER BY tenant_id) FROM job WHERE type = 'operations.operation.step' AND status = 'done'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE status <> 'done'"));
    }

    [Fact]
    public async Task Two_Tenant_steps_finishing_together_still_finish_the_Operation()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, [new(TenantStage, TenantA), new(TenantStage, TenantB)]);
        await using var first = database.Runner(OperationsContract.ProductionRegistry, operations: Registry);
        await using var second = database.Runner(OperationsContract.ProductionRegistry, operations: Registry);

        // The run job fans out both steps; then each runner claims one and they finish at once.
        Assert.True(await first.RunOnceAsync(Cancellation));
        _bothArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ran = await Task.WhenAll(first.RunOnceAsync(Cancellation), second.RunOnceAsync(Cancellation));

        Assert.Equal([true, true], ran);
        Assert.Equal(2, _calls.Count);
        Assert.Equal(OperationStatus.Succeeded, (await GetAsync(database, started.Id))!.Status);
    }

    [Fact]
    public async Task Two_run_jobs_at_once_run_the_Deployment_step_once()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, [new(DeploymentStage)]);
        var enqueuer = OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null);
        await database.InScopeAsync(TableRegistry.Worker, null, context =>
            enqueuer.EnqueueAsync(context, OperationsContract.RunOperation, started.Id, runAfter: null, Cancellation));
        await using var first = database.Runner(OperationsContract.ProductionRegistry, operations: Registry);
        await using var second = database.Runner(OperationsContract.ProductionRegistry, operations: Registry);
        _deploymentDelay = TimeSpan.FromSeconds(1);

        var ran = await Task.WhenAll(first.RunOnceAsync(Cancellation), second.RunOnceAsync(Cancellation));

        Assert.Equal([true, true], ran);
        Assert.Single(_calls, c => c.Stage == DeploymentStage);
        var operation = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Succeeded, operation.Status);
        Assert.Equal(1, Assert.Single(operation.Steps).Attempts);
    }

    [Fact]
    public async Task Step_job_refuses_a_step_it_mustnt_run_and_leaves_it_unchanged()
    {
        var database = await CreateAsync(postgres, registry: null);

        // An Operation that succeeded, its step then put back to pending.
        var done = await StartAsync(database, TenantA, [new(TenantStage, TenantA)]);
        await DrainAsync(database);
        var doneStep = Assert.Single(done.Steps).Id;
        await database.SuperuserAsync($"UPDATE operation_step SET status = 'pending' WHERE id = '{doneStep}'");

        // A running Operation, with A's step already succeeded and its run job removed.
        var running = await StartAsync(database, null, [new(TenantStage, TenantA), new(TenantStage, TenantB)]);
        var stepA = running.Steps.Single(s => s.TenantId == TenantA).Id;
        var stepB = running.Steps.Single(s => s.TenantId == TenantB).Id;
        await database.SuperuserAsync($"UPDATE operation_step SET status = 'succeeded', result_code = 'succeeded' WHERE id = '{stepA}'");
        await database.SuperuserAsync("DELETE FROM job WHERE status = 'pending'");
        _calls.Clear();

        var before = await StepRowsAsync(database);
        var enqueuer = OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null);
        var jobs = new List<Guid>();

        // B's step from A's scope, a step that already succeeded, and a step of a succeeded Operation.
        foreach (var (operation, step) in new[] { (running.Id, stepB), (running.Id, stepA), (done.Id, doneStep) })
        {
            var payload = new JobPayload(new Dictionary<string, Guid> { ["operation_id"] = operation, ["step_id"] = step });
            jobs.Add(await database.InScopeAsync(TableRegistry.Worker, TenantA, context =>
                enqueuer.EnqueueAsync(context, OperationsContract.RunOperationStep, payload, runAfter: null, Cancellation)));
        }

        await DrainAsync(database);

        Assert.Empty(_calls);
        Assert.Equal(before, await StepRowsAsync(database));
        foreach (var job in jobs)
        {
            Assert.Equal("done", await database.StatusAsync(job));
        }
    }

    [Fact]
    public async Task Step_for_a_Tenant_other_than_its_Operations_is_refused()
    {
        var database = await CreateAsync(postgres, registry: null);
        var operation = Guid.CreateVersion7();
        await database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation (id, type, tenant_id) VALUES ('{operation}', '{Sync}', '{TenantA}')");

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation_step (id, operation_id, position, tenant_id, stage) VALUES (gen_random_uuid(), '{operation}', 0, '{TenantB}', 'tenant.sync')"));
        Assert.Equal("P0001", error.SqlState);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM operation_step"));

        await database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation_step (id, operation_id, position, tenant_id, stage) VALUES (gen_random_uuid(), '{operation}', 0, '{TenantA}', 'tenant.sync'), (gen_random_uuid(), '{operation}', 1, NULL, 'deployment.sync')");
        Assert.Equal(2L, await database.ScalarAsync<long>("SELECT count(*) FROM operation_step"));
    }

    [Fact]
    public async Task Whole_read_in_a_Tenant_context_is_refused()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);

        await Assert.ThrowsAsync<InvalidOperationException>(() => database.InScopeAsync(TableRegistry.Admin, TenantA, context =>
            Operations().GetAsync(context, started.Id, Cancellation)));
    }

    [Fact]
    public async Task Start_for_an_unknown_Tenant_is_refused_and_the_transaction_stays_usable()
    {
        var database = await CreateAsync(postgres, registry: null);
        var unknown = Guid.CreateVersion7();

        var count = await database.InScopeAsync(TableRegistry.Admin, null, async context =>
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                Operations().StartAsync(context, Sync, unknown, [new(TenantStage, unknown)], Cancellation));

            await using var command = context.CreateCommand();
            command.CommandText = "SELECT count(*) FROM operation";
            return (long)(await command.ExecuteScalarAsync(Cancellation))!;
        });

        Assert.Equal(0L, count);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM operation_step"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Tenant_scoped_Operation_runs_to_completion()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, TenantA, [new(TenantStage, TenantA), new(DeploymentStage)]);

        await DrainAsync(database);

        var operation = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Succeeded, operation.Status);
        Assert.Equal(TenantA, operation.TenantId);
        Assert.All(operation.Steps, s => Assert.Equal(OperationStepStatus.Succeeded, s.Status));
        Assert.Equal(2, _calls.Count);
    }

    [Fact]
    public async Task Failed_Deployment_step_is_retried_alone()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);
        _failing[Guid.Empty] = Failure.Returns;
        await DrainAsync(database);

        var failed = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Failed, failed.Status);
        Assert.Equal(Unreachable, Assert.Single(failed.Steps, s => s.TenantId is null).ResultCode);

        _failing.Clear();
        await database.InScopeAsync(TableRegistry.Admin, null, context => Operations().RetryAsync(context, started.Id, Cancellation));
        await DrainAsync(database);

        Assert.Equal(2, _calls.Count(c => c.Stage == DeploymentStage));
        Assert.Equal(2, _calls.Count(c => c.Stage == TenantStage));
        Assert.Equal(OperationStatus.Succeeded, (await GetAsync(database, started.Id))!.Status);
    }

    [Fact]
    public async Task Handler_returning_no_result_fails_and_its_writes_are_undone()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);
        _failing[TenantB] = Failure.ReturnsNull;

        await DrainAsync(database);

        var b = Assert.Single((await GetAsync(database, started.Id))!.Steps, s => s.TenantId == TenantB);
        Assert.Equal(OperationStepStatus.Failed, b.Status);
        Assert.Equal(OperationResultCodes.HandlerFailed, b.ResultCode);
        Assert.Equal(1, b.Attempts);
    }

    [Theory]
    [InlineData("Not A Code")]
    [InlineData("tests.operation")]
    [InlineData("person@example.test")]
    public async Task Operation_type_holding_anything_but_a_type_code_is_refused(string type)
    {
        var database = await CreateAsync(postgres, registry: null);

        var error = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation (id, type) VALUES (gen_random_uuid(), '{type}')"));

        Assert.Equal(CheckViolation, error.SqlState);
        Assert.Equal("operation_type_code", error.ConstraintName);
    }

    private static Task<string> StepRowsAsync(JobDatabase database) =>
        database.ScalarAsync<string>("SELECT string_agg(to_jsonb(s)::text, '' ORDER BY id) FROM operation_step s");

    [Fact]
    public async Task A_rerun_of_the_run_job_runs_no_step_twice()
    {
        var database = await CreateAsync(postgres, registry: null);
        var operation = await StartAsync(database, null, ThreeSteps);
        var enqueuer = OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null);
        await database.InScopeAsync(TableRegistry.Worker, null, context =>
            enqueuer.EnqueueAsync(context, OperationsContract.RunOperation, operation.Id, runAfter: null, Cancellation));

        await DrainAsync(database);

        Assert.Equal(3, _calls.Count);
        Assert.Equal(2L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'operations.operation.step'"));
        Assert.Equal(OperationStatus.Succeeded, (await GetAsync(database, operation.Id))!.Status);
    }

    [Fact]
    public async Task Partial_failure_is_visible_and_the_Operation_fails()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);
        _failing[TenantB] = Failure.Returns;

        await DrainAsync(database);

        var operation = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Failed, operation.Status);
        Assert.NotNull(operation.FinishedAt);

        var b = Assert.Single(operation.Steps, s => s.TenantId == TenantB);
        Assert.Equal(OperationStepStatus.Failed, b.Status);
        Assert.Equal(Unreachable, b.ResultCode);
        Assert.All(
            operation.Steps.Where(s => s.TenantId != TenantB),
            s => Assert.Equal(OperationStepStatus.Succeeded, s.Status));
    }

    [Fact]
    public async Task Retry_runs_only_the_failed_step()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);
        _failing[TenantB] = Failure.Returns;
        await DrainAsync(database);

        _failing.Clear();
        var retried = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().RetryAsync(context, started.Id, Cancellation));

        Assert.Equal(OperationStatus.Running, retried.Status);
        Assert.Null(retried.FinishedAt);
        Assert.Equal(OperationStepStatus.Pending, Assert.Single(retried.Steps, s => s.TenantId == TenantB).Status);
        Assert.Null(Assert.Single(retried.Steps, s => s.TenantId == TenantB).ResultCode);
        Assert.Equal(2, retried.Steps.Count(s => s.Status == OperationStepStatus.Succeeded));

        await DrainAsync(database);

        Assert.Equal(1, _calls.Count(c => c.TenantId == TenantA));
        Assert.Equal(1, _calls.Count(c => c.Stage == DeploymentStage));
        Assert.Equal(2, _calls.Count(c => c.TenantId == TenantB));

        var operation = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Succeeded, operation.Status);
        Assert.All(operation.Steps, s => Assert.Equal(OperationStepStatus.Succeeded, s.Status));
        Assert.Equal(2, Assert.Single(operation.Steps, s => s.TenantId == TenantB).Attempts);
        Assert.Equal(1, Assert.Single(operation.Steps, s => s.TenantId == TenantA).Attempts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Retry_of_an_Operation_that_hasnt_failed_is_refused(bool succeeded)
    {
        var database = await CreateAsync(postgres, registry: null);
        var operation = await StartAsync(database, null, ThreeSteps);

        if (succeeded)
        {
            await DrainAsync(database);
            Assert.Equal(OperationStatus.Succeeded, (await GetAsync(database, operation.Id))!.Status);
        }

        var jobs = await database.ScalarAsync<long>("SELECT count(*) FROM job");

        await Assert.ThrowsAsync<OperationNotFailedException>(() => database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().RetryAsync(context, operation.Id, Cancellation)));
        await Assert.ThrowsAsync<OperationNotFailedException>(() => database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().RetryAsync(context, Guid.CreateVersion7(), Cancellation)));

        Assert.Equal(jobs, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Throwing_handler_stores_only_a_fixed_code_and_its_writes_are_undone()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);
        _failing[TenantB] = Failure.Throws;

        await DrainAsync(database);

        var operation = (await GetAsync(database, started.Id))!;
        var b = Assert.Single(operation.Steps, s => s.TenantId == TenantB);
        Assert.Equal(OperationStepStatus.Failed, b.Status);
        Assert.Equal(OperationResultCodes.HandlerFailed, b.ResultCode);
        Assert.Equal(OperationStatus.Failed, operation.Status);

        // The handler bumped its own step's attempts before throwing; the savepoint undid it.
        Assert.Equal(1, b.Attempts);

        var stored = await database.ScalarAsync<string>(
            """
            SELECT (SELECT coalesce(string_agg(to_jsonb(o)::text, ''), '') FROM operation o)
                || (SELECT coalesce(string_agg(to_jsonb(s)::text, ''), '') FROM operation_step s)
                || (SELECT coalesce(string_agg(to_jsonb(j)::text, ''), '') FROM job j)
            """);
        Assert.DoesNotContain(Canary, stored);
    }

    [Fact]
    public async Task Step_of_a_stage_the_running_registry_doesnt_list_fails_with_a_fixed_code()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);

        await DrainAsync(database, OperationsContract.ProductionOperationRegistry);

        var operation = (await GetAsync(database, started.Id))!;
        Assert.Equal(OperationStatus.Failed, operation.Status);
        Assert.All(operation.Steps, s => Assert.Equal(OperationResultCodes.UnknownStage, s.ResultCode));
        Assert.Empty(_calls);
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("person@example.test")]
    [InlineData("Upper.case")]
    [InlineData("trailing.")]
    public async Task Stage_or_result_code_holding_free_text_is_refused(string code)
    {
        await AssertCodeRefusedAsync(code);
    }

    [Fact]
    public async Task Code_over_64_characters_is_refused()
    {
        await AssertCodeRefusedAsync(new string('a', 65));
    }

    [Fact]
    public async Task Code_of_64_characters_is_accepted()
    {
        var code = new string('a', 64);
        var database = await CreateAsync(postgres, registry: null);
        var operation = await InsertOperationAsync(database);

        await database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation_step (id, operation_id, position, stage, result_code) VALUES (gen_random_uuid(), '{operation}', 0, '{code}', '{code}')");

        Assert.Equal(code, new OperationCode(code).Value);
    }

    [Fact]
    public async Task Tenant_read_returns_only_that_Tenants_steps()
    {
        var database = await CreateAsync(postgres, registry: null);
        var started = await StartAsync(database, null, ThreeSteps);

        var forA = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().GetForTenantAsync(context, started.Id, TenantA, Cancellation));
        var inTenantScope = await database.InScopeAsync(TableRegistry.Admin, TenantA, context =>
            Operations().GetForTenantAsync(context, started.Id, TenantA, Cancellation));

        Assert.NotNull(forA);
        Assert.Equal(TenantA, Assert.Single(forA.Steps).TenantId);
        Assert.NotNull(inTenantScope);
        Assert.Equal(TenantA, Assert.Single(inTenantScope.Steps).TenantId);
        Assert.Equal(3, (await GetAsync(database, started.Id))!.Steps.Count);
    }

    [Fact]
    public async Task Tenant_read_of_another_Tenants_Operation_finds_nothing()
    {
        var database = await CreateAsync(postgres, registry: null);
        var scopedToA = await StartAsync(database, TenantA, [new(TenantStage, TenantA), new(DeploymentStage)]);
        var deploymentWithoutB = await StartAsync(database, null, [new(TenantStage, TenantA)]);

        Assert.Null(await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().GetForTenantAsync(context, scopedToA.Id, TenantB, Cancellation)));
        Assert.Null(await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().GetForTenantAsync(context, deploymentWithoutB.Id, TenantB, Cancellation)));
        Assert.Null(await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().GetForTenantAsync(context, Guid.CreateVersion7(), TenantA, Cancellation)));
        await Assert.ThrowsAsync<ArgumentException>(() => database.InScopeAsync(TableRegistry.Admin, TenantB, context =>
            Operations().GetForTenantAsync(context, scopedToA.Id, TenantA, Cancellation)));

        var forA = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().GetForTenantAsync(context, scopedToA.Id, TenantA, Cancellation));
        Assert.NotNull(forA);
        Assert.Equal(TenantA, Assert.Single(forA.Steps).TenantId);
    }

    [Theory]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Cli)]
    [InlineData(TableRegistry.Worker)]
    public async Task Listed_roles_start_and_retry(string role)
    {
        var database = await CreateAsync(postgres, registry: null);
        var operation = await database.InScopeAsync(role, null, context =>
            Operations().StartAsync(context, Sync, null, ThreeSteps, Cancellation));
        _failing[TenantA] = Failure.Returns;
        await DrainAsync(database);
        _failing.Clear();

        var retried = await database.InScopeAsync(role, null, context => Operations().RetryAsync(context, operation.Id, Cancellation));

        Assert.Equal(OperationStatus.Running, retried.Status);
    }

    [Theory]
    [InlineData(TableRegistry.Hosted)]
    [InlineData(TableRegistry.Sealer)]
    [InlineData(TableRegistry.Retention)]
    [InlineData(TableRegistry.Dispatch)]
    public async Task Other_roles_cant_start_or_read(string role)
    {
        var database = await CreateAsync(postgres, registry: null);
        var operation = await InsertOperationAsync(database);

        var start = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(role, null, context =>
            Operations().StartAsync(context, Sync, null, ThreeSteps, Cancellation)));
        var insert = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            role,
            null,
            $"INSERT INTO operation (id, type) VALUES (gen_random_uuid(), '{Sync}')"));
        var read = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(role, null, "SELECT 1 FROM operation_step"));
        var update = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            role,
            null,
            $"UPDATE operation SET status = 'failed' WHERE id = '{operation}'"));

        Assert.All(new[] { start, insert, read, update }, e => Assert.Equal(PermissionDenied, e.SqlState));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM operation"));
    }

    [Fact]
    public async Task Start_refuses_a_plan_that_doesnt_fit_the_registry()
    {
        var database = await CreateAsync(postgres, registry: null);

        IReadOnlyList<OperationStepPlan>[] plans =
        [
            [],
            [new(new OperationCode("tenant.other"), TenantA)],
            [new(TenantStage)],
            [new(DeploymentStage, TenantA)],
            [new(TenantStage, TenantA), new(TenantStage, TenantA)],
        ];

        foreach (var plan in plans)
        {
            await Assert.ThrowsAsync<ArgumentException>(() => StartAsync(database, null, plan));
        }

        await Assert.ThrowsAsync<ArgumentException>(() => StartAsync(database, TenantA, [new(TenantStage, TenantB)]));
        await Assert.ThrowsAsync<ArgumentException>(() => database.InScopeAsync(TableRegistry.Admin, null, context =>
            Operations().StartAsync(context, new OperationType("tests.operation.unknown"), null, ThreeSteps, Cancellation)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => database.InScopeAsync(TableRegistry.Admin, TenantA, context =>
            Operations().StartAsync(context, Sync, TenantA, [new(TenantStage, TenantA)], Cancellation)));

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM operation"));
    }

    private async Task AssertCodeRefusedAsync(string code)
    {
        Assert.Throws<ArgumentException>(() => new OperationCode(code));

        var database = await CreateAsync(postgres, registry: null);
        var operation = await InsertOperationAsync(database);

        var stage = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation_step (id, operation_id, position, stage) VALUES (gen_random_uuid(), '{operation}', 0, '{code}')"));
        var result = await Assert.ThrowsAsync<PostgresException>(() => database.InScopeAsync(
            TableRegistry.Worker,
            null,
            $"INSERT INTO operation_step (id, operation_id, position, stage, result_code) VALUES (gen_random_uuid(), '{operation}', 0, 'ok', '{code}')"));

        Assert.Equal(CheckViolation, stage.SqlState);
        Assert.Equal("operation_step_stage_code", stage.ConstraintName);
        Assert.Equal(CheckViolation, result.SqlState);
        Assert.Equal("operation_step_result_code", result.ConstraintName);
    }

    private static async Task<Guid> InsertOperationAsync(JobDatabase database)
    {
        var id = Guid.CreateVersion7();
        await database.InScopeAsync(TableRegistry.Worker, null, $"INSERT INTO operation (id, type) VALUES ('{id}', '{Sync}')");
        return id;
    }

    private IOperations Operations() => OperationsContract.CreateOperations(Registry);

    private Task<OperationResource> StartAsync(JobDatabase database, Guid? tenantId, IReadOnlyList<OperationStepPlan> steps) =>
        database.InScopeAsync(TableRegistry.Admin, null, context => Operations().StartAsync(context, Sync, tenantId, steps, Cancellation));

    private Task<OperationResource?> GetAsync(JobDatabase database, Guid id) =>
        database.InScopeAsync(TableRegistry.Admin, null, context => Operations().GetAsync(context, id, Cancellation));

    /// <summary>Runs every due job, the run job's fan-out included, until none is left.</summary>
    private async Task DrainAsync(JobDatabase database, OperationRegistry? operations = null)
    {
        await using var runner = database.Runner(OperationsContract.ProductionRegistry, operations: operations ?? Registry);

        while (await runner.RunOnceAsync(Cancellation))
        {
        }
    }

    private async Task<OperationStepResult> HandleAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        string session;
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = "SELECT current_user::text || '|' || coalesce(current_setting('gatekeep.tenant_id', true), '')";
            session = (string)(await command.ExecuteScalarAsync(cancellationToken))!;
        }

        _calls.Enqueue(new StageCall(run.Stage, run.TenantId, run.Context.TenantId, session));

        if (_bothArrived is { } barrier)
        {
            if (Interlocked.Increment(ref _arrived) == 2)
            {
                barrier.SetResult();
            }

            await barrier.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
        }

        if (run.TenantId is null && _deploymentDelay > TimeSpan.Zero)
        {
            await Task.Delay(_deploymentDelay, cancellationToken);
        }

        if (!_failing.TryGetValue(run.TenantId ?? Guid.Empty, out var failure))
        {
            return OperationStepResult.Success();
        }

        if (failure == Failure.Returns)
        {
            return OperationStepResult.Failure(Unreachable);
        }

        // A write the savepoint must undo, then no result, or an exception carrying text that must not be kept.
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = $"UPDATE operation_step SET attempts = attempts + 10 WHERE id = '{run.StepId}'";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return failure == Failure.ReturnsNull ? null! : throw new InvalidOperationException(Canary);
    }

    private sealed record StageCall(OperationCode Stage, Guid? TenantId, Guid? ContextTenantId, string Session);
}
