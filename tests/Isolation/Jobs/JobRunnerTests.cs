using System.Collections.Concurrent;
using System.Text;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Contracts;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Jobs;

/// <summary>The AD-15 runner: claim, run, back off, dead, and the schedule.</summary>
public sealed class JobRunnerTests(PostgresFixture postgres)
{
    private const string Canary = "canary-job-failure-7f3a";

    private static readonly JobType Work = new("tests.job.work");
    private static readonly JobType Credentialed = new("tests.job.credentialed");
    private static readonly JobType Sealed = new("tests.job.sealed");
    private static readonly JobType Alert = new("alerts.test.send");
    private static readonly JobType Scheduled = new("tests.schedule.tick");
    private static readonly JobType Retained = new("tests.job.retained");

    private static readonly Guid UserId = Guid.Parse("01900000-0000-7000-8000-0000000000c1");

    private static readonly byte[] Credential = Encoding.UTF8.GetBytes("reset-link-credential-value");

    private readonly ConcurrentQueue<RunRecord> _runs = new();

    private Func<JobRun, CancellationToken, Task> _body = (_, _) => Task.CompletedTask;

    private JobRegistry Registry => new(
    [
        new JobDefinition(Work, JobScope.Tenant, [JobRole.Worker, JobRole.Admin], JobRole.Worker, 3, HandleAsync),
        new JobDefinition(Credentialed, JobScope.Tenant, [JobRole.Worker], JobRole.Worker, 3, HandleAsync, mayCarryCredential: true),
        new JobDefinition(Sealed, JobScope.Tenant, [JobRole.Worker], JobRole.Sealer, 3, HandleAsync),
        new JobDefinition(Alert, JobScope.Tenant, [JobRole.Sealer, JobRole.Worker], JobRole.Worker, 2, HandleAsync, neverDead: true),
        new JobDefinition(Scheduled, JobScope.DeploymentWide, [JobRole.Worker], JobRole.Worker, 3, HandleAsync),
        new JobDefinition(Retained, JobScope.Tenant, [JobRole.Worker], JobRole.Retention, 3, HandleAsync),
    ]);

    [Fact]
    public async Task Successful_job_is_done_and_its_payload_is_gone()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var job = await EnqueueAsync(database, registry, Work, TenantA, new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }));
        await EnqueueAsync(database, registry, Work, TenantB, new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }), DateTimeOffset.UtcNow.AddHours(1));
        await using var runner = database.Runner(registry);

        Assert.True(await runner.RunOnceAsync(Cancellation));

        var run = Assert.Single(_runs);
        Assert.Equal(job, run.JobId);
        Assert.Equal(UserId, run.Ids["user_id"]);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job_payload WHERE job_id = '{job}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM job_payload WHERE tenant_id = '{TenantB}'"));
        Assert.False(await runner.RunOnceAsync(Cancellation));
    }

    [Theory]
    [InlineData("tests.job.work", TableRegistry.Worker)]
    [InlineData("tests.job.sealed", TableRegistry.Sealer)]
    [InlineData("tests.job.retained", TableRegistry.Retention)]
    public async Task Body_runs_as_the_run_as_role_in_its_own_Tenant_only(string type, string role)
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var ids = new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId });
        await EnqueueAsync(database, registry, new JobType(type), TenantA, ids);
        await EnqueueAsync(database, registry, new JobType(type), TenantB, ids, DateTimeOffset.UtcNow.AddHours(1));
        await using var runner = database.Runner(registry);

        Assert.True(await runner.RunOnceAsync(Cancellation));

        var run = Assert.Single(_runs);
        Assert.Equal(role, run.Role);
        Assert.Equal(TenantA.ToString(), run.ScopeTenant);
        Assert.Equal(TenantA, run.TenantId);
        Assert.Equal(1L, run.VisiblePayloads);
    }

    [Fact]
    public async Task Exhausted_job_goes_dead_with_one_system_event_and_no_ciphertext()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var custody = new FakeKeyCustody();
        var logger = new RecordingLogger();
        _body = (_, _) => throw new InvalidOperationException(Canary);
        var job = await EnqueueAsync(
            database,
            registry,
            Credentialed,
            TenantA,
            new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }, new Secret<byte[]>(Credential)),
            custody: custody);
        await using var runner = database.Runner(registry, custody, logger);

        var delays = new List<double>();
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
            Assert.Equal("pending", await database.StatusAsync(job));
            delays.Add(await database.SecondsUntilDueAsync(job));
            Assert.False(await runner.RunOnceAsync(Cancellation));
            await database.MakeDueAsync(job);
        }

        Assert.True(await runner.RunOnceAsync(Cancellation));

        // 400 ms, then 800 ms, less the few milliseconds before each read.
        Assert.InRange(delays[0], 0.1, 0.4);
        Assert.InRange(delays[1], 0.45, 0.8);
        Assert.Equal("dead", await database.StatusAsync(job));
        Assert.Equal(3, await database.AttemptsAsync(job));
        Assert.Equal(3, _runs.Count);
        Assert.Equal("handler_failed", await database.ScalarAsync<string>($"SELECT failure_code FROM job WHERE id = '{job}'"));
        Assert.True(await database.ScalarAsync<bool>($"SELECT ciphertext IS NULL FROM job_payload WHERE job_id = '{job}'"));
        Assert.Equal(
            "system|",
            await database.ScalarAsync<string>(
                $"SELECT concat_ws('|', actor_kind, coalesce(actor_id::text, '')) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = 'operations.job.dead'"));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code = 'operations.job.dead'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event"));
        Assert.False(await runner.RunOnceAsync(Cancellation));

        // No error text reaches the row or the log.
        Assert.DoesNotContain(Canary, await database.JobRowAsync(job));
        Assert.DoesNotContain(logger.Lines, l => l.Contains(Canary, StringComparison.Ordinal));
        Assert.Empty(logger.Exceptions);
        Assert.NotEmpty(logger.Lines);
    }

    [Fact]
    public async Task Never_dead_type_keeps_retrying_with_a_capped_delay()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        _body = (_, _) => throw new InvalidOperationException(Canary);
        var job = await EnqueueAsync(database, registry, Alert, TenantA, payload: null);
        await using var runner = database.Runner(registry);

        var delays = new List<double>();
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
            delays.Add(await database.SecondsUntilDueAsync(job));
            await database.MakeDueAsync(job);
        }

        Assert.Equal("pending", await database.StatusAsync(job));
        Assert.Equal(5, await database.AttemptsAsync(job));
        Assert.All(delays.Skip(1), d => Assert.InRange(d, 0.45, 0.8));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event"));
    }

    [Fact]
    public async Task Credential_is_decrypted_once_and_none_remains()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var custody = new FakeKeyCustody();
        byte[]? seen = null;
        _body = async (run, token) =>
        {
            var secret = await run.DecryptCredentialAsync(token);
            seen = secret.Use(bytes => bytes.ToArray());
        };
        var job = await EnqueueAsync(
            database,
            registry,
            Credentialed,
            TenantA,
            new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }, new Secret<byte[]>(Credential)),
            custody: custody);

        var stored = await database.ScalarAsync<string>($"SELECT ciphertext FROM job_payload WHERE job_id = '{job}'");
        Assert.DoesNotContain("reset-link-credential-value", stored);
        Assert.StartsWith("vault:v1:", stored);

        await using var runner = database.Runner(registry, custody);
        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Equal(Credential, seen);
        Assert.Equal(1, custody.Encrypts);
        Assert.Equal(1, custody.Decrypts);
        Assert.All(custody.KeysUsed, k => Assert.Equal(KeyName.ForTenant(TenantKeyClass.Payload, TenantA).Value, k));
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job_payload"));
    }

    [Fact]
    public async Task Credential_on_an_IDs_only_type_is_refused_before_any_insert()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var custody = new FakeKeyCustody();
        var enqueuer = OperationsContract.CreateEnqueuer(registry, custody);

        await database.InScopeAsync(TableRegistry.Worker, TenantA, async context =>
        {
            await Assert.ThrowsAsync<ArgumentException>(() => enqueuer.EnqueueAsync(
                context,
                Work,
                new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }, new Secret<byte[]>(Credential)),
                runAfter: null,
                Cancellation));
            return 0;
        });

        Assert.Equal(0, custody.Encrypts);
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job_payload"));
    }

    [Fact]
    public async Task Enqueue_takes_its_scope_from_the_context()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var enqueuer = OperationsContract.CreateEnqueuer(registry, custody: null);

        await database.InScopeAsync(TableRegistry.Worker, null, async context =>
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => enqueuer.EnqueueAsync(context, Work, payload: null, runAfter: null, Cancellation));
            return 0;
        });
        await database.InScopeAsync(TableRegistry.Worker, TenantA, async context =>
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => enqueuer.EnqueueAsync(context, Scheduled, operationId: null, runAfter: null, Cancellation));
            await Assert.ThrowsAsync<ArgumentException>(
                () => enqueuer.EnqueueAsync(context, Scheduled, payload: null, runAfter: null, Cancellation));
            return 0;
        });

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Rolled_back_command_leaves_no_job()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var enqueuer = OperationsContract.CreateEnqueuer(registry, custody: null);

        await using (var source = database.Source(TableRegistry.Worker))
        await using (var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation))
        {
            await enqueuer.EnqueueAsync(scope.CreateCommandContext(), Work, payload: null, runAfter: null, Cancellation);
        }

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Expired_claim_is_claimed_again_and_run()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var job = await EnqueueAsync(database, registry, Work, TenantA, payload: null);
        await using var runner = database.Runner(registry);

        // A runner that claimed it and crashed.
        await database.SuperuserAsync($"UPDATE job SET status = 'running', attempts = 1, locked_until = now() + interval '1 hour' WHERE id = '{job}'");
        Assert.False(await runner.RunOnceAsync(Cancellation));

        await database.SuperuserAsync($"UPDATE job SET locked_until = now() - interval '1 second' WHERE id = '{job}'");
        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Single(_runs);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(2, await database.AttemptsAsync(job));
    }

    [Fact]
    public async Task Two_runners_claim_one_job_once()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        await EnqueueAsync(database, registry, Work, TenantA, payload: null);
        _body = (_, token) => Task.Delay(TimeSpan.FromMilliseconds(500), token);
        await using var first = database.Runner(registry);
        await using var second = database.Runner(registry);

        var results = await Task.WhenAll(first.RunOnceAsync(Cancellation), second.RunOnceAsync(Cancellation));

        Assert.Equal(1, results.Count(r => r));
        Assert.Single(_runs);
    }

    [Fact]
    public async Task Locked_job_is_skipped_rather_than_waited_for()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        await EnqueueAsync(database, registry, Work, TenantA, payload: null);
        await using var runner = database.Runner(registry);

        // Another runner mid-claim holds the row lock.
        await using var holder = new NpgsqlConnection(postgres.SuperuserConnection(database.Name));
        await holder.OpenAsync(Cancellation);
        await using var transaction = await holder.BeginTransactionAsync(Cancellation);
        await using (var lockRow = new NpgsqlCommand("SELECT id FROM job FOR UPDATE", holder, transaction))
        {
            await lockRow.ExecuteNonQueryAsync(Cancellation);
        }

        Assert.False(await runner.RunOnceAsync(Cancellation).WaitAsync(TimeSpan.FromSeconds(10), Cancellation));

        await transaction.RollbackAsync(Cancellation);
        Assert.True(await runner.RunOnceAsync(Cancellation));
    }

    [Fact]
    public async Task Due_schedule_entry_enqueues_one_deployment_job_that_the_runner_runs()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        await using var schedule = OperationsContract.CreateScheduleRunner(
            registry,
            [new ScheduleEntry(Scheduled, TimeSpan.FromDays(1))],
            database.Connection(TableRegistry.Worker),
            logger: null);
        await using var runner = database.Runner(registry);

        Assert.Equal(1, await schedule.TickAsync(Cancellation));
        Assert.Equal(0, await schedule.TickAsync(Cancellation));
        Assert.Equal(
            "1|true",
            await database.ScalarAsync<string>($"SELECT count(*) || '|' || bool_and(deployment_wide) FROM job WHERE type = '{Scheduled}'"));

        Assert.True(await runner.RunOnceAsync(Cancellation));

        var run = Assert.Single(_runs);
        Assert.Null(run.TenantId);
        Assert.Equal(TableRegistry.Worker, run.Role);
        Assert.Equal(0, await schedule.TickAsync(Cancellation));
        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE status = 'done'"));
    }

    [Fact]
    public void Schedule_refuses_a_type_that_isnt_deployment_wide()
    {
        Assert.Throws<ArgumentException>(() => OperationsContract.CreateScheduleRunner(
            Registry,
            [new ScheduleEntry(Work, TimeSpan.FromDays(1))],
            "Host=unused",
            logger: null));
    }

    [Fact]
    public async Task Purge_deletes_only_done_jobs_older_than_30_days()
    {
        var database = await CreateAsync(postgres, registry: null);
        await database.SuperuserAsync(
            """
            ALTER TABLE job DISABLE TRIGGER job_guard_insert;
            INSERT INTO job (id, type, deployment_wide, status, finished_at) VALUES
              (gen_random_uuid(), 'operations.job.purge', true, 'done', now() - interval '31 days'),
              (gen_random_uuid(), 'operations.job.purge', true, 'done', now() - interval '29 days'),
              (gen_random_uuid(), 'operations.job.purge', true, 'dead', now() - interval '31 days');
            ALTER TABLE job ENABLE TRIGGER job_guard_insert;
            """);
        var registry = OperationsContract.ProductionRegistry;
        await database.InScopeAsync(TableRegistry.Worker, null, context => OperationsContract.CreateEnqueuer(registry, null)
            .EnqueueAsync(context, OperationsContract.PurgeJobs, operationId: null, runAfter: null, Cancellation));
        await using var runner = database.Runner(registry);

        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Equal(
            "dead,done,done",
            await database.ScalarAsync<string>("SELECT string_agg(status, ',' ORDER BY status) FROM job"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE finished_at < now() - interval '30 days' AND status = 'done'"));
    }

    [Fact]
    public async Task Runner_refuses_a_connection_for_the_wrong_role()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var databases = database.Databases with { Dispatch = database.Connection(TableRegistry.Worker) };
        await using var runner = OperationsContract.CreateRunner(registry, databases, FastOptions, null, null);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => runner.RunOnceAsync(Cancellation));
    }

    [Fact]
    public async Task Wrong_role_stops_RunAsync_rather_than_retrying()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var databases = database.Databases with { Sealer = database.Connection(TableRegistry.Worker) };
        await using var runner = OperationsContract.CreateRunner(registry, databases, FastOptions, null, null);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => runner.RunAsync(Cancellation).WaitAsync(TimeSpan.FromSeconds(20), Cancellation));
    }

    [Fact]
    public async Task Schedule_refuses_a_connection_for_the_wrong_role()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        await using var schedule = OperationsContract.CreateScheduleRunner(
            registry,
            [new ScheduleEntry(Scheduled, TimeSpan.FromDays(1))],
            database.Connection(TableRegistry.Dispatch),
            logger: null);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => schedule.TickAsync(Cancellation));
        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => schedule.RunAsync(TimeSpan.FromSeconds(1), Cancellation).WaitAsync(TimeSpan.FromSeconds(20), Cancellation));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    [Fact]
    public async Task Body_that_outlasts_its_lease_is_cancelled_and_retried_as_timed_out()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var cancelled = false;
        _body = async (_, token) =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), token);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
                throw;
            }
        };
        var job = await EnqueueAsync(database, registry, Work, TenantA, payload: null);
        await using var runner = database.Runner(registry, options: FastOptions with { Lease = TimeSpan.FromSeconds(1) });

        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.True(cancelled);
        Assert.Equal("pending", await database.StatusAsync(job));
        Assert.Equal(1, await database.AttemptsAsync(job));
        Assert.Equal("timed_out", await FailureCodeAsync(database, job));
    }

    [Fact]
    public async Task Row_of_an_unregistered_type_goes_dead_as_unknown_type()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var job = Guid.CreateVersion7();
        await database.SuperuserAsync(
            $"""
            ALTER TABLE job DISABLE TRIGGER job_guard_insert;
            INSERT INTO job (id, type, tenant_id) VALUES ('{job}', 'tests.job.unregistered', '{TenantA}');
            ALTER TABLE job ENABLE TRIGGER job_guard_insert;
            """);
        await using var runner = database.Runner(registry);

        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Empty(_runs);
        Assert.Equal("dead", await database.StatusAsync(job));
        Assert.Equal("unknown_type", await FailureCodeAsync(database, job));
        Assert.Equal(1L, await DeadEventsAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Reclaim_after_the_last_attempt_goes_dead_as_lease_expired_without_running()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var job = await EnqueueAsync(database, registry, Work, TenantA, payload: null);

        // A runner crashed during the last of Work's three attempts.
        await database.SuperuserAsync(
            $"UPDATE job SET status = 'running', attempts = 3, locked_until = now() - interval '1 second' WHERE id = '{job}'");
        await using var runner = database.Runner(registry);

        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Empty(_runs);
        Assert.Equal("dead", await database.StatusAsync(job));
        Assert.Equal("lease_expired", await FailureCodeAsync(database, job));
        Assert.Equal(1L, await DeadEventsAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Credential_job_with_no_custody_fails_as_custody_failed()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var custody = new FakeKeyCustody();
        _body = (run, token) => run.DecryptCredentialAsync(token);
        var job = await EnqueueAsync(
            database,
            registry,
            Credentialed,
            TenantA,
            new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }, new Secret<byte[]>(Credential)),
            custody: custody);

        // As Host.Worker is wired today.
        await using var runner = database.Runner(registry, custody: null);
        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.Equal(0, custody.Decrypts);
        Assert.Equal("pending", await database.StatusAsync(job));
        Assert.Equal("custody_failed", await FailureCodeAsync(database, job));
    }

    [Fact]
    public async Task Ciphertext_on_an_IDs_only_type_is_never_decrypted()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var custody = new FakeKeyCustody();
        var job = await EnqueueAsync(database, registry, Work, TenantA, new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }));
        await database.SuperuserAsync($"UPDATE job_payload SET ciphertext = 'vault:v1:planted' WHERE job_id = '{job}'");
        await using var runner = database.Runner(registry, custody);

        Assert.True(await runner.RunOnceAsync(Cancellation));

        Assert.False(Assert.Single(_runs).HasCredential);
        Assert.Equal(0, custody.Decrypts);
        Assert.Equal("done", await database.StatusAsync(job));
    }

    [Fact]
    public async Task Exhausted_deployment_wide_job_goes_dead_in_the_deployment_chain()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        _body = (_, _) => throw new InvalidOperationException(Canary);
        var enqueuer = OperationsContract.CreateEnqueuer(registry, custody: null);
        var job = await database.InScopeAsync(
            TableRegistry.Worker,
            null,
            context => enqueuer.EnqueueAsync(context, Scheduled, operationId: null, runAfter: null, Cancellation));
        await using var runner = database.Runner(registry);

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
            await database.MakeDueAsync(job);
        }

        Assert.Equal("dead", await database.StatusAsync(job));
        Assert.Equal(
            "system|",
            await database.ScalarAsync<string>(
                "SELECT concat_ws('|', actor_kind, coalesce(actor_id::text, '')) FROM deployment_audit_event WHERE type_code = 'operations.job.dead'"));
        Assert.Equal(1L, await DeadEventsAsync(database, "deployment_audit_event"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event"));
    }

    [Fact]
    public async Task Stopping_mid_body_returns_the_claim_unspent()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        // Stop only once the body is running, so a slow claim under load can't stop it first.
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _body = (_, token) =>
        {
            started.TrySetResult();
            return Task.Delay(Timeout.InfiniteTimeSpan, token);
        };
        var job = await EnqueueAsync(database, registry, Work, TenantA, payload: null);
        await using var runner = database.Runner(registry);
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);

        var run = runner.RunOnceAsync(stopping.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(30), Cancellation);
        await stopping.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);

        Assert.Single(_runs);
        Assert.Equal(
            "pending|0|",
            await database.ScalarAsync<string>(
                $"SELECT concat_ws('|', status, attempts, coalesce(locked_until::text, '')) FROM job WHERE id = '{job}'"));
    }

    [Fact]
    public async Task RunAsync_is_woken_by_notify_and_returns_when_cancelled()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        await using var runner = database.Runner(registry, options: FastOptions with { PollInterval = TimeSpan.FromMinutes(5) });
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        var running = runner.RunAsync(stopping.Token);

        // Lets the runner drain the empty queue and start waiting before the job arrives.
        await Task.Delay(TimeSpan.FromSeconds(1), Cancellation);
        var job = await EnqueueAsync(database, registry, Work, TenantA, payload: null);

        var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
        while (await database.StatusAsync(job) != "done" && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(100), Cancellation);
        }

        Assert.Equal("done", await database.StatusAsync(job));

        await stopping.CancelAsync();
        await running.WaitAsync(TimeSpan.FromSeconds(10), Cancellation);
        Assert.True(running.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Enqueuer_refuses_what_it_cant_store()
    {
        var registry = Registry;
        var database = await CreateAsync(postgres, registry);
        var credential = new JobPayload(new Dictionary<string, Guid> { ["user_id"] = UserId }, new Secret<byte[]>(Credential));

        await database.InScopeAsync(TableRegistry.Worker, TenantA, async context =>
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => OperationsContract.CreateEnqueuer(registry, custody: null)
                .EnqueueAsync(context, Credentialed, credential, runAfter: null, Cancellation));
            await Assert.ThrowsAsync<ArgumentException>(() => OperationsContract.CreateEnqueuer(registry, new FakeKeyCustody { Padding = 8192 })
                .EnqueueAsync(context, Credentialed, credential, runAfter: null, Cancellation));
            return 0;
        });
        await database.InScopeAsync(TableRegistry.Worker, null, async context =>
        {
            await Assert.ThrowsAsync<ArgumentException>(() => OperationsContract.CreateEnqueuer(registry, custody: null)
                .EnqueueAsync(context, Scheduled, operationId: Guid.Empty, runAfter: null, Cancellation));
            return 0;
        });

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job"));
    }

    private static Task<string> FailureCodeAsync(JobDatabase database, Guid job) =>
        database.ScalarAsync<string>($"SELECT failure_code FROM job WHERE id = '{job}'");

    private static Task<long> DeadEventsAsync(JobDatabase database, string table) =>
        database.ScalarAsync<long>($"SELECT count(*) FROM {table} WHERE type_code = 'operations.job.dead'");

    private async Task<Guid> EnqueueAsync(
        JobDatabase database,
        JobRegistry registry,
        JobType type,
        Guid tenantId,
        JobPayload? payload,
        DateTimeOffset? runAfter = null,
        IKeyCustody? custody = null)
    {
        var enqueuer = OperationsContract.CreateEnqueuer(registry, custody);
        return await database.InScopeAsync(
            TableRegistry.Worker,
            tenantId,
            context => enqueuer.EnqueueAsync(context, type, payload, runAfter, Cancellation));
    }

    private async Task HandleAsync(JobRun run, CancellationToken cancellationToken)
    {
        await using var command = run.Context.CreateCommand();
        command.CommandText = run.TenantId is null
            ? "SELECT current_user::text, '', 0::bigint"
            : "SELECT current_user::text, current_setting('gatekeep.tenant_id'), (SELECT count(*) FROM job_payload)";

        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            await reader.ReadAsync(cancellationToken);
            _runs.Enqueue(new RunRecord(
                run.JobId, run.TenantId, run.Ids, reader.GetString(0), reader.GetString(1), reader.GetInt64(2), run.HasCredential));
        }

        await _body(run, cancellationToken);
    }

    private sealed record RunRecord(
        Guid JobId,
        Guid? TenantId,
        IReadOnlyDictionary<string, Guid> Ids,
        string Role,
        string ScopeTenant,
        long VisiblePayloads,
        bool HasCredential);
}
