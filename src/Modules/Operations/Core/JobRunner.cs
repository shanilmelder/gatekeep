using System.Data.Common;
using System.Text.Json;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Claims as <c>gk_dispatch</c>, which sees <c>job</c> only. A body runs in its own scope,
/// for the job's Tenant or the Deployment, under the registry's run-as role. One
/// <c>gk_worker</c> scope then finishes the job, so <c>done</c> and the payload's deletion,
/// or <c>dead</c>, the erased credential and its audit event, commit together (AD-15).
/// </summary>
internal sealed class JobRunner : IJobRunner
{
    public const string Channel = "gatekeep_job";

    private const string ClaimJob =
        """
        UPDATE job
        SET status = 'running', attempts = attempts + 1, locked_until = now() + make_interval(secs => @lease_seconds)
        WHERE id = (
          SELECT id FROM job
          WHERE (status = 'pending' AND run_after <= now()) OR (status = 'running' AND locked_until < now())
          ORDER BY run_after
          FOR UPDATE SKIP LOCKED
          LIMIT 1)
        RETURNING id, type, tenant_id, operation_id, attempts
        """;

    private const string RetryJob =
        """
        UPDATE job
        SET status = 'pending', run_after = now() + make_interval(secs => @delay_seconds),
            locked_until = NULL, failure_code = @failure_code
        WHERE id = @id AND status = 'running' AND attempts = @attempt
        """;

    // A dead job's reason code is written with its dead mark and audit event, so they
    // commit together. Success keeps the code of any earlier failed attempt.
    private const string MarkFinished =
        """
        UPDATE job
        SET status = @status, locked_until = NULL, finished_at = now(),
            failure_code = coalesce(@failure_code::text, failure_code)
        WHERE id = @id AND status = 'running' AND attempts = @attempt
        """;

    // Hands an interrupted claim back unspent, so stopping the host costs no attempt.
    private const string ReleaseClaim =
        """
        UPDATE job
        SET status = 'pending', attempts = attempts - 1, locked_until = NULL
        WHERE id = @id AND attempts = @attempt AND status = 'running'
        """;

    private const string DeletePayload = "DELETE FROM job_payload WHERE tenant_id = @tenant_id AND job_id = @id";

    private const string ErasePayloadCredential =
        """
        UPDATE job_payload
        SET ciphertext = NULL
        WHERE tenant_id = @tenant_id AND job_id = @id
        """;

    private const string ReadPayload = "SELECT ids::text, ciphertext FROM job_payload WHERE tenant_id = @tenant_id AND job_id = @id";

    private const string ReadPayloadIds = "SELECT ids::text FROM job_payload WHERE tenant_id = @tenant_id AND job_id = @id";

    // A dead Operation job can't finish its steps, so they fail, and the Operation with them, which
    // Retry then reopens (Story 1.27). Steps before the Operation: the order a step job locks them in.
    private const string FailOpenSteps =
        """
        UPDATE operation_step
        SET status = 'failed', result_code = @result_code, updated_at = now()
        WHERE operation_id = @operation_id AND status IN ('pending', 'running')
        """;

    // A dead run job leaves a dispatched Tenant step to its own step job: only what it hadn't handed on fails.
    private const string FailUndispatchedSteps =
        """
        UPDATE operation_step
        SET status = 'failed', result_code = @result_code, updated_at = now()
        WHERE operation_id = @operation_id
          AND (status = 'pending' OR (tenant_id IS NULL AND status = 'running'))
        """;

    private const string FailTenantStep =
        """
        UPDATE operation_step
        SET status = 'failed', result_code = @result_code, updated_at = now()
        WHERE id = @id AND operation_id = @operation_id AND tenant_id = @tenant_id AND status IN ('pending', 'running')
        """;

    /// <summary>The result code of a step whose run or step job went dead.</summary>
    public static readonly OperationCode JobDeadCode = new("job_dead");

    private static readonly AuditTypeCode JobDead = OperationsEvents.JobDead.Code;

    private static readonly IReadOnlyDictionary<string, Guid> NoIds = new Dictionary<string, Guid>();

    private readonly JobRegistry _registry;
    private readonly JobRunnerOptions _options;
    private readonly IKeyCustody? _custody;
    private readonly OperationRegistry _operations;
    private readonly ILogger? _logger;
    private readonly IAuditAppender _appender = AuditContract.CreateAppender();
    private readonly NpgsqlDataSource _dispatch;
    private readonly Dictionary<string, NpgsqlDataSource> _runAs;
    private readonly SemaphoreSlim _roleCheck = new(1, 1);
    private bool _rolesChecked;

    public JobRunner(
        JobRegistry registry,
        JobDatabases databases,
        JobRunnerOptions options,
        IKeyCustody? custody,
        OperationRegistry operations,
        ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(operations);
        ArgumentNullException.ThrowIfNull(databases);
        ArgumentNullException.ThrowIfNull(options);

        if (options.Lease <= TimeSpan.Zero || options.BaseBackoff <= TimeSpan.Zero
            || options.MaxBackoff < options.BaseBackoff || options.NeverDeadMaxBackoff <= TimeSpan.Zero
            || options.PollInterval <= TimeSpan.Zero)
        {
            throw new ArgumentException("Runner timings must be positive, and the backoff cap at least its base.", nameof(options));
        }

        _registry = registry;
        _options = options;
        _custody = custody;
        _operations = operations;
        _logger = logger;

        _dispatch = Create(databases.Dispatch, nameof(databases.Dispatch));
        _runAs = new Dictionary<string, NpgsqlDataSource>(StringComparer.Ordinal)
        {
            [JobRole.Worker] = Create(databases.Worker, nameof(databases.Worker)),
            [JobRole.Sealer] = Create(databases.Sealer, nameof(databases.Sealer)),
            [JobRole.Retention] = Create(databases.Retention, nameof(databases.Retention)),
        };
    }

    private NpgsqlDataSource Worker => _runAs[JobRole.Worker];

    public async Task<bool> RunOnceAsync(CancellationToken cancellationToken)
    {
        await EnsureRolesAsync(cancellationToken);

        var claim = await ClaimAsync(cancellationToken);
        if (claim is null)
        {
            return false;
        }

        var definition = _registry.Find(claim.Type);
        if (definition is null)
        {
            await FailAsync(claim, null, FailureCode.UnknownType, cancellationToken);
            return true;
        }

        // Only a crash after the last attempt's claim gets here: that attempt has been made.
        if (!definition.NeverDead && claim.Attempt > definition.MaxAttempts)
        {
            await FailAsync(claim, definition, FailureCode.LeaseExpired, cancellationToken);
            return true;
        }

        var failure = await RunBodyAsync(claim, definition, cancellationToken);

        if (failure is null)
        {
            await FinishAsync(claim, "done", failureCode: null, cancellationToken);
        }
        else
        {
            await FailAsync(claim, definition, failure, cancellationToken);
        }

        return true;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        // Says whether credential jobs can be decrypted here, which no other output shows
        // until such a job fails.
        if (_custody is null)
        {
            _logger?.LogWarning("Job runner started without key custody: credential jobs fail with custody_failed.");
        }
        else
        {
            _logger?.LogInformation("Job runner started with key custody.");
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var listener = await _dispatch.OpenConnectionAsync(cancellationToken);
                await using (var listen = new NpgsqlCommand($"LISTEN {Channel}", listener))
                {
                    await listen.ExecuteNonQueryAsync(cancellationToken);
                }

                while (!cancellationToken.IsCancellationRequested)
                {
                    while (await RunOnceAsync(cancellationToken))
                    {
                    }

                    // A notification wakes the runner at once; the timeout is the polling fallback.
                    await listener.WaitAsync(_options.PollInterval, cancellationToken);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (WrongJobRoleException)
            {
                // Misconfiguration never heals: stop, so the host stops too.
                throw;
            }
            catch (Exception e)
            {
                // The type only: a message can quote a value.
                _logger?.LogError("Job runner stopped on {ErrorType} and starts again after its poll interval.", e.GetType().Name);
                await DelayAsync(_options.PollInterval, cancellationToken);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _dispatch.DisposeAsync();
        foreach (var source in _runAs.Values)
        {
            await source.DisposeAsync();
        }

        _roleCheck.Dispose();
    }

    private static NpgsqlDataSource Create(string connectionString, string name)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException($"The {name} database has no connection string.", nameof(connectionString));
        }

        return NpgsqlDataSource.Create(connectionString);
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Stopping: the loop sees the cancellation.
        }
    }

    /// <summary>A connection string for the wrong role would run bodies with the wrong grants, so each is checked once.</summary>
    private async Task EnsureRolesAsync(CancellationToken cancellationToken)
    {
        if (_rolesChecked)
        {
            return;
        }

        await _roleCheck.WaitAsync(cancellationToken);
        try
        {
            if (_rolesChecked)
            {
                return;
            }

            await RoleCheck.EnsureAsync(_dispatch, JobRole.Dispatch, cancellationToken);
            foreach (var (role, source) in _runAs)
            {
                await RoleCheck.EnsureAsync(source, role, cancellationToken);
            }

            _rolesChecked = true;
        }
        finally
        {
            _roleCheck.Release();
        }
    }

    private async Task<Claim?> ClaimAsync(CancellationToken cancellationToken)
    {
        await using var command = _dispatch.CreateCommand(ClaimJob);
        Sql.Add(command, "lease_seconds", _options.Lease.TotalSeconds);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new Claim(
            reader.GetGuid(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3),
            reader.GetInt32(4));
    }

    /// <returns>Null on success, or the failure's reason code.</returns>
    private async Task<string?> RunBodyAsync(Claim claim, JobDefinition definition, CancellationToken cancellationToken)
    {
        // The body stops a little before its claim ends, so another runner rarely overlaps it.
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lease.CancelAfter(_options.Lease * 0.9);

        try
        {
            var source = _runAs[definition.RunAs];
            await using CommandScope scope = claim.TenantId is { } tenantId
                ? await TenantScope.BeginAsync(source, tenantId, lease.Token)
                : await DeploymentScope.BeginAsync(source, lease.Token);

            var context = scope.CreateCommandContext();
            var services = new JobRunServices(source, _operations, _custody, _logger);
            var run = claim.TenantId is { } tenant
                ? await TenantRunAsync(claim, definition, tenant, context, services, lease.Token)
                : new JobRun(claim.Id, definition.Type, null, claim.OperationId, claim.Attempt, NoIds, context, null, services);

            await definition.Handler(run, lease.Token);
            await scope.CommitAsync(lease.Token);

            return null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Stopping: the body's scope rolled back, so the claim goes back unspent.
            await ReleaseClaimAsync(claim);
            throw;
        }
        catch (OperationCanceledException) when (lease.IsCancellationRequested)
        {
            return FailureCode.TimedOut;
        }
        catch (KeyCustodyException)
        {
            return FailureCode.CustodyFailed;
        }
        catch (Exception)
        {
            // Nothing from the exception is kept: only the fixed code.
            return FailureCode.HandlerFailed;
        }
    }

    private async Task<JobRun> TenantRunAsync(
        Claim claim,
        JobDefinition definition,
        Guid tenantId,
        CommandContext context,
        JobRunServices services,
        CancellationToken cancellationToken)
    {
        var ids = NoIds;
        string? ciphertext = null;

        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReadPayload;
            Sql.Add(command, "tenant_id", tenantId);
            Sql.Add(command, "id", claim.Id);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                ids = JsonSerializer.Deserialize<Dictionary<string, Guid>>(reader.GetString(0)) ?? [];
                ciphertext = reader.IsDBNull(1) ? null : reader.GetString(1);
            }
        }

        // A type that may not carry a credential never has one decrypted, whatever the row holds.
        Func<CancellationToken, Task<Secret<byte[]>>>? decrypt = null;
        if (ciphertext is not null && definition.MayCarryCredential)
        {
            var key = KeyName.ForTenant(TenantKeyClass.Payload, tenantId);
            decrypt = token => _custody is null
                ? throw new KeyCustodyException(key.Value, KeyOperation.Decrypt, KeyCustodyFailure.Unavailable)
                : _custody.DecryptAsync(key, tenantId, new KeyCiphertext(ciphertext), token);
        }

        return new JobRun(claim.Id, definition.Type, tenantId, claim.OperationId, claim.Attempt, ids, context, decrypt, services);
    }

    private async Task FailAsync(Claim claim, JobDefinition? definition, string failureCode, CancellationToken cancellationToken)
    {
        var neverDead = definition?.NeverDead ?? false;
        var exhausted = !neverDead && claim.Attempt >= (definition?.MaxAttempts ?? 1);

        _logger?.LogWarning(
            "Job {JobId} of type {JobType} failed attempt {Attempt} with {FailureCode}.",
            claim.Id,
            claim.Type,
            claim.Attempt,
            failureCode);

        if (!exhausted)
        {
            var cap = neverDead ? _options.NeverDeadMaxBackoff : _options.MaxBackoff;

            await using var retry = _dispatch.CreateCommand(RetryJob);
            AddClaim(retry, claim);
            Sql.Add(retry, "failure_code", failureCode);
            Sql.Add(retry, "delay_seconds", Backoff(claim.Attempt, _options.BaseBackoff, cap).TotalSeconds);
            await retry.ExecuteNonQueryAsync(cancellationToken);
            return;
        }

        await FinishAsync(claim, "dead", failureCode, cancellationToken);
    }

    /// <summary><c>min(base * 2^(attempt-1), cap)</c>, computed so a large attempt can't overflow.</summary>
    private static TimeSpan Backoff(int attempt, TimeSpan baseDelay, TimeSpan cap)
    {
        var factor = Math.Pow(2, Math.Min(attempt - 1, 40));
        var seconds = Math.Min(baseDelay.TotalSeconds * factor, cap.TotalSeconds);
        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>Takes no token: the host is already stopping, and the claim must still go back.</summary>
    private async Task ReleaseClaimAsync(Claim claim)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            await using var release = _dispatch.CreateCommand(ReleaseClaim);
            AddClaim(release, claim);
            await release.ExecuteNonQueryAsync(limit.Token);
        }
        catch (Exception e)
        {
            // The claim then expires and the job runs again, at the cost of one attempt.
            _logger?.LogWarning("Job {JobId} claim couldn't be released on {ErrorType}.", claim.Id, e.GetType().Name);
        }
    }

    private async Task FinishAsync(Claim claim, string status, string? failureCode, CancellationToken cancellationToken)
    {
        await using (CommandScope scope = claim.TenantId is { } tenantId
            ? await TenantScope.BeginAsync(Worker, tenantId, cancellationToken)
            : await DeploymentScope.BeginAsync(Worker, cancellationToken))
        {
            var context = scope.CreateCommandContext();

            await using (var mark = context.CreateCommand())
            {
                mark.CommandText = MarkFinished;
                AddClaim(mark, claim);
                Sql.Add(mark, "status", status);
                Sql.Add(mark, "failure_code", failureCode);

                // Another runner reclaimed it after this claim expired, so that run finishes it.
                if (await mark.ExecuteNonQueryAsync(cancellationToken) == 0)
                {
                    return;
                }
            }

            if (claim.TenantId is { } tenant)
            {
                // A dead job's IDs stay: only its credential goes, so its Operation step can be found after.
                await using var payload = context.CreateCommand();
                payload.CommandText = status == "done" ? DeletePayload : ErasePayloadCredential;
                Sql.Add(payload, "tenant_id", tenant);
                Sql.Add(payload, "id", claim.Id);
                await payload.ExecuteNonQueryAsync(cancellationToken);
            }

            if (status == "dead")
            {
                _logger?.LogError("Job {JobId} of type {JobType} is dead after {Attempt} attempts.", claim.Id, claim.Type, claim.Attempt);
                await _appender.AppendAsync(context, new AuditEvent(JobDead, Actor.System), null, cancellationToken);
            }

            await scope.CommitAsync(cancellationToken);
        }

        if (status == "dead")
        {
            // In a transaction of its own, after the job is dead for good: a failure here can't keep
            // the job from dying, or make it run again. Failing open steps is safe to repeat.
            await FailOperationStepsAsync(claim, cancellationToken);
        }
    }

    /// <summary>
    /// Fails what a dead Operation job leaves open, so the Operation finishes as failed and Retry
    /// applies (Story 1.27), in a transaction of its own, tried up to three times. A dead
    /// <c>operations.operation.run</c> job fails its Operation's <c>pending</c> steps and its
    /// Deployment steps, and leaves a dispatched Tenant step to its own step job. A dead
    /// <c>operations.operation.step</c> job fails its own step, named by its payload and matched
    /// against its Tenant; when the payload is missing or unreadable, every open step of the
    /// Operation the job names. Any other job is left alone.
    /// </summary>
    private async Task FailOperationStepsAsync(Claim claim, CancellationToken cancellationToken)
    {
        var isRun = claim.Type == ProductionJobs.RunOperation.Value && claim.TenantId is null;
        var isStep = claim.Type == ProductionJobs.RunOperationStep.Value && claim.TenantId is not null;
        if (!isRun && !isStep)
        {
            return;
        }

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await using CommandScope scope = claim.TenantId is { } tenantId
                    ? await TenantScope.BeginAsync(Worker, tenantId, cancellationToken)
                    : await DeploymentScope.BeginAsync(Worker, cancellationToken);
                var context = scope.CreateCommandContext();

                if (await FailStepsAsync(context, claim, isRun, cancellationToken) is { } operationId)
                {
                    // Only a step failed here can make it finish: a failed step never runs a completion handler.
                    await OperationStore.TryFinishAsync(context, _operations, operationId, cancellationToken);
                }

                await scope.CommitAsync(cancellationToken);
                return;
            }
            catch (Exception e) when (!cancellationToken.IsCancellationRequested && e is not WrongJobRoleException)
            {
                // The type only: a message can quote a value.
                _logger?.LogWarning(
                    "Job {JobId}'s Operation steps couldn't be failed on attempt {Attempt}, on {ErrorType}.",
                    claim.Id,
                    attempt,
                    e.GetType().Name);
                if (attempt >= 3)
                {
                    return;
                }
            }
        }
    }

    /// <returns>The Operation when a step was failed, else null.</returns>
    private static async Task<Guid?> FailStepsAsync(CommandContext context, Claim claim, bool isRun, CancellationToken cancellationToken)
    {
        if (isRun)
        {
            if (claim.OperationId is not { } run)
            {
                return null;
            }

            return await ExecuteAsync(context, FailUndispatchedSteps, run, null, null, cancellationToken) > 0 ? run : null;
        }

        var tenantId = claim.TenantId!.Value;
        Dictionary<string, Guid>? ids = null;
        await using (var read = context.CreateCommand())
        {
            read.CommandText = ReadPayloadIds;
            Sql.Add(read, "tenant_id", tenantId);
            Sql.Add(read, "id", claim.Id);
            if (await read.ExecuteScalarAsync(cancellationToken) is string json)
            {
                try
                {
                    ids = JsonSerializer.Deserialize<Dictionary<string, Guid>>(json);
                }
                catch (JsonException)
                {
                    ids = null;
                }
            }
        }

        if (ids is not null
            && ids.TryGetValue(OperationJobs.OperationIdName, out var operationId)
            && ids.TryGetValue(OperationJobs.StepIdName, out var stepId))
        {
            return await ExecuteAsync(context, FailTenantStep, operationId, stepId, tenantId, cancellationToken) > 0 ? operationId : null;
        }

        // No usable payload: the job's own Operation, so nothing stays stuck.
        if (claim.OperationId is { } fallback)
        {
            return await ExecuteAsync(context, FailOpenSteps, fallback, null, null, cancellationToken) > 0 ? fallback : null;
        }

        return null;
    }

    private static async Task<int> ExecuteAsync(
        CommandContext context,
        string sql,
        Guid operationId,
        Guid? stepId,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        Sql.Add(command, "operation_id", operationId);
        Sql.Add(command, "result_code", JobDeadCode.Value);
        if (stepId is { } step)
        {
            Sql.Add(command, "id", step);
            Sql.Add(command, "tenant_id", tenantId);
        }

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddClaim(DbCommand command, Claim claim)
    {
        Sql.Add(command, "id", claim.Id);
        Sql.Add(command, "attempt", claim.Attempt);
    }

    private sealed record Claim(Guid Id, string Type, Guid? TenantId, Guid? OperationId, int Attempt);
}
