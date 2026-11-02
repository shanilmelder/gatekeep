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

    private static readonly AuditTypeCode JobDead = new("operations.job.dead");

    private static readonly IReadOnlyDictionary<string, Guid> NoIds = new Dictionary<string, Guid>();

    private readonly JobRegistry _registry;
    private readonly JobRunnerOptions _options;
    private readonly IKeyCustody? _custody;
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
        ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(registry);
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
            var run = claim.TenantId is { } tenant
                ? await TenantRunAsync(claim, definition, tenant, context, lease.Token)
                : new JobRun(claim.Id, definition.Type, null, claim.OperationId, claim.Attempt, NoIds, context, null);

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

        return new JobRun(claim.Id, definition.Type, tenantId, claim.OperationId, claim.Attempt, ids, context, decrypt);
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
        await using CommandScope scope = claim.TenantId is { } tenantId
            ? await TenantScope.BeginAsync(Worker, tenantId, cancellationToken)
            : await DeploymentScope.BeginAsync(Worker, cancellationToken);

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

    private static void AddClaim(DbCommand command, Claim claim)
    {
        Sql.Add(command, "id", claim.Id);
        Sql.Add(command, "attempt", claim.Attempt);
    }

    private sealed record Claim(Guid Id, string Type, Guid? TenantId, Guid? OperationId, int Attempt);
}
