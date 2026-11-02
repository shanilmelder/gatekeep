using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Enqueues the code-owned schedule through <see cref="IJobEnqueuer"/> (AD-15), so a
/// scheduled job runs through the same path as any other. An entry is due when no job of
/// its type is pending or running and none was created within its interval. The check
/// and the insert hold a transaction-level lock on the type, so two ticks can't both enqueue.
/// </summary>
internal sealed class JobScheduleRunner : IJobScheduleRunner
{
    /// <summary>The first key of every job-schedule lock, so no other advisory lock can collide with one.</summary>
    private const int LockNamespace = 0x4A4F4253;

    private const string LockType = "SELECT pg_advisory_xact_lock(@namespace, hashtext(@type))";

    private const string Busy =
        """
        SELECT EXISTS (
          SELECT 1 FROM job
          WHERE type = @type
            AND (status IN ('pending', 'running') OR created_at > now() - make_interval(secs => @interval_seconds)))
        """;

    private readonly IReadOnlyList<ScheduleEntry> _entries;
    private readonly IJobEnqueuer _enqueuer;
    private readonly ILogger? _logger;
    private readonly NpgsqlDataSource _worker;
    private bool _roleChecked;

    public JobScheduleRunner(
        JobRegistry registry,
        IReadOnlyList<ScheduleEntry> entries,
        string workerDatabase,
        ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(entries);

        if (string.IsNullOrWhiteSpace(workerDatabase))
        {
            throw new ArgumentException("The Worker database has no connection string.", nameof(workerDatabase));
        }

        foreach (var entry in entries)
        {
            ArgumentNullException.ThrowIfNull(entry, nameof(entries));

            if (registry.Find(entry.Type) is not { Scope: JobScope.DeploymentWide })
            {
                throw new ArgumentException($"Scheduled type {entry.Type} isn't a Deployment-wide registry type.", nameof(entries));
            }

            if (entry.Interval <= TimeSpan.Zero)
            {
                throw new ArgumentException($"Scheduled type {entry.Type} needs a positive interval.", nameof(entries));
            }
        }

        if (entries.Select(e => e.Type.Value).Distinct(StringComparer.Ordinal).Count() != entries.Count)
        {
            throw new ArgumentException("A type is scheduled once.", nameof(entries));
        }

        _entries = [.. entries];
        _enqueuer = new JobEnqueuer(registry, custody: null);
        _logger = logger;
        _worker = NpgsqlDataSource.Create(workerDatabase);
    }

    public async Task<int> TickAsync(CancellationToken cancellationToken)
    {
        // A misconfigured connection would enqueue under another role's grants.
        if (!_roleChecked)
        {
            await RoleCheck.EnsureAsync(_worker, JobRole.Worker, cancellationToken);
            _roleChecked = true;
        }

        var enqueued = 0;

        foreach (var entry in _entries)
        {
            try
            {
                if (await TickEntryAsync(entry, cancellationToken))
                {
                    enqueued++;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception e)
            {
                // One failing entry doesn't stop the rest. The type and error type only.
                _logger?.LogError("Job schedule entry {JobType} failed on {ErrorType}.", entry.Type.Value, e.GetType().Name);
            }
        }

        return enqueued;
    }

    private async Task<bool> TickEntryAsync(ScheduleEntry entry, CancellationToken cancellationToken)
    {
        await using var scope = await DeploymentScope.BeginAsync(_worker, cancellationToken);
        var context = scope.CreateCommandContext();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockType;
            Sql.Add(command, "namespace", LockNamespace);
            Sql.Add(command, "type", entry.Type.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        bool busy;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Busy;
            Sql.Add(command, "type", entry.Type.Value);
            Sql.Add(command, "interval_seconds", entry.Interval.TotalSeconds);
            busy = (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
        }

        if (busy)
        {
            return false;
        }

        await _enqueuer.EnqueueAsync(context, entry.Type, operationId: null, runAfter: null, cancellationToken);
        await scope.CommitAsync(cancellationToken);
        return true;
    }

    public async Task RunAsync(TimeSpan tickInterval, CancellationToken cancellationToken)
    {
        if (tickInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(tickInterval));
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await TickAsync(cancellationToken);
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
                _logger?.LogError("Job schedule tick failed on {ErrorType}.", e.GetType().Name);
            }

            try
            {
                await Task.Delay(tickInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    public ValueTask DisposeAsync() => _worker.DisposeAsync();
}
