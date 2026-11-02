using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Core;

namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>
/// One attempt at one job, as its handler sees it. <see cref="Context"/> belongs to the
/// body's own scope: the job's Tenant only, or the Deployment, under the registry's
/// run-as role. The runner ends that scope, so the handler never does.
/// </summary>
public sealed class JobRun
{
    private readonly Func<CancellationToken, Task<Secret<byte[]>>>? _decrypt;

    internal JobRun(
        Guid jobId,
        JobType type,
        Guid? tenantId,
        Guid? operationId,
        int attempt,
        IReadOnlyDictionary<string, Guid> ids,
        CommandContext context,
        Func<CancellationToken, Task<Secret<byte[]>>>? decrypt,
        JobRunServices services)
    {
        JobId = jobId;
        Type = type;
        TenantId = tenantId;
        OperationId = operationId;
        Attempt = attempt;
        Ids = ids;
        Context = context;
        _decrypt = decrypt;
        Services = services;
    }

    public Guid JobId { get; }

    public JobType Type { get; }

    /// <summary>The job's Tenant. Null for a Deployment-wide job.</summary>
    public Guid? TenantId { get; }

    public Guid? OperationId { get; }

    /// <summary>This attempt's number, from 1.</summary>
    public int Attempt { get; }

    /// <summary>The payload's IDs. Destructive handlers re-check authoritative state rather than trust them (AD-15).</summary>
    public IReadOnlyDictionary<string, Guid> Ids { get; }

    public CommandContext Context { get; }

    public bool HasCredential => _decrypt is not null;

    /// <summary>What Operations' own handlers need beyond the context: the run-as database and the Operation registry.</summary>
    internal JobRunServices Services { get; }

    /// <summary>Decrypts the payload's credential at the moment of use (AD-10).</summary>
    /// <exception cref="InvalidOperationException">The payload has no credential.</exception>
    public Task<Secret<byte[]>> DecryptCredentialAsync(CancellationToken cancellationToken) =>
        _decrypt is null
            ? throw new InvalidOperationException("This job carries no credential.")
            : _decrypt(cancellationToken);
}

/// <summary>Where the runner reaches the database: one connection string per role it uses.</summary>
public sealed record JobDatabases(string Dispatch, string Worker, string Sealer, string Retention)
{
    public override string ToString() => nameof(JobDatabases);
}

/// <summary>How the runner claims and retries. The defaults are the AD-15 design values.</summary>
public sealed record JobRunnerOptions
{
    /// <summary>How long a claim lasts. A body still running at the end of it is cancelled, and the job is claimed again.</summary>
    public TimeSpan Lease { get; init; } = TimeSpan.FromMinutes(5);

    public TimeSpan BaseBackoff { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan MaxBackoff { get; init; } = TimeSpan.FromHours(1);

    public TimeSpan NeverDeadMaxBackoff { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How long the runner waits for a notification before it looks anyway.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>Claims and runs jobs (AD-15).</summary>
public interface IJobRunner : IAsyncDisposable
{
    /// <summary>Claims one due job, runs it and finishes it.</summary>
    /// <returns>False when no job was due.</returns>
    Task<bool> RunOnceAsync(CancellationToken cancellationToken);

    /// <summary>Runs jobs until cancelled, woken by <c>NOTIFY</c> and by polling.</summary>
    Task RunAsync(CancellationToken cancellationToken);
}

/// <summary>A recurring Deployment-wide job, due once per <paramref name="Interval"/>.</summary>
public sealed record ScheduleEntry(JobType Type, TimeSpan Interval);

/// <summary>Enqueues scheduled jobs through <see cref="IJobEnqueuer"/>, so they run through the same path.</summary>
public interface IJobScheduleRunner : IAsyncDisposable
{
    /// <summary>Enqueues each due entry that has no pending or running job of its type.</summary>
    /// <returns>How many jobs were enqueued.</returns>
    Task<int> TickAsync(CancellationToken cancellationToken);

    /// <summary>Ticks every <paramref name="tickInterval"/> until cancelled.</summary>
    Task RunAsync(TimeSpan tickInterval, CancellationToken cancellationToken);
}
