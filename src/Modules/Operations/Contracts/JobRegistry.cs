using Gatekeep.Kernel.Jobs;

namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>Whether a job belongs to one Tenant or to the whole Deployment (AD-15).</summary>
public enum JobScope
{
    Tenant,
    DeploymentWide,
}

/// <summary>The database roles a job registry may name (AD-3).</summary>
public static class JobRole
{
    public const string Hosted = "gk_hosted";
    public const string Admin = "gk_admin";
    public const string Worker = "gk_worker";
    public const string Dispatch = "gk_dispatch";
    public const string Sealer = "gk_sealer";
    public const string Retention = "gk_retention";
    public const string Cli = "gk_cli";

    /// <summary>Every runtime role. Only these can be named as enqueuers.</summary>
    public static readonly IReadOnlyList<string> Runtime = [Hosted, Admin, Worker, Dispatch, Sealer, Retention, Cli];

    /// <summary>The roles a job body may run as (AD-15).</summary>
    public static readonly IReadOnlyList<string> RunAs = [Worker, Sealer, Retention];
}

/// <summary>The recorded review a Deployment-wide job type needs (AD-15).</summary>
public sealed record JobReview(string Reviewer, DateOnly Date, string Reason);

/// <summary>Runs one job's body. It must be idempotent: delivery is at-least-once.</summary>
public delegate Task JobHandler(JobRun run, CancellationToken cancellationToken);

/// <summary>One job type in a code-owned registry.</summary>
public sealed class JobDefinition
{
    public const int MaxAttemptsLimit = 100;

    public JobDefinition(
        JobType type,
        JobScope scope,
        IReadOnlyList<string> enqueuingRoles,
        string runAs,
        int maxAttempts,
        JobHandler handler,
        bool neverDead = false,
        bool mayCarryCredential = false,
        JobReview? review = null)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(enqueuingRoles);
        ArgumentNullException.ThrowIfNull(runAs);
        ArgumentNullException.ThrowIfNull(handler);

        if (!Enum.IsDefined(scope))
        {
            throw new ArgumentOutOfRangeException(nameof(scope));
        }

        // The guard SQL is rendered from these names, so only known ones get through.
        if (enqueuingRoles.Count == 0
            || enqueuingRoles.Distinct(StringComparer.Ordinal).Count() != enqueuingRoles.Count
            || enqueuingRoles.Any(r => !JobRole.Runtime.Contains(r)))
        {
            throw new ArgumentException("Enqueuing roles are distinct runtime roles, at least one.", nameof(enqueuingRoles));
        }

        if (!JobRole.RunAs.Contains(runAs))
        {
            throw new ArgumentException("A job body runs as gk_worker, gk_sealer or gk_retention.", nameof(runAs));
        }

        if (maxAttempts is < 1 or > MaxAttemptsLimit)
        {
            throw new ArgumentOutOfRangeException(nameof(maxAttempts));
        }

        if (mayCarryCredential && scope != JobScope.Tenant)
        {
            throw new ArgumentException("A Deployment-wide job carries no payload, so no credential.", nameof(mayCarryCredential));
        }

        Type = type;
        Scope = scope;
        EnqueuingRoles = [.. enqueuingRoles];
        RunAs = runAs;
        MaxAttempts = maxAttempts;
        Handler = handler;
        NeverDead = neverDead;
        MayCarryCredential = mayCarryCredential;
        Review = review;
    }

    public JobType Type { get; }

    public JobScope Scope { get; }

    public IReadOnlyList<string> EnqueuingRoles { get; }

    public string RunAs { get; }

    /// <summary>Attempts before the job goes <c>dead</c>. A never-dead type keeps retrying past it.</summary>
    public int MaxAttempts { get; }

    public JobHandler Handler { get; }

    /// <summary>Alert types never go <c>dead</c>: they retry with capped backoff (AD-15).</summary>
    public bool NeverDead { get; }

    public bool MayCarryCredential { get; }

    public JobReview? Review { get; }
}

/// <summary>A code-owned set of job types, each listed once.</summary>
public sealed class JobRegistry
{
    private readonly Dictionary<string, JobDefinition> _byType;

    public JobRegistry(IEnumerable<JobDefinition> definitions)
    {
        ArgumentNullException.ThrowIfNull(definitions);

        Definitions = [.. definitions];

        if (Definitions.Count == 0)
        {
            throw new ArgumentException("A registry lists at least one job type.", nameof(definitions));
        }

        _byType = new Dictionary<string, JobDefinition>(StringComparer.Ordinal);
        foreach (var definition in Definitions)
        {
            ArgumentNullException.ThrowIfNull(definition, nameof(definitions));

            if (!_byType.TryAdd(definition.Type.Value, definition))
            {
                throw new ArgumentException($"Job type {definition.Type} is listed twice.", nameof(definitions));
            }
        }
    }

    public IReadOnlyList<JobDefinition> Definitions { get; }

    public JobDefinition? Find(JobType type) => _byType.GetValueOrDefault(type.Value);

    public JobDefinition? Find(string type) => _byType.GetValueOrDefault(type);
}
