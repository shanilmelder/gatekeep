using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Core;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>What a composition root uses to wire jobs (AD-15).</summary>
public static class OperationsContract
{
    /// <summary>Deletes <c>done</c> jobs finished more than 30 days ago.</summary>
    public static JobType PurgeJobs => ProductionJobs.Purge;

    /// <summary>The code-owned production registry. No type exists in it only for tests.</summary>
    public static JobRegistry ProductionRegistry => ProductionJobs.Registry;

    /// <summary>
    /// The enqueuer for a registry. <paramref name="custody"/> encrypts credentials under the
    /// Tenant's <c>payload</c> key. Without it, a credential is refused.
    /// </summary>
    public static IJobEnqueuer CreateEnqueuer(JobRegistry registry, IKeyCustody? custody) =>
        new JobEnqueuer(registry, custody);

    /// <summary>
    /// A runner over a registry. <paramref name="custody"/> decrypts credentials. Without it,
    /// a job carrying one fails with a fixed reason code.
    /// </summary>
    public static IJobRunner CreateRunner(
        JobRegistry registry,
        JobDatabases databases,
        JobRunnerOptions? options,
        IKeyCustody? custody,
        ILogger? logger) =>
        new JobRunner(registry, databases, options ?? new JobRunnerOptions(), custody, logger);

    /// <summary>A schedule runner. It enqueues as the role of <paramref name="workerDatabase"/>.</summary>
    public static IJobScheduleRunner CreateScheduleRunner(
        JobRegistry registry,
        IReadOnlyList<ScheduleEntry> entries,
        string workerDatabase,
        ILogger? logger) =>
        new JobScheduleRunner(registry, entries, workerDatabase, logger);

    /// <summary>
    /// The SQL that replaces <c>job_guard_insert()</c> with one checking <paramref name="registry"/>.
    /// The migration holds the render of <see cref="ProductionRegistry"/>, and a test compares them.
    /// </summary>
    public static string RenderGuard(JobRegistry registry) => JobGuardRenderer.Render(registry);
}
