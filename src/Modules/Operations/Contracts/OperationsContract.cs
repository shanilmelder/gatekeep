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

    /// <summary>Runs an Operation: fans out its Tenant steps and runs its Deployment steps (AD-30).</summary>
    public static JobType RunOperation => ProductionJobs.RunOperation;

    /// <summary>Runs one Tenant step of an Operation in that Tenant's own scope.</summary>
    public static JobType RunOperationStep => ProductionJobs.RunOperationStep;

    /// <summary>
    /// The code-owned production Operation types. None exists yet: Tenant creation and deletion
    /// arrive in their own stories.
    /// </summary>
    public static OperationRegistry ProductionOperationRegistry => ProductionOperations.Registry;

    /// <summary>Starts, retries and reads Operations of the types in <paramref name="registry"/>.</summary>
    public static IOperations CreateOperations(OperationRegistry registry) => new OperationService(registry);

    /// <summary>
    /// The enqueuer for a registry. <paramref name="custody"/> encrypts credentials under the
    /// Tenant's <c>payload</c> key. Without it, a credential is refused.
    /// </summary>
    public static IJobEnqueuer CreateEnqueuer(JobRegistry registry, IKeyCustody? custody) =>
        new JobEnqueuer(registry, custody);

    /// <summary>
    /// A runner over a registry. <paramref name="custody"/> decrypts credentials. Without it,
    /// a job carrying one fails with a fixed reason code. The Operation jobs look up stage
    /// handlers in <paramref name="operations"/>, by default <see cref="ProductionOperationRegistry"/>.
    /// </summary>
    public static IJobRunner CreateRunner(
        JobRegistry registry,
        JobDatabases databases,
        JobRunnerOptions? options,
        IKeyCustody? custody,
        ILogger? logger,
        OperationRegistry? operations = null) =>
        new JobRunner(registry, databases, options ?? new JobRunnerOptions(), custody, operations ?? ProductionOperations.Registry, logger);

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
