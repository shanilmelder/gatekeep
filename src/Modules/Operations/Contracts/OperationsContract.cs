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

    /// <summary>Fans out one <c>audit.retention.apply</c> job per Tenant (AD-16). Scheduled daily.</summary>
    public static JobType SweepRetention => ProductionJobs.SweepRetention;

    /// <summary>Applies retention to one Tenant's chain, as <c>gk_retention</c>.</summary>
    public static JobType ApplyRetention => ProductionJobs.ApplyRetention;

    /// <summary>Applies retention to the Deployment chain, as <c>gk_retention</c>. Scheduled daily.</summary>
    public static JobType DeploymentRetention => ProductionJobs.DeploymentRetention;

    /// <summary>Deletes one Tenant's whole chain once its retention has ended, as <c>gk_retention</c>.</summary>
    public static JobType PurgeChain => ProductionJobs.PurgeChain;

    /// <summary>
    /// The Operation that purges a deleted Tenant's audit chain once its retention ends. Its
    /// future caller, Tenant deletion, starts it with one <see cref="PurgeChainStage"/> step for the Tenant.
    /// </summary>
    public static OperationType PurgeChainOperation => AuditRetentionJobs.PurgeOperation;

    /// <summary>The purge Operation's one Tenant stage, which enqueues <see cref="PurgeChain"/>.</summary>
    public static OperationCode PurgeChainStage => AuditRetentionJobs.PurgeStage;

    /// <summary>
    /// Creates a new Tenant's secret class keys (Story 1.27) and its Signing Keys (Story 2.3), then,
    /// once every stage has succeeded, its settings, and makes it active. Tenant creation starts it
    /// scoped to the new Tenant, with one step for it per <see cref="TenantCreationStages"/>.
    /// </summary>
    public static OperationType TenantCreationOperation => TenantCreation.Type;

    /// <summary>The creation Operation's first stage: the six secret class keys (AD-10).</summary>
    public static OperationCode TenantCreationStage => TenantCreation.SecretClassKeysStage;

    /// <summary>
    /// The creation Operation's second stage (Story 2.3): the Tenant's current and next Signing and
    /// Management keys and its wrapped token protection key, through <c>KeysContract.EnsureTenantKeysAsync</c>.
    /// </summary>
    public static OperationCode TenantSigningKeysStage => TenantCreation.SigningKeysStage;

    /// <summary>Every stage Tenant creation plans, one step each for the new Tenant.</summary>
    public static IReadOnlyList<OperationCode> TenantCreationStages => TenantCreation.Stages;

    /// <summary>
    /// Gives every active Tenant the keys it lacks, as Tenant creation does (Story 2.3). Scheduled hourly.
    /// </summary>
    public static JobType BackfillTenantKeys => ProductionJobs.BackfillTenantKeys;

    /// <summary>
    /// The code-owned production Operation types: <see cref="PurgeChainOperation"/> and
    /// <see cref="TenantCreationOperation"/>. Tenant deletion arrives in its own story.
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
    /// The audit seal loop (AD-16). <paramref name="sealerDatabase"/> must connect as
    /// <c>gk_sealer</c>: the first pass checks it, and a wrong role stops the loop.
    /// </summary>
    public static IAuditSealLoop CreateSealLoop(string sealerDatabase, TimeSpan interval, ILogger? logger) =>
        new AuditSealLoop(sealerDatabase, interval, logger);

    /// <summary>
    /// The SQL that replaces <c>job_guard_insert()</c> with one checking <paramref name="registry"/>.
    /// The migration holds the render of <see cref="ProductionRegistry"/>, and a test compares them.
    /// </summary>
    public static string RenderGuard(JobRegistry registry) => JobGuardRenderer.Render(registry);
}
