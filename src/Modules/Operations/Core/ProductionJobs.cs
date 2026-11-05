using Gatekeep.Kernel.Jobs;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>The production job registry (AD-15). The migration holds the guard rendered from it.</summary>
internal static class ProductionJobs
{
    public static readonly TimeSpan PurgeAge = TimeSpan.FromDays(30);

    public static readonly JobType Purge = new("operations.job.purge");

    public static readonly JobType RunOperation = new("operations.operation.run");

    public static readonly JobType RunOperationStep = new("operations.operation.step");

    public static readonly JobType SweepRetention = new("audit.retention.sweep");

    public static readonly JobType ApplyRetention = new("audit.retention.apply");

    public static readonly JobType DeploymentRetention = new("audit.retention.deployment");

    public static readonly JobType PurgeChain = new("audit.chain.purge");

    public static readonly JobType BackfillTenantKeys = TenantKeyBackfill.Type;

    public static readonly JobType RotateSigningKeys = SigningKeyJobs.RotateType;

    public static readonly JobType DestroySigningKey = SigningKeyJobs.DestroyType;

    public static readonly JobType SweepTransitKeys = SigningKeyJobs.SweepType;

    public static readonly JobRegistry Registry = new(
    [
        new JobDefinition(
            Purge,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: PurgeAsync,
            review: new JobReview(
                "Story 1.8 build review",
                new DateOnly(2026, 11, 2),
                "Touches only the control table job, deleting done rows finished more than 30 days ago. "
                + "It takes no parameter, and no Tenant table is read or written.")),
        new JobDefinition(
            RunOperation,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Admin, JobRole.Cli, JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: OperationJobs.RunAsync,
            review: new JobReview(
                "Story 1.9 build review",
                new DateOnly(2026, 11, 2),
                "Its only parameter is the operation_id. In its own scope it reads and writes only the control "
                + "tables operation and operation_step, running the Operation's Deployment stages. Each pending "
                + "Tenant step fans out into one operations.operation.step job, enqueued in that Tenant's own scope.")),
        new JobDefinition(
            RunOperationStep,
            JobScope.Tenant,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: OperationJobs.StepAsync),
        new JobDefinition(
            SweepRetention,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: AuditRetentionJobs.SweepAsync,
            review: new JobReview(
                "Story 7.3 build review",
                new DateOnly(2026, 11, 2),
                "Takes no parameter. In its own scope it reads only tenant IDs and the job table. For each Tenant "
                + "it enqueues one audit.retention.apply job in that Tenant's own scope, unless one is already "
                + "waiting there. It deletes nothing: the apply job does, as gk_retention.")),
        new JobDefinition(
            ApplyRetention,
            JobScope.Tenant,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Retention,
            maxAttempts: 5,
            handler: AuditRetentionJobs.ApplyAsync),
        new JobDefinition(
            DeploymentRetention,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Retention,
            maxAttempts: 5,
            handler: AuditRetentionJobs.ApplyAsync,
            review: new JobReview(
                "Story 7.3 build review",
                new DateOnly(2026, 11, 2),
                "Takes no parameter. As gk_retention, under the chain's seal lock, it deletes only the Deployment "
                + "chain's sealed prefix older than the fixed 90-day period, never its head, with that prefix's "
                + "detail, and writes one checkpoint event. It reads and writes no Tenant table.")),
        new JobDefinition(
            PurgeChain,
            JobScope.Tenant,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Retention,
            maxAttempts: 20,
            handler: AuditRetentionJobs.PurgeAsync),
        new JobDefinition(
            BackfillTenantKeys,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: TenantKeyBackfill.RunAsync,
            review: new JobReview(
                "Story 2.3 build review",
                new DateOnly(2026, 11, 5),
                "Takes no parameter. In its own scope it reads only the IDs of active Tenants. For each it opens "
                + "that Tenant's own scope and, only where the Tenant lacks them, creates its Signing and Management "
                + "keys and its wrapped token protection key in key custody and inserts their signing_key and "
                + "protection_key_wrap rows with one audit event. It updates and deletes nothing.")),
        new JobDefinition(
            RotateSigningKeys,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: SigningKeyJobs.RotateAsync,
            review: new JobReview(
                "Story 2.4 build review",
                new DateOnly(2026, 11, 5),
                "Takes no parameter. In its own scope it reads only the IDs of active Tenants. For each it opens that "
                + "Tenant's own scope, under the provisioning lock, and only for keys past their age rotates current to "
                + "previous and next to current, creates one replacement next key in key custody, retires previous keys "
                + "whose tokens have expired and enqueues one ID-only destroy job per retired row, with one audit event "
                + "per change and a NOTIFY of the Tenant ID. It deletes nothing.")),
        new JobDefinition(
            DestroySigningKey,
            JobScope.Tenant,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 20,
            handler: SigningKeyJobs.DestroyAsync,
            review: new JobReview(
                "Story 2.4 build review",
                new DateOnly(2026, 11, 5),
                "Its only parameter is one signing_key row ID, never a key name. In its Tenant's scope it re-reads and "
                + "locks that row and, only if it is retired and not yet destroyed, deletes the Transit key the row's "
                + "own IDs name and sets destroyed_at with one audit event. A custody failure commits one failure event "
                + "and retries. No other row or key is touched.")),
        new JobDefinition(
            SweepTransitKeys,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: SigningKeyJobs.SweepAsync,
            review: new JobReview(
                "Story 2.4 build review",
                new DateOnly(2026, 11, 5),
                "Takes no parameter. It lists key names in custody and considers only sig- and mgmt- names older than "
                + "24 hours. For each it reads, in that key's Tenant scope, whether a signing_key row names it, and only "
                + "when none does deletes it with one Deployment audit event. Secret class and Deployment keys are never "
                + "read or deleted.")),
    ]);

    private const string DeleteDone =
        """
        DELETE FROM job
        WHERE status = 'done' AND finished_at < now() - make_interval(secs => @age_seconds)
        """;

    private static async Task PurgeAsync(JobRun run, CancellationToken cancellationToken)
    {
        await using var command = run.Context.CreateCommand();
        command.CommandText = DeleteDone;
        Sql.Add(command, "age_seconds", PurgeAge.TotalSeconds);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
