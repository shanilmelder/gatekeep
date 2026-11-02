using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Retention;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// The AD-16 retention jobs. <c>audit.retention.sweep</c> runs Deployment-wide as
/// <c>gk_worker</c> and fans out one <c>audit.retention.apply</c> per Tenant, each enqueued
/// in that Tenant's own scope. The apply, Deployment and purge jobs run as
/// <c>gk_retention</c>, the only role that may delete events. Every one is idempotent: a
/// second cut finds nothing due, and a second purge finds nothing left.
/// </summary>
internal static class AuditRetentionJobs
{
    public static readonly OperationType PurgeOperation = new("audit.chain.purge");

    public static readonly OperationCode PurgeStage = new("audit.chain.purge");

    /// <summary>The purge stage's code once its job is queued. The chain goes when the job runs.</summary>
    public static readonly OperationCode PurgeQueued = new("purge_queued");

    private const string ListTenants = "SELECT id FROM tenant ORDER BY id";

    private const string ActiveJob =
        """
        SELECT EXISTS (
          SELECT 1 FROM job
          WHERE type = @type AND tenant_id = @tenant_id AND status IN ('pending', 'running'))
        """;

    // A checkpoint is retention's own record, so it doesn't push the purge back.
    private const string NewestEvent =
        "SELECT max(occurred_at) FROM audit_event WHERE tenant_id = @tenant_id AND type_code <> @checkpoint";

    private static readonly IAuditRetention Retention = AuditContract.CreateRetention();

    // Built on use: the production registry names these handlers, so it can't be read while it's being built.
    private static JobEnqueuer Enqueuer => new(ProductionJobs.Registry, custody: null);

    /// <summary>Lists the Tenants and enqueues one apply job for each that has none waiting.</summary>
    public static async Task SweepAsync(JobRun run, CancellationToken cancellationToken)
    {
        var tenants = new List<Guid>();
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = ListTenants;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                tenants.Add(reader.GetGuid(0));
            }
        }

        foreach (var tenantId in tenants)
        {
            await using var scope = await TenantScope.BeginAsync(run.Services.Source, tenantId, cancellationToken);
            var context = scope.CreateCommandContext();

            if (!await HasActiveJobAsync(context, ProductionJobs.ApplyRetention, tenantId, cancellationToken))
            {
                await Enqueuer.EnqueueAsync(context, ProductionJobs.ApplyRetention, payload: null, runAfter: null, cancellationToken);
            }

            await scope.CommitAsync(cancellationToken);
        }
    }

    /// <summary>Cuts the job's own chain: its Tenant's, or the Deployment's for a Deployment-wide job.</summary>
    public static Task ApplyAsync(JobRun run, CancellationToken cancellationToken) =>
        Retention.ApplyAsync(run.Context, cancellationToken);

    /// <summary>Throws while retention hasn't ended, so the job is retried with a fixed failure code and nothing deleted.</summary>
    public static async Task PurgeAsync(JobRun run, CancellationToken cancellationToken)
    {
        if (!await Retention.PurgeAsync(run.Context, cancellationToken))
        {
            throw new InvalidOperationException("The Tenant's audit chain is still inside its retention, or not all sealed.");
        }
    }

    /// <summary>
    /// The purge Operation's Tenant stage, as <c>gk_worker</c> in the Tenant's own scope: it
    /// enqueues the purge job, due once the newest event is past retention, so its retries
    /// aren't spent waiting out the period.
    /// </summary>
    public static async Task<OperationStepResult> PurgeStageAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The purge stage runs for one Tenant.");

        if (await HasActiveJobAsync(run.Context, ProductionJobs.PurgeChain, tenantId, cancellationToken))
        {
            return OperationStepResult.Success(PurgeQueued);
        }

        DateTimeOffset? newest;
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = NewestEvent;
            Sql.Add(command, "tenant_id", tenantId);
            Sql.Add(command, "checkpoint", AuditContract.CheckpointTypeCode);
            var value = await command.ExecuteScalarAsync(cancellationToken);
            newest = value is DateTime time ? new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)) : null;
        }

        var due = newest + TimeSpan.FromDays(RetentionPeriods.LogDays);
        var runAfter = due > DateTimeOffset.UtcNow ? due : null;

        await Enqueuer.EnqueueAsync(run.Context, ProductionJobs.PurgeChain, payload: null, runAfter, cancellationToken);
        return OperationStepResult.Success(PurgeQueued);
    }

    private static async Task<bool> HasActiveJobAsync(
        CommandContext context,
        JobType type,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = ActiveJob;
        Sql.Add(command, "type", type.Value);
        Sql.Add(command, "tenant_id", tenantId);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
    }
}
