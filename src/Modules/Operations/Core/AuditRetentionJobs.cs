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

    private const string ListTenants = "SELECT id, status = 'deleted' FROM tenant ORDER BY id";

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

    /// <summary>
    /// Lists the Tenants and enqueues one apply job for each that has none waiting. For a deleted
    /// Tenant whose chain still holds an event it also schedules the chain's purge again when no
    /// purge job is pending or running (Story 1.29): a purge job that went dead, or was never
    /// enqueued, is replaced within a day, so a deleted Tenant's chain is never kept for good.
    /// </summary>
    public static async Task SweepAsync(JobRun run, CancellationToken cancellationToken)
    {
        var tenants = new List<(Guid Id, bool Deleted)>();
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = ListTenants;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                tenants.Add((reader.GetGuid(0), reader.GetBoolean(1)));
            }
        }

        foreach (var (tenantId, deleted) in tenants)
        {
            await using var scope = await TenantScope.BeginAsync(run.Services.Source, tenantId, cancellationToken);
            var context = scope.CreateCommandContext();

            if (!await HasActiveJobAsync(context, ProductionJobs.ApplyRetention, tenantId, cancellationToken))
            {
                await Enqueuer.EnqueueAsync(context, ProductionJobs.ApplyRetention, payload: null, runAfter: null, cancellationToken);
            }

            if (deleted)
            {
                await SchedulePurgeAsync(context, tenantId, cancellationToken, skipWhenEmpty: true);
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

        await SchedulePurgeAsync(run.Context, tenantId, cancellationToken);
        return OperationStepResult.Success(PurgeQueued);
    }

    /// <summary>
    /// Enqueues the Tenant's <c>audit.chain.purge</c> job, in its own scope as <c>gk_worker</c>,
    /// unless one is pending or running: due once its newest non-checkpoint event is past
    /// <see cref="RetentionPeriods.LogDays"/>, whatever the Tenant's label. The purge stage, and from
    /// Story 1.29 a Tenant deletion's completion, once <c>tenancy.tenant.deleted</c> is written.
    /// </summary>
    /// <param name="skipWhenEmpty">The sweep's case: a chain with no event left, already purged, gets no job.</param>
    /// <returns>Whether this call enqueued the job.</returns>
    public static async Task<bool> SchedulePurgeAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken, bool skipWhenEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's chain purge is scheduled in its own scope.");
        }

        if (await HasActiveJobAsync(context, ProductionJobs.PurgeChain, tenantId, cancellationToken))
        {
            return false;
        }

        DateTimeOffset? newest;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = NewestEvent;
            Sql.Add(command, "tenant_id", tenantId);
            Sql.Add(command, "checkpoint", AuditEvents.RetentionCheckpoint.Code.Value);
            var value = await command.ExecuteScalarAsync(cancellationToken);
            newest = value is DateTime time ? new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Utc)) : null;
        }

        if (newest is null && skipWhenEmpty)
        {
            return false;
        }

        var due = newest + TimeSpan.FromDays(RetentionPeriods.LogDays);
        var runAfter = due > DateTimeOffset.UtcNow ? due : null;

        await Enqueuer.EnqueueAsync(context, ProductionJobs.PurgeChain, payload: null, runAfter, cancellationToken);
        return true;
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
