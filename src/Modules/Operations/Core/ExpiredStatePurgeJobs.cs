using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Identity.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// The Story 4.3 purge of expired sign-in state (FR-8, NFR-3, AD-13, AD-15), following the audit retention sweep and
/// apply. <c>sessions.expired_state.sweep</c> runs hourly, Deployment-wide as <c>gk_worker</c>: it reads only the active
/// Tenants' IDs and the job table, and enqueues one <c>sessions.expired_state.purge</c> in each Tenant's own scope
/// unless one is already waiting there. It deletes nothing. The purge, as <c>gk_worker</c> in its Tenant's scope and its
/// one transaction, calls each owning module's purge, children before parents (AD-1): Sessions' expired tokens, dead
/// Token Families and over, unanchored Sessions, then Authentication's transactions past their restart retention, then
/// Identity's verification links an hour past their expiry (Story 4.7), all against one clock read once. A run that deleted anything writes one <see cref="SessionsEvents.ExpiredStatePurged"/>
/// with actor System; one that deleted nothing writes nothing. A failure rolls the whole run back for a retry.
/// </summary>
internal static class ExpiredStatePurgeJobs
{
    public static readonly JobType SweepType = new("sessions.expired_state.sweep");

    public static readonly JobType PurgeType = new("sessions.expired_state.purge");

    private const string ListActive = "SELECT id FROM tenant WHERE status = 'active' ORDER BY id";

    private const string IsActive = "SELECT EXISTS (SELECT 1 FROM tenant WHERE id = @tenant_id AND status = 'active')";

    private const string ActiveJob =
        """
        SELECT EXISTS (
          SELECT 1 FROM job
          WHERE type = @type AND tenant_id = @tenant_id AND status IN ('pending', 'running'))
        """;

    private static readonly IAuditAppender Appender = AuditContract.CreateAppender();

    // Built on use: the production registry names these handlers, so it can't be read while it's being built.
    private static JobEnqueuer Enqueuer => new(ProductionJobs.Registry, custody: null);

    /// <summary>Enqueues one purge per active Tenant, in that Tenant's own scope, unless one is pending or running there.</summary>
    public static async Task SweepAsync(JobRun run, CancellationToken cancellationToken)
    {
        var tenants = new List<Guid>();
        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = ListActive;
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

            if (await HasActiveJobAsync(context, tenantId, cancellationToken))
            {
                continue;
            }

            await Enqueuer.EnqueueAsync(context, PurgeType, payload: null, runAfter: null, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Purges the job's Tenant's expired state in the run's one transaction, with one event if anything went. A Tenant
    /// no longer active when it runs, deleting or deleted, is its deletion's to purge: this deletes and writes nothing.
    /// </summary>
    public static async Task PurgeAsync(JobRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.Context.TenantId
            ?? throw new InvalidOperationException("The expired-state purge runs for one Tenant.");

        await using (var command = run.Context.CreateCommand())
        {
            command.CommandText = IsActive;
            Sql.Add(command, "tenant_id", tenantId);
            if (!(bool)(await command.ExecuteScalarAsync(cancellationToken))!)
            {
                return;
            }
        }

        await PurgeAsync(run.Context, (run.Services.Time ?? TimeProvider.System).GetUtcNow(), cancellationToken);
    }

    /// <summary>The purge itself, against <paramref name="now"/>, in <paramref name="context"/>'s Tenant scope.</summary>
    /// <returns>How many rows it deleted.</returns>
    public static async Task<int> PurgeAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        _ = context.TenantId ?? throw new InvalidOperationException("The expired-state purge runs for one Tenant.");

        var deleted = await SessionsContract.PurgeExpiredStateAsync(context, now, cancellationToken);
        deleted += await AuthenticationContract.PurgeExpiredStateAsync(context, now, cancellationToken);
        deleted += await IdentityContract.PurgeExpiredStateAsync(context, now, cancellationToken);

        if (deleted > 0)
        {
            await Appender.AppendAsync(
                context,
                new AuditEvent(SessionsEvents.ExpiredStatePurged.Code, Actor.System),
                detail: null,
                cancellationToken);
        }

        return deleted;
    }

    private static async Task<bool> HasActiveJobAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = ActiveJob;
        Sql.Add(command, "type", PurgeType.Value);
        Sql.Add(command, "tenant_id", tenantId);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
    }
}
