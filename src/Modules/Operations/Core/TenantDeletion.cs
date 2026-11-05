using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Identity.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// <c>tenancy.tenant.delete</c> (Story 1.29, AD-30): the Worker-only half of deleting a Tenant.
/// Host.Admin's start command has already set the Tenant <c>deleting</c>, so its host stopped
/// resolving, removed every Tenant Role in it, and written this Operation, scoped to it. Its two
/// Tenant stages are independent, so they run in either order on a Tenant nobody can reach: one
/// purges every module's <c>tenant</c> tables but Audit's, the other destroys the six secret class
/// keys, which only Host.Worker's custody policy may (AD-10). Each re-checks the Tenant is
/// <c>deleting</c> under <c>FOR SHARE</c> first. Once both have succeeded, its completion purges
/// Operations' own <c>job_payload</c> rows, marks the Tenant <c>deleted</c> with
/// <c>tenancy.tenant.deleted</c> on its chain, and schedules the chain's purge for when that event is
/// past retention. Every step and the completion are idempotent.
/// </summary>
internal static class TenantDeletion
{
    public static readonly OperationType Type = new("tenancy.tenant.delete");

    public static readonly OperationCode PurgeStage = new("tenancy.tenant.purge");

    public static readonly OperationCode DestroyKeysStage = new("keys.secret_classes.destroy");

    /// <summary>A stage for a Tenant that isn't being deleted: nothing is deleted or destroyed.</summary>
    public static readonly OperationCode TenantNotDeleting = new("tenant_not_deleting");

    /// <summary>A purge the settings guard refused (<c>GK008</c>): nothing of the purge is kept.</summary>
    public static readonly OperationCode PurgeRefused = new("purge_refused");

    /// <summary>
    /// A purge that met a row referencing what it deleted (<c>23503</c>), or a serialization failure
    /// (<c>40001</c>): nothing of the purge is kept, and Retry runs it again whole.
    /// </summary>
    public static readonly OperationCode PurgeConflict = new("purge_conflict");

    /// <summary>Custody refused the destroy (403): a policy that may not delete, which a Retry alone won't mend.</summary>
    public static readonly OperationCode CustodyRefused = new("custody_refused");

    /// <summary>
    /// The module purges the purge stage calls, in this order, in one transaction: Sessions before
    /// Identity, because <c>user_session</c> references <c>user</c> with <c>ON DELETE RESTRICT</c>.
    /// Operations' own purge runs in the completion, because the stage jobs' own payloads live there.
    /// </summary>
    public static readonly IReadOnlyList<(string Module, ITenantPurge Purge)> StagePurges =
    [
        ("Sessions", SessionsContract.TenantPurge),
        ("Authentication", AuthenticationContract.TenantPurge),
        ("Identity", IdentityContract.TenantPurge),
        ("Tenancy", TenancyContract.TenantPurge),
    ];

    /// <summary>Every module whose Tenant data the deletion purges, in order, Operations' own last.</summary>
    public static readonly IReadOnlyList<string> PurgeModules = [.. StagePurges.Select(p => p.Module), "Operations"];

    private const string SettingsRefused = "GK008";

    private const string ForeignKeyViolation = "23503";

    private const string SerializationFailure = "40001";

    private const string Savepoint = "tenant_purge";

    // Every pending job of the deleted Tenant but its chain's purge ends dead, with its own reason, so
    // none is left orphaned to run against a Tenant whose data is gone.
    private const string KillPendingJobs =
        """
        UPDATE job
        SET status = 'dead', locked_until = NULL, finished_at = now(), failure_code = 'tenant_deleted'
        WHERE tenant_id = @tenant_id AND status = 'pending' AND type <> @purge_type
        """;

    // Only the payloads of jobs that will never run again: a running job keeps its own, which the
    // runner deletes once it is done.
    private const string PurgePayloads =
        """
        DELETE FROM job_payload p
        USING job j
        WHERE p.tenant_id = @tenant_id AND j.tenant_id = @tenant_id AND j.id = p.job_id AND j.status IN ('done', 'dead')
        """;

    private static readonly ITenants Tenants = TenancyContract.CreateTenants(AuditContract.CreateAppender());

    public static readonly OperationDefinition Definition = new(
        Type,
        [
            new OperationStage(PurgeStage, OperationStageKind.Tenant, PurgeAsync),
            new OperationStage(DestroyKeysStage, OperationStageKind.Tenant, DestroySecretClassKeysAsync),
        ],
        CompleteAsync);

    /// <summary>Every module's purge, in order, under a savepoint: a refusal leaves nothing half purged.</summary>
    private static async Task<OperationStepResult> PurgeAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The purge stage runs for one Tenant.");

        // FOR UPDATE: every writer whose foreign-key check holds the Tenant's row commits first.
        if (await Tenants.LockForPurgeAsync(run.Context, tenantId, cancellationToken) != TenantStatus.Deleting)
        {
            return OperationStepResult.Failure(TenantNotDeleting);
        }

        await OperationStore.ExecuteAsync(run.Context, $"SAVEPOINT {Savepoint}", cancellationToken);
        try
        {
            foreach (var (_, purge) in StagePurges)
            {
                await purge.PurgeAsync(run.Context, cancellationToken);
            }
        }
        catch (DbException e) when (e.SqlState is SettingsRefused or ForeignKeyViolation or SerializationFailure)
        {
            await OperationStore.ExecuteAsync(run.Context, $"ROLLBACK TO SAVEPOINT {Savepoint}", cancellationToken);
            return OperationStepResult.Failure(e.SqlState == SettingsRefused ? PurgeRefused : PurgeConflict);
        }

        await OperationStore.ExecuteAsync(run.Context, $"RELEASE SAVEPOINT {Savepoint}", cancellationToken);
        return OperationStepResult.Success();
    }

    /// <summary>A key already gone counts as destroyed, so a rerun or retry finishes what is left.</summary>
    private static async Task<OperationStepResult> DestroySecretClassKeysAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The secret class keys stage runs for one Tenant.");

        if (await Tenants.LockStatusAsync(run.Context, tenantId, cancellationToken) != TenantStatus.Deleting)
        {
            return OperationStepResult.Failure(TenantNotDeleting);
        }

        if (run.Custody is not { } custody)
        {
            return OperationStepResult.Failure(TenantCreation.CustodyUnavailable);
        }

        try
        {
            await KeysContract.DestroySecretClassKeysAsync(custody, tenantId, cancellationToken);
        }
        catch (KeyCustodyException e)
        {
            return OperationStepResult.Failure(e.Failure == KeyCustodyFailure.Refused ? CustodyRefused : TenantCreation.CustodyUnavailable);
        }

        return OperationStepResult.Success();
    }

    /// <summary>
    /// In the last step job's transaction and the Tenant's own scope, and only when this call marks the
    /// Tenant deleted: it ends the Tenant's other pending jobs dead as <c>tenant_deleted</c>, deletes the
    /// payloads of its done and dead jobs (the running step job keeps its own, which the runner deletes
    /// once it is done), and schedules its chain's purge. A repeat finds the Tenant deleted and writes
    /// nothing at all.
    /// </summary>
    private static async Task CompleteAsync(OperationCompletion completion, CancellationToken cancellationToken)
    {
        if (!await Tenants.MarkDeletedAsync(completion.Context, completion.TenantId, cancellationToken))
        {
            return;
        }

        await using (var command = completion.Context.CreateCommand())
        {
            command.CommandText = KillPendingJobs;
            Sql.Add(command, "tenant_id", completion.TenantId);
            Sql.Add(command, "purge_type", ProductionJobs.PurgeChain.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = completion.Context.CreateCommand())
        {
            command.CommandText = PurgePayloads;
            Sql.Add(command, "tenant_id", completion.TenantId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await AuditRetentionJobs.SchedulePurgeAsync(completion.Context, completion.TenantId, cancellationToken);
    }
}
