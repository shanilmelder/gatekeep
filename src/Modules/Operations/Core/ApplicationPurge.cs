using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// <c>directory.application.purge</c> (Story 3.5, AD-1, AD-30): removes the rows of a Tenant's deleted Applications,
/// which their deletion has already hidden and revoked, from each owning module. Host.Admin starts it once a
/// deletion commits, scoped to the Tenant, with its one Tenant stage. That stage, in one transaction under one
/// savepoint, reads the IDs of the Tenant's Applications whose <c>deleted_at</c> is set once, then calls each owning
/// module's purge with that same list, in owning-module order, as Tenant deletion's purge stage does: Sessions' tokens
/// then Token Families, Authentication's sign-in transactions, then Directory's client secrets and the Applications
/// themselves, children before parents. So it purges every deleted Application of the Tenant the read found, not only
/// the one whose deletion started it. An Application marked deleted after that read is untouched in every module and
/// left, hidden and revoked, for the next purge Operation. The stage is idempotent: a rerun deletes nothing more. A row
/// that still references what it deletes (<c>23503</c>, or <c>23001</c> for <c>ON DELETE RESTRICT</c>), such as a
/// token written while it ran, or a serialization failure (<c>40001</c>), keeps nothing of the purge and fails the step
/// <c>purge_conflict</c>, for a Retry, which runs it again whole. It has no completion.
/// </summary>
internal static class ApplicationPurge
{
    public static readonly OperationType Type = new("directory.application.purge");

    public static readonly OperationCode PurgeStage = new("directory.application.purge");

    /// <summary>The one stage: every module's purge, in order, in one transaction.</summary>
    public static readonly IReadOnlyList<OperationCode> Stages = [PurgeStage];

    /// <summary>
    /// The modules the stage purges, in this order: Sessions and Authentication before Directory, because
    /// <c>token</c>, <c>authorization</c> and <c>signin_transaction</c> reference <c>application</c> with
    /// <c>ON DELETE RESTRICT</c> (Story 2.5), as <see cref="TenantDeletion.StagePurges"/> orders them.
    /// </summary>
    public static readonly IReadOnlyList<string> PurgeModules = ["Sessions", "Authentication", "Directory"];

    private const string ForeignKeyViolation = "23503";

    // ON DELETE RESTRICT, which every reference to an Application has, raises this rather than 23503.
    private const string RestrictViolation = "23001";

    private const string SerializationFailure = "40001";

    private const string Savepoint = "application_purge";

    public static readonly OperationDefinition Definition = new(
        Type,
        [new OperationStage(PurgeStage, OperationStageKind.Tenant, PurgeAsync)]);

    /// <summary>Every module's purge of one list of deleted Applications, in order, under a savepoint: a conflict leaves nothing half purged.</summary>
    private static async Task<OperationStepResult> PurgeAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        _ = run.TenantId ?? throw new InvalidOperationException("The Application purge stage runs for one Tenant.");
        var context = run.Context;

        await OperationStore.ExecuteAsync(context, $"SAVEPOINT {Savepoint}", cancellationToken);
        try
        {
            // Read once: every module purges exactly these, so none deletes an Application another hasn't purged.
            var deleted = await DirectoryContract.DeletedApplicationIdsAsync(context, cancellationToken);
            if (deleted.Count > 0)
            {
                await SessionsContract.PurgeApplicationsAsync(context, deleted, cancellationToken);
                await AuthenticationContract.PurgeApplicationsAsync(context, deleted, cancellationToken);
                await DirectoryContract.PurgeDeletedApplicationsAsync(context, deleted, cancellationToken);
            }
        }
        catch (DbException e) when (e.SqlState is ForeignKeyViolation or RestrictViolation or SerializationFailure)
        {
            await OperationStore.ExecuteAsync(context, $"ROLLBACK TO SAVEPOINT {Savepoint}", cancellationToken);
            return OperationStepResult.Failure(TenantDeletion.PurgeConflict);
        }

        await OperationStore.ExecuteAsync(context, $"RELEASE SAVEPOINT {Savepoint}", cancellationToken);
        return OperationStepResult.Success();
    }
}
