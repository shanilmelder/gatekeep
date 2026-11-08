using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// <c>tenancy.tenant.create</c> (Story 1.27, AD-30): the Worker-only half of creating a Tenant.
/// Host.Admin's start command has already written the Tenant as <c>creating</c>, its host, its
/// creator's Owner role and this Operation, scoped to the new Tenant. Its one Tenant stage creates
/// the six secret class keys, which only Host.Worker's custody policy may (AD-10). Its completion
/// handler, once every stage has succeeded, inserts the Tenant's settings and makes it active, in
/// the Tenant's own scope. Later stories add their own stages, and all of them run before activation.
/// Story 2.3 adds the second: the Tenant's Signing and Management keys and its wrapped token
/// protection key, through the same Keys contract method the hourly backfill calls. Steps fan out as
/// separate jobs, so the two stages may run in either order. Story 2.8: the completion handler, only
/// when it activates the Tenant, also writes the Tenant's hidden <c>system</c> Application (AD-12),
/// in the same transaction, so every active Tenant has one; a Tenant whose deletion started gets none.
/// </summary>
internal static class TenantCreation
{
    public static readonly OperationType Type = new("tenancy.tenant.create");

    public static readonly OperationCode SecretClassKeysStage = new("keys.secret_classes");

    /// <summary>The Signing and Management keys and the wrapped token protection key (Story 2.3).</summary>
    public static readonly OperationCode SigningKeysStage = new("keys.signing");

    /// <summary>Key custody was missing or failed. Nothing from the failure is kept.</summary>
    public static readonly OperationCode CustodyUnavailable = new("custody_unavailable");

    private static readonly IAuditAppender Appender = AuditContract.CreateAppender();

    private static readonly ITenants Tenants = TenancyContract.CreateTenants(Appender);

    private static readonly IDirectory Applications = DirectoryContract.CreateDirectory(Appender, TimeProvider.System);

    public static readonly OperationDefinition Definition = new(
        Type,
        [
            new OperationStage(SecretClassKeysStage, OperationStageKind.Tenant, CreateSecretClassKeysAsync),
            new OperationStage(SigningKeysStage, OperationStageKind.Tenant, EnsureSigningKeysAsync),
        ],
        ActivateAsync);

    /// <summary>The stages a new Tenant's creation plans, one step each, in this order.</summary>
    public static readonly IReadOnlyList<OperationCode> Stages = [SecretClassKeysStage, SigningKeysStage];

    /// <summary>A stage for a Tenant that stopped being created, by a deletion's start: no key is created (Story 1.29).</summary>
    public static readonly OperationCode TenantNotCreating = new("tenant_not_creating");

    /// <summary>
    /// Creating a key that exists returns it unchanged, so a rerun or retry is harmless. The Tenant's
    /// status is re-checked first under <c>FOR SHARE</c> (Story 1.29): a deletion's start, which
    /// conflicts with it, either ran before and is seen, or waits, so no key is created after a
    /// deletion's destroy stage looked.
    /// </summary>
    private static async Task<OperationStepResult> CreateSecretClassKeysAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The secret class keys stage runs for one Tenant.");

        if (await Tenants.LockStatusAsync(run.Context, tenantId, cancellationToken) != TenantStatus.Creating)
        {
            return OperationStepResult.Failure(TenantNotCreating);
        }

        if (run.Custody is not { } custody)
        {
            return OperationStepResult.Failure(CustodyUnavailable);
        }

        try
        {
            await KeysContract.CreateSecretClassKeysAsync(custody, tenantId, cancellationToken);
        }
        catch (KeyCustodyException)
        {
            return OperationStepResult.Failure(CustodyUnavailable);
        }

        return OperationStepResult.Success();
    }

    /// <summary>
    /// Creates only what the Tenant lacks, so a rerun after a crash or a retry converges on one
    /// current and one next key per purpose. A custody failure takes back this step's rows. Like the
    /// secret class stage, it re-checks the Tenant's status under <c>FOR SHARE</c> first (Story 1.29),
    /// so no Signing Key is created once a deletion has started.
    /// </summary>
    private static async Task<OperationStepResult> EnsureSigningKeysAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The signing keys stage runs for one Tenant.");

        if (await Tenants.LockStatusAsync(run.Context, tenantId, cancellationToken) != TenantStatus.Creating)
        {
            return OperationStepResult.Failure(TenantNotCreating);
        }

        if (run.Custody is not { } custody)
        {
            return OperationStepResult.Failure(CustodyUnavailable);
        }

        try
        {
            await KeysContract.EnsureTenantKeysAsync(run.Context, custody, Appender, tenantId, cancellationToken);
        }
        catch (KeyCustodyException)
        {
            return OperationStepResult.Failure(CustodyUnavailable);
        }

        return OperationStepResult.Success();
    }

    /// <summary>
    /// Does nothing to a Tenant that isn't creating, so a deleted one never gets settings back (Story 1.29).
    /// Only the call that activates it writes its <c>system</c> Application (Story 2.8), in the Tenant's own
    /// scope and transaction, so activation and that row commit together or not at all.
    /// </summary>
    private static async Task ActivateAsync(OperationCompletion completion, CancellationToken cancellationToken)
    {
        if (await Tenants.ActivateAsync(completion.Context, completion.TenantId, cancellationToken))
        {
            await Applications.EnsureSystemApplicationAsync(completion.Context, cancellationToken);
        }
    }
}
