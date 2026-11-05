using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
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
/// separate jobs, so the two stages may run in either order.
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

    public static readonly OperationDefinition Definition = new(
        Type,
        [
            new OperationStage(SecretClassKeysStage, OperationStageKind.Tenant, CreateSecretClassKeysAsync),
            new OperationStage(SigningKeysStage, OperationStageKind.Tenant, EnsureSigningKeysAsync),
        ],
        ActivateAsync);

    /// <summary>The stages a new Tenant's creation plans, one step each, in this order.</summary>
    public static readonly IReadOnlyList<OperationCode> Stages = [SecretClassKeysStage, SigningKeysStage];

    /// <summary>Creating a key that exists returns it unchanged, so a rerun or retry is harmless.</summary>
    private static async Task<OperationStepResult> CreateSecretClassKeysAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The secret class keys stage runs for one Tenant.");

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
    /// current and one next key per purpose. A custody failure takes back this step's rows.
    /// </summary>
    private static async Task<OperationStepResult> EnsureSigningKeysAsync(OperationStepRun run, CancellationToken cancellationToken)
    {
        var tenantId = run.TenantId
            ?? throw new InvalidOperationException("The signing keys stage runs for one Tenant.");

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

    private static Task ActivateAsync(OperationCompletion completion, CancellationToken cancellationToken) =>
        Tenants.ActivateAsync(completion.Context, completion.TenantId, cancellationToken);
}
