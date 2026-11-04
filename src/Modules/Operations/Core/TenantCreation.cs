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
/// </summary>
internal static class TenantCreation
{
    public static readonly OperationType Type = new("tenancy.tenant.create");

    public static readonly OperationCode SecretClassKeysStage = new("keys.secret_classes");

    /// <summary>Key custody was missing or failed. Nothing from the failure is kept.</summary>
    public static readonly OperationCode CustodyUnavailable = new("custody_unavailable");

    private static readonly ITenants Tenants = TenancyContract.CreateTenants(AuditContract.CreateAppender());

    public static readonly OperationDefinition Definition = new(
        Type,
        [new OperationStage(SecretClassKeysStage, OperationStageKind.Tenant, CreateSecretClassKeysAsync)],
        ActivateAsync);

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

    private static Task ActivateAsync(OperationCompletion completion, CancellationToken cancellationToken) =>
        Tenants.ActivateAsync(completion.Context, completion.TenantId, cancellationToken);
}
