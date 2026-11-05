using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>
/// Tenant creation's start command (Story 1.27, FR-7): one Deployment transaction writes the
/// Tenant, its host, its creator's Owner role and its creation Operation, or nothing. The
/// Operation then does what only Host.Worker may (AD-10, AD-30). From Story 1.28 also the Tenant
/// switcher's list of an Admin's Tenants and the Tenant Owner's label change.
/// </summary>
internal sealed class TenantManagement(IAuditAppender appender, TenantAddressing addressing) : ITenantManagement
{
    private static readonly OperationType CreationType = OperationsContract.TenantCreationOperation;

    private readonly IAuditAppender _appender = appender;
    private readonly TenantAddressing _addressing = addressing;
    private readonly ITenants _tenants = TenancyContract.CreateTenants(appender);
    private readonly IAdminTenantRoles _roles = AdminsContract.CreateTenantRoles();
    private readonly IAdminAuthorization _authorization = AdminsContract.CreateAuthorization(appender);
    private readonly IOperations _operations = OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry);

    public string TenantZone => _addressing.Zone;

    public async Task<TenantCreationResult> CreateAsync(
        CommandContext context,
        AdminPrincipal principal,
        CreateTenantInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);

        // Authorization runs in the handler too (AD-5), whatever the request checks decided.
        if (!AdminCapabilities.Allows(AdminCapabilities.DeploymentTenantsCreate, principal, null, null))
        {
            return new TenantCreationResult(TenantCreationStatus.Forbidden);
        }

        if (!TenantName.TryNormalize(input.Name, out var name) || !TenantValues.TryParseLabel(input.Label, out var label))
        {
            return new TenantCreationResult(TenantCreationStatus.TenantInvalid);
        }

        if (!TenantSubdomain.TryParse(input.Subdomain, _addressing.Zone, out var subdomain))
        {
            return new TenantCreationResult(TenantCreationStatus.SubdomainRefused);
        }

        // Derived once, here, and stored: nothing recomputes it later (AD-6).
        var address = TenantAddress.For(subdomain, _addressing.Zone, _addressing.HttpsPort);
        var tenantId = Guid.CreateVersion7();

        var inserted = await _tenants.InsertAsync(context, new TenantDraft(tenantId, name, label, address), cancellationToken);
        if (inserted.Status == TenantInsertStatus.SubdomainTaken)
        {
            return new TenantCreationResult(TenantCreationStatus.SubdomainRefused);
        }

        await _roles.GrantCreatorOwnerAsync(context, principal.AdminId, tenantId, cancellationToken);

        var operation = await _operations.StartAsync(
            context,
            CreationType,
            tenantId,
            [new OperationStepPlan(OperationsContract.TenantCreationStage, tenantId)],
            cancellationToken);

        await _appender.AppendAsync(
            context,
            new AuditEvent(TenancyEvents.TenantCreated.Code, Actor.Admin(principal.AdminId), AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);

        var managed = Managed(operation);
        var tenant = new ManagedTenant(
            tenantId,
            name,
            address.Host,
            TenantValues.Stored(label),
            TenantValues.Stored(TenantStatus.Creating),
            inserted.CreatedAt!.Value,
            new ManagedTenantCreation(operation.Id, managed.Status));

        return new TenantCreationResult(TenantCreationStatus.Created, tenant, managed);
    }

    public async Task<TenantPage?> ListAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid? after,
        int limit,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);

        if (!AdminCapabilities.Allows(AdminCapabilities.DeploymentTenantsRead, principal, null, null))
        {
            return null;
        }

        // One more than a page says whether another follows.
        var rows = await _tenants.ListAsync(context, after, limit + 1, cancellationToken);
        var page = rows.Take(limit).ToList();

        // The page's creation Operations, in one query.
        var creating = page.Where(t => t.Status == TenantStatus.Creating).Select(t => t.Id).ToList();
        var active = await _operations.FindActiveForTenantsAsync(context, CreationType, creating, cancellationToken);

        var tenants = new List<ManagedTenant>(page.Count);
        foreach (var row in page)
        {
            ManagedTenantCreation? creation = row.Status == TenantStatus.Creating && active.TryGetValue(row.Id, out var found)
                ? new ManagedTenantCreation(found.OperationId, Status(found.Status))
                : null;

            tenants.Add(new ManagedTenant(
                row.Id,
                row.Name,
                row.Host,
                TenantValues.Stored(row.Label),
                TenantValues.Stored(row.Status),
                row.CreatedAt,
                creation));
        }

        return new TenantPage(tenants, rows.Count > limit ? page[^1].Id : null);
    }

    public async Task<TenantOperationRead> GetOperationAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid tenantId,
        Guid operationId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);

        // Authorization runs in the module too (AD-5): the principal's role in the path Tenant.
        var decision = await _authorization.AuthorizeAsync(context, principal, AdminCapabilities.TenantConfigurationRead, tenantId, cancellationToken);
        if (!decision.Allowed)
        {
            return new TenantOperationRead(Allowed: false, Operation: null);
        }

        // Only the path Tenant's steps, and nothing at all of another Tenant's Operation.
        var operation = await _operations.GetForTenantAsync(context, operationId, tenantId, cancellationToken);
        return new TenantOperationRead(Allowed: true, operation is null ? null : Managed(operation));
    }

    public async Task<OperationRetryResult> RetryCreationAsync(
        CommandContext context,
        AdminPrincipal principal,
        Guid operationId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.DeploymentTenantsCreate, principal, null, null))
        {
            return new OperationRetryResult(OperationRetryStatus.Forbidden);
        }

        var existing = await _operations.GetAsync(context, operationId, cancellationToken);
        if (existing is null || existing.Type != CreationType)
        {
            return new OperationRetryResult(OperationRetryStatus.NotFound);
        }

        if (existing.Status != OperationStatus.Failed)
        {
            return new OperationRetryResult(OperationRetryStatus.NotFailed);
        }

        OperationResource retried;
        try
        {
            retried = await _operations.RetryAsync(context, operationId, cancellationToken);
        }
        catch (OperationNotFailedException)
        {
            // Retried by another request since the read: it is no longer failed.
            return new OperationRetryResult(OperationRetryStatus.NotFailed);
        }

        await _appender.AppendAsync(
            context,
            new AuditEvent(
                OperationsEvents.OperationRetried.Code,
                Actor.Admin(principal.AdminId),
                retried.TenantId is null ? null : AuditTargetKind.Tenant,
                retried.TenantId),
            detail: null,
            cancellationToken);

        return new OperationRetryResult(OperationRetryStatus.Retried, Managed(retried));
    }

    public async Task<IReadOnlyList<AdminTenant>> ListForAdminAsync(CommandContext context, AdminPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);

        // The Admin's own role rows' Tenants, then those Tenants' records: never the role itself.
        var ids = await _roles.ListTenantIdsAsync(context, principal.AdminId, cancellationToken);
        var tenants = await _tenants.ListActiveAsync(context, ids, cancellationToken);
        return [.. tenants.Select(t => new AdminTenant(t.Id, t.Name, t.Host, TenantValues.Stored(t.Label)))];
    }

    public async Task<TenantLabelRead> GetLabelAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(principal);

        // Authorization runs in the module too (AD-5), from the grant the checks read: no second read.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new TenantLabelRead(Allowed: false, Label: null);
        }

        // A plain read: it never waits behind a label change, and sees the label before or after it.
        var state = await _tenants.GetLabelAsync(tenantContext, tenantId, cancellationToken);
        return state is null
            ? new TenantLabelRead(Allowed: false, Label: null)
            : new TenantLabelRead(Allowed: true, TenantValues.Stored(state.Label), TenantValues.Stored(state.Status));
    }

    public async Task<LabelChangeResult> ChangeLabelAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string? requested,
        Func<CancellationToken, Task<bool>> requireFreshAssertion,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(requireFreshAssertion);

        // 1. Authorization runs in the module too (AD-5), from the grant the checks read.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantLabelManage, principal, grant, tenantId))
        {
            return new LabelChangeResult(LabelChangeStatus.Forbidden);
        }

        // 2. One of the three stored spellings, or nothing is locked.
        if (!TenantValues.TryParseLabel(requested, out var label))
        {
            return new LabelChangeResult(LabelChangeStatus.Invalid);
        }

        // 3. The row lock, held to the end of the caller's transaction: the predicate below is
        // decided on the label this write replaces, never on one read earlier.
        var state = await _tenants.LockLabelAsync(tenantContext, tenantId, cancellationToken);
        if (state is null)
        {
            // The checks allowed a role there, so this is a Tenant gone since: refused alike.
            return new LabelChangeResult(LabelChangeStatus.Forbidden);
        }

        if (state.Status != TenantStatus.Active)
        {
            return new LabelChangeResult(LabelChangeStatus.NotActive);
        }

        // 4. Nothing to change: no write, no event, and no grant used.
        if (state.Label == label)
        {
            return new LabelChangeResult(LabelChangeStatus.Unchanged, TenantValues.Stored(label));
        }

        // 5. WhenProdTenant (FR-46): only removing Prod needs a fresh assertion. The gate uses up
        // the grant in its own committed transaction, so a failure after this still uses it.
        var removesProd = TenantLabelChange.RemovesProd(state.Label, label);
        if (removesProd && !await requireFreshAssertion(cancellationToken))
        {
            return new LabelChangeResult(LabelChangeStatus.FreshAssertionRequired);
        }

        // 6. The label, and nothing else, and its event on the Tenant's own chain. Once a grant is
        // used up nothing may stop the write a client going away: so never the request's token.
        try
        {
            await _tenants.SetLabelAsync(
                tenantContext, tenantId, label, Actor.Admin(principal.AdminId), removesProd, removesProd ? CancellationToken.None : cancellationToken);
        }
        catch (InvalidOperationException)
        {
            // The locked row stopped being an active Tenant: a refusal, never a 500.
            return new LabelChangeResult(LabelChangeStatus.NotActive);
        }

        return new LabelChangeResult(LabelChangeStatus.Changed, TenantValues.Stored(label));
    }

    private static ManagedOperation Managed(OperationResource operation) => new(
        operation.Id,
        operation.Type.Value,
        operation.TenantId,
        Status(operation.Status),
        operation.CreatedAt,
        operation.UpdatedAt,
        operation.FinishedAt,
        operation.Steps.Select(Step).ToList());

    private static ManagedOperationStep Step(OperationStepResource step) => new(
        step.Stage.Value,
        step.TenantId,
        Status(step.Status),
        step.ResultCode?.Value,
        step.Attempts,
        step.UpdatedAt);

    private static ManagedOperationStepStatus Status(OperationStepStatus status) => status switch
    {
        OperationStepStatus.Pending => ManagedOperationStepStatus.Pending,
        OperationStepStatus.Running => ManagedOperationStepStatus.Running,
        OperationStepStatus.Succeeded => ManagedOperationStepStatus.Succeeded,
        _ => ManagedOperationStepStatus.Failed,
    };

    private static ManagedOperationStatus Status(OperationStatus status) => status switch
    {
        OperationStatus.Running => ManagedOperationStatus.Running,
        OperationStatus.Failed => ManagedOperationStatus.Failed,
        _ => ManagedOperationStatus.Succeeded,
    };
}
