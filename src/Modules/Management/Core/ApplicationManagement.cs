using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>
/// The Applications pages' reads and create (Story 3.1), over Directory's contract: Host.Admin never
/// reaches Directory itself. Every call decides its capability again (AD-5) and refuses with
/// <see cref="ApplicationStatus.Forbidden"/>, as <see cref="SigningKeyManagement"/> does.
/// </summary>
internal sealed class ApplicationManagement(IAuditAppender appender) : IApplicationManagement
{
    private const int MaxPurgeStartAttempts = 3;

    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(appender, TimeProvider.System);
    private readonly ITenants _tenants = TenancyContract.CreateTenants(appender);
    private readonly IOperations _operations = OperationsContract.CreateOperations(OperationsContract.ProductionOperationRegistry);

    public async Task<ApplicationPageResult> ListAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid? after,
        int limit,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApplicationPageResult(ApplicationStatus.Forbidden, [], null);
        }

        var page = await _directory.ListApplicationsPageAsync(tenantContext, after, limit, cancellationToken);
        return new ApplicationPageResult(ApplicationStatus.Done, [.. page.Applications.Select(Managed)], page.NextAfter);
    }

    public async Task<ApplicationResult> GetAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApplicationResult(ApplicationStatus.Forbidden);
        }

        return await _directory.FindApplicationAsync(tenantContext, applicationId, cancellationToken) is { } application
            ? new ApplicationResult(ApplicationStatus.Done, Managed(application))
            : new ApplicationResult(ApplicationStatus.NotFound);
    }

    public async Task<ApplicationResult> CreateAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string? name,
        string? type,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApplicationsManage, principal, grant, tenantId))
        {
            return new ApplicationResult(ApplicationStatus.Forbidden);
        }

        var trimmed = name?.Trim();
        if (string.IsNullOrEmpty(trimmed)
            || trimmed.Length > DirectoryContract.MaxNameLength
            || trimmed.Any(char.IsControl)
            || type is null
            || !DirectoryContract.CreatableKinds.Contains(type, StringComparer.Ordinal))
        {
            return new ApplicationResult(ApplicationStatus.Invalid);
        }

        var created = await _directory.CreateApplicationAsync(tenantContext, ActorOf(principal), trimmed, type, cancellationToken);
        return new ApplicationResult(ApplicationStatus.Done, Managed(created));
    }

    public async Task<ApplicationSettingsResult> UpdateSettingsAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        ApplicationSettingsInput input,
        Func<CancellationToken, Task<bool>> requireFreshAssertion,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(requireFreshAssertion);

        // 1. Authorization runs in the module too (AD-5), from the grant the checks read. The capability is
        // machine-denied, so a machine principal never gets past here.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApplicationCallbacksManage, principal, grant, tenantId)
            || principal is not AdminPrincipal admin)
        {
            return new ApplicationSettingsResult(ApplicationSettingsStatus.Forbidden);
        }

        // 2. The label under the Tenant's row lock, then the Application under its own, both held to the end of
        // the caller's transaction: WhenProdTenant is decided on the label and the callbacks this save replaces.
        var label = await _tenants.LockLabelAsync(tenantContext, tenantId, cancellationToken);
        if (label is null)
        {
            return new ApplicationSettingsResult(ApplicationSettingsStatus.Forbidden);
        }

        if (label.Status is TenantStatus.Deleting or TenantStatus.Deleted
            || await _directory.LockApplicationAsync(tenantContext, applicationId, cancellationToken) is not { } current)
        {
            return new ApplicationSettingsResult(ApplicationSettingsStatus.NotFound);
        }

        // 3. The type table, every line named; nothing is locked further or used up.
        var settings = new ApplicationSettings(input.CallbackUrls, input.LogoutUrls, input.WebOrigins, input.GrantTypes);
        var problems = DirectoryContract.CheckSettings(current.Kind, settings);
        if (problems.Count != 0)
        {
            return new ApplicationSettingsResult(
                ApplicationSettingsStatus.Invalid,
                Errors: [.. problems.Select(p => new ApplicationSettingsError(p.Field, p.Index, p.Reason))]);
        }

        var prod = label.Label == TenantLabel.Prod;

        // 4. A Prod Tenant's new custom-scheme URL needs the Admin's acknowledgement, which isn't stored.
        if (prod && !input.AcknowledgeCustomScheme
            && (AddsCustomScheme(input.CallbackUrls, current.RedirectUris) || AddsCustomScheme(input.LogoutUrls, current.PostLogoutRedirectUris)))
        {
            return new ApplicationSettingsResult(ApplicationSettingsStatus.AcknowledgementRequired);
        }

        // 5. Nothing to change: no write, no event, and no grant used.
        var grants = input.GrantTypes.Order(StringComparer.Ordinal).ToList();
        if (input.CallbackUrls.SequenceEqual(current.RedirectUris, StringComparer.Ordinal)
            && input.LogoutUrls.SequenceEqual(current.PostLogoutRedirectUris, StringComparer.Ordinal)
            && input.WebOrigins.SequenceEqual(current.WebOrigins, StringComparer.Ordinal)
            && grants.SequenceEqual(current.GrantTypes, StringComparer.Ordinal))
        {
            return new ApplicationSettingsResult(ApplicationSettingsStatus.Unchanged, Managed(current));
        }

        // 6. WhenProdTenant (FR-46, AD-20): a Prod Tenant's changed callback set needs a fresh assertion. The gate
        // uses up the grant in its own committed transaction, so a failure after this still uses it.
        var callbacksChange = !input.CallbackUrls.ToHashSet(StringComparer.Ordinal).SetEquals(current.RedirectUris);
        var needsAssertion = prod && callbacksChange;
        if (needsAssertion && !await requireFreshAssertion(cancellationToken))
        {
            return new ApplicationSettingsResult(ApplicationSettingsStatus.FreshAssertionRequired);
        }

        // 7. The row and its events. Once a grant is used up nothing may stop the write a client going away.
        var added = prod && input.CallbackUrls.Any(url => !current.RedirectUris.Contains(url, StringComparer.Ordinal));
        var updated = await _directory.UpdateApplicationSettingsAsync(
            tenantContext,
            Actor.Admin(admin.AdminId),
            applicationId,
            settings,
            added,
            needsAssertion ? CancellationToken.None : cancellationToken);

        return updated is null
            ? new ApplicationSettingsResult(ApplicationSettingsStatus.NotFound)
            : new ApplicationSettingsResult(ApplicationSettingsStatus.Saved, Managed(updated));
    }

    public async Task<ApplicationLifetimesResult> UpdateLifetimesAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        ApplicationLifetimesInput input,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);

        // Authorization runs in the module too (AD-5), from the grant the checks read. Machine principals may hold it.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApplicationsManage, principal, grant, tenantId))
        {
            return new ApplicationLifetimesResult(ApplicationLifetimesStatus.Forbidden);
        }

        // Every limit named, before anything is locked or written.
        var lifetimes = new ApplicationLifetimes(
            input.AccessTokenLifetime, input.IdTokenLifetime, input.RefreshTokenAbsoluteLifetime, input.RefreshTokenInactivityLifetime);
        var problems = DirectoryContract.CheckLifetimes(lifetimes);
        if (problems.Count != 0)
        {
            return new ApplicationLifetimesResult(
                ApplicationLifetimesStatus.Invalid,
                Errors: [.. problems.Select(p => new ApplicationLifetimesError(p.Field, p.Reason, p.Maximum))]);
        }

        return await _directory.UpdateApplicationLifetimesAsync(tenantContext, ActorOf(principal), applicationId, lifetimes, cancellationToken) switch
        {
            null => new ApplicationLifetimesResult(ApplicationLifetimesStatus.NotFound),
            { Changed: true } write => new ApplicationLifetimesResult(ApplicationLifetimesStatus.Saved, Managed(write.Application)),
            { } write => new ApplicationLifetimesResult(ApplicationLifetimesStatus.Unchanged, Managed(write.Application)),
        };
    }

    public async Task<ApplicationSecretsResult> ListSecretsAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApplicationSecretsResult { Status = ApplicationSecretStatus.Forbidden };
        }

        return await _directory.ListClientSecretsAsync(tenantContext, applicationId, cancellationToken) is { } secrets
            ? new ApplicationSecretsResult { Status = ApplicationSecretStatus.Done, Secrets = [.. secrets.Select(Managed)] }
            : new ApplicationSecretsResult { Status = ApplicationSecretStatus.NotFound };
    }

    public async Task<ApplicationSecretsResult> CreateSecretAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        // Authorization runs in the module too (AD-5). The capability is Owner-only and machine-denied.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantClientSecretsManage, principal, grant, tenantId)
            || principal is not AdminPrincipal admin)
        {
            return new ApplicationSecretsResult { Status = ApplicationSecretStatus.Forbidden };
        }

        // The checks have used up the fresh assertion already: nothing may stop the write a client going away.
        return Secrets(await _directory.CreateClientSecretAsync(tenantContext, Actor.Admin(admin.AdminId), applicationId, CancellationToken.None));
    }

    public async Task<ApplicationSecretsResult> RevokeSecretAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        Guid secretId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantClientSecretsManage, principal, grant, tenantId)
            || principal is not AdminPrincipal admin)
        {
            return new ApplicationSecretsResult { Status = ApplicationSecretStatus.Forbidden };
        }

        return Secrets(await _directory.RevokeClientSecretAsync(tenantContext, Actor.Admin(admin.AdminId), applicationId, secretId, CancellationToken.None));
    }

    public async Task<ApplicationDeleteResult> DeleteAsync(
        CommandContext tenantContext,
        CommandContext deploymentContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(deploymentContext);
        if (deploymentContext.TenantId is not null)
        {
            throw new InvalidOperationException("An Application's purge starts in a Deployment context.");
        }

        ArgumentNullException.ThrowIfNull(principal);

        // 1. Authorization runs in the module too (AD-5), from the grant the checks read. Machine principals may hold it.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApplicationsManage, principal, grant, tenantId))
        {
            return new ApplicationDeleteResult(ApplicationDeleteStatus.Forbidden);
        }

        // 2. The deletion, its revocation and its events, in the Tenant's own context, to be committed together.
        if (!await _directory.DeleteApplicationAsync(tenantContext, ActorOf(principal), applicationId, cancellationToken))
        {
            return new ApplicationDeleteResult(ApplicationDeleteStatus.NotFound);
        }

        // 3. The purge, in the Deployment context, which the caller commits only after the Tenant one: one Operation
        // per Tenant serves every deletion.
        return await StartPurgeAsync(deploymentContext, tenantId, cancellationToken) is { } operation
            ? new ApplicationDeleteResult(ApplicationDeleteStatus.Started, TenantManagement.Managed(operation))
            : new ApplicationDeleteResult(ApplicationDeleteStatus.PurgeNotStarted);
    }

    /// <summary>
    /// Starts the Tenant's <c>directory.application.purge</c>, or finds the one already running or failed for it, whose
    /// stages purge this deletion too. A start that loses the race to another is tried again a few times, as the other
    /// may finish before it is read; null when every try lost.
    /// </summary>
    private async Task<OperationResource?> StartPurgeAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaxPurgeStartAttempts; attempt++)
        {
            try
            {
                return await _operations.StartAsync(
                    context,
                    OperationsContract.ApplicationPurgeOperation,
                    tenantId,
                    [.. OperationsContract.ApplicationPurgeStages.Select(stage => new OperationStepPlan(stage, tenantId))],
                    cancellationToken);
            }
            catch (OperationAlreadyActiveException)
            {
                // The caller's transaction stays usable: read the active one, which may have finished meanwhile.
                if (await _operations.FindActiveAsync(context, OperationsContract.ApplicationPurgeOperation, tenantId, cancellationToken) is { } active)
                {
                    return active;
                }
            }
        }

        return null;
    }

    private static ApplicationSecretsResult Secrets(ClientSecretWrite write) => new()
    {
        Status = write.Status switch
        {
            ClientSecretWriteStatus.Done => ApplicationSecretStatus.Done,
            ClientSecretWriteStatus.NotApplicable => ApplicationSecretStatus.NotApplicable,
            ClientSecretWriteStatus.LimitReached => ApplicationSecretStatus.LimitReached,
            _ => ApplicationSecretStatus.NotFound,
        },
        Secret = write.Secret,
        Secrets = [.. write.Secrets.Select(Managed)],
    };

    private static ManagedClientSecret Managed(DirectoryClientSecret secret) => new(secret.Id, secret.CreatedAt, secret.ExpiresAt);

    /// <summary>Whether <paramref name="submitted"/> holds a custom-scheme URL that <paramref name="stored"/> doesn't.</summary>
    private static bool AddsCustomScheme(IReadOnlyList<string> submitted, IReadOnlyList<string> stored) =>
        submitted.Any(url => DirectoryContract.IsCustomScheme(url) && !stored.Contains(url, StringComparer.Ordinal));

    private static ManagedApplication Managed(DirectoryApplication application) =>
        new(
            application.Id,
            application.ClientId,
            application.Name,
            application.Kind,
            application.CredentialRequired,
            application.CreatedAt,
            application.RedirectUris,
            application.PostLogoutRedirectUris,
            application.WebOrigins,
            application.GrantTypes,
            application.Lifetimes.AccessTokenLifetime,
            application.Lifetimes.IdTokenLifetime,
            application.Lifetimes.RefreshTokenAbsoluteLifetime,
            application.Lifetimes.RefreshTokenInactivityLifetime);

    /// <summary>Who a write is by: the Admin, or the machine client a Management API token names.</summary>
    private static Actor ActorOf(Principal principal) => principal switch
    {
        AdminPrincipal admin => Actor.Admin(admin.AdminId),
        MachinePrincipal machine => Actor.Client(machine.ClientId),
        _ => throw new ArgumentOutOfRangeException(nameof(principal)),
    };

    private static void RequireOwnContext(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's Applications are read and created in its own context.");
        }
    }
}
