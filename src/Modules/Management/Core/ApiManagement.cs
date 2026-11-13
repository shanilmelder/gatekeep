using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>
/// The APIs pages' reads and writes (Story 3.6), over Directory's contract: Host.Admin never reaches Directory itself.
/// Every call decides its capability again (AD-5) and refuses with <see cref="ApiStatus.Forbidden"/>.
/// </summary>
internal sealed class ApiManagement(IAuditAppender appender) : IApiManagement
{
    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(appender, TimeProvider.System);

    public async Task<ApiPageResult> ListAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, Guid? after, int limit, CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApiPageResult(ApiStatus.Forbidden, [], null);
        }

        var page = await _directory.ListApisPageAsync(tenantContext, after, limit, cancellationToken);
        return new ApiPageResult(ApiStatus.Done, [.. page.Apis.Select(Managed)], page.NextAfter);
    }

    public async Task<ApiResult> GetAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, Guid apiId, CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApiResult(ApiStatus.Forbidden);
        }

        if (await _directory.FindApiAsync(tenantContext, apiId, cancellationToken) is not { } api)
        {
            return new ApiResult(ApiStatus.NotFound);
        }

        var permissions = await _directory.ListPermissionsAsync(tenantContext, apiId, cancellationToken) ?? [];
        return new ApiResult(ApiStatus.Done, Managed(api), [.. permissions.Select(Managed)]);
    }

    public async Task<ApiResult> CreateAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string name,
        string identifier,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(identifier);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApisManage, principal, grant, tenantId))
        {
            return new ApiResult(ApiStatus.Forbidden);
        }

        // Every field named, before anything is written. The name is trimmed; the identifier is matched exactly, so it isn't.
        var trimmed = name.Trim();
        var problems = DirectoryContract.CheckApi(trimmed, identifier);
        if (problems.Count != 0)
        {
            return Invalid(problems);
        }

        var created = await _directory.CreateApiAsync(tenantContext, ActorOf(principal), trimmed, identifier, cancellationToken);
        return created.Status == ApiCreateStatus.Created
            ? new ApiResult(ApiStatus.Done, Managed(created.Api!), [])
            : new ApiResult(ApiStatus.IdentifierTaken);
    }

    public async Task<ApiResult> UpdateSettingsAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        ApiSettingsInput input,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApisManage, principal, grant, tenantId))
        {
            return new ApiResult(ApiStatus.Forbidden);
        }

        // The Application's lifetime rules (Story 3.4), every limit named, before anything is locked or written.
        var lifetimes = new ApplicationLifetimes(
            input.AccessTokenLifetime, input.IdTokenLifetime, input.RefreshTokenAbsoluteLifetime, input.RefreshTokenInactivityLifetime);
        var problems = DirectoryContract.CheckLifetimes(lifetimes);
        if (problems.Count != 0)
        {
            return new ApiResult(ApiStatus.Invalid, Errors: [.. problems.Select(p => new ApiFieldError(p.Field, p.Reason, p.Maximum))]);
        }

        var write = await _directory.UpdateApiSettingsAsync(
            tenantContext, ActorOf(principal), apiId, new ApiSettings(input.OfflineAccess, input.Rbac, lifetimes), cancellationToken);
        if (write is null)
        {
            return new ApiResult(ApiStatus.NotFound);
        }

        var permissions = await _directory.ListPermissionsAsync(tenantContext, apiId, cancellationToken) ?? [];
        return new ApiResult(write.Changed ? ApiStatus.Done : ApiStatus.Unchanged, Managed(write.Api), [.. permissions.Select(Managed)]);
    }

    public async Task<ApiResult> AddPermissionAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        string value,
        string? description,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(value);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApisManage, principal, grant, tenantId))
        {
            return new ApiResult(ApiStatus.Forbidden);
        }

        var text = description?.Trim() ?? string.Empty;
        var problems = DirectoryContract.CheckPermission(value, text);
        if (problems.Count != 0)
        {
            return Invalid(problems);
        }

        var write = await _directory.AddPermissionAsync(tenantContext, ActorOf(principal), apiId, value, text, cancellationToken);
        return await WrittenAsync(tenantContext, apiId, write, cancellationToken);
    }

    public async Task<ApiResult> RemovePermissionAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        string value,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(value);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApisManage, principal, grant, tenantId))
        {
            return new ApiResult(ApiStatus.Forbidden);
        }

        var write = await _directory.RemovePermissionAsync(tenantContext, ActorOf(principal), apiId, value, cancellationToken);
        return await WrittenAsync(tenantContext, apiId, write, cancellationToken);
    }

    private async Task<ApiResult> WrittenAsync(CommandContext tenantContext, Guid apiId, PermissionWrite write, CancellationToken cancellationToken)
    {
        switch (write.Status)
        {
            case PermissionWriteStatus.Done:
                var api = await _directory.FindApiAsync(tenantContext, apiId, cancellationToken)
                    ?? throw new InvalidOperationException("An API just written to is gone in the same transaction.");
                return new ApiResult(ApiStatus.Done, Managed(api), [.. (write.Permissions ?? []).Select(Managed)]);

            case PermissionWriteStatus.NotFound:
                return new ApiResult(ApiStatus.NotFound);

            case PermissionWriteStatus.BuiltIn:
                return new ApiResult(ApiStatus.BuiltIn);

            case PermissionWriteStatus.Taken:
                return new ApiResult(ApiStatus.PermissionTaken);

            case PermissionWriteStatus.LimitReached:
                return new ApiResult(ApiStatus.PermissionLimitReached);

            default:
                throw new System.Diagnostics.UnreachableException($"Unhandled Permission write status {write.Status}.");
        }
    }

    private static ApiResult Invalid(IReadOnlyList<ApiFieldProblem> problems) =>
        new(ApiStatus.Invalid, Errors: [.. problems.Select(p => new ApiFieldError(p.Field, p.Reason, p.Maximum))]);

    private static ManagedApi Managed(DirectoryApi api) =>
        new(
            api.Id,
            api.Name,
            api.Identifier,
            api.BuiltIn,
            api.OfflineAccess,
            api.Rbac,
            api.Lifetimes.AccessTokenLifetime,
            api.Lifetimes.IdTokenLifetime,
            api.Lifetimes.RefreshTokenAbsoluteLifetime,
            api.Lifetimes.RefreshTokenInactivityLifetime,
            api.CreatedAt);

    private static ManagedPermission Managed(DirectoryPermission permission) => new(permission.Value, permission.Description);

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
            throw new InvalidOperationException("A Tenant's APIs are read and written in its own context.");
        }
    }
}
