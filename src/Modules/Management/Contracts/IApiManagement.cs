using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>
/// One API as the Admin API shows it (Story 3.6): its ID, name, identifier (fixed at creation), whether it is the
/// built-in Management API, offline access, RBAC, its four token lifetimes in whole seconds and when it was created.
/// </summary>
public sealed record ManagedApi(
    Guid Id,
    string Name,
    string Identifier,
    bool BuiltIn,
    bool OfflineAccess,
    bool Rbac,
    int AccessTokenLifetime,
    int IdTokenLifetime,
    int RefreshTokenAbsoluteLifetime,
    int RefreshTokenInactivityLifetime,
    DateTimeOffset CreatedAt);

/// <summary>One of an API's Permissions as the Admin API shows it (Story 3.6): its <c>resource:action</c> value and description.</summary>
public sealed record ManagedPermission(string Value, string Description);

/// <summary>
/// One machine-to-machine Application's grant on an API as the Admin API shows it (Story 3.7): the Application's ID and
/// name, and the values of the API's Permissions it holds, in ordinal order.
/// </summary>
public sealed record ManagedApiGrant(Guid ApplicationId, string Name, IReadOnlyList<string> Permissions);

/// <summary>One refused field of an API or Permission write (Story 3.6): the field, the reason and, for a lifetime above its limit, that limit in seconds.</summary>
public sealed record ApiFieldError(string Field, string Reason, int? Maximum, int? Index = null);

/// <summary>How an API call ended (Story 3.6).</summary>
public enum ApiStatus
{
    /// <summary>Done: the result holds the API, the page or the Permissions; a write's event is written.</summary>
    Done,

    /// <summary>A save that changes nothing: nothing written and no event.</summary>
    Unchanged,

    /// <summary>The capability isn't held in the path Tenant, decided again here (AD-5). Nothing was written.</summary>
    Forbidden,

    /// <summary>The path Tenant has no API by that ID, or for a removal the API has no Permission by that value. Nothing was written.</summary>
    NotFound,

    /// <summary>Some field breaks a rule: the result names each. Nothing was written.</summary>
    Invalid,

    /// <summary>Another of the Tenant's APIs has that identifier, exactly. Nothing was written.</summary>
    IdentifierTaken,

    /// <summary>The API already has a Permission by that value. Nothing was written.</summary>
    PermissionTaken,

    /// <summary>The API already holds the most Permissions. Nothing was written.</summary>
    PermissionLimitReached,

    /// <summary>
    /// The API is the built-in Management API, whose identifier and Permissions are fixed, and which only Epic 17's Owner
    /// flow grants. Nothing was written.
    /// </summary>
    BuiltIn,

    /// <summary>A grant names an Application that isn't a machine-to-machine one (Story 3.7). Nothing was written.</summary>
    ApplicationNotMachine,
}

/// <summary>
/// An API call's result: the API, its Permissions and from Story 3.7 its grants when done or unchanged, the errors when
/// invalid.
/// </summary>
public sealed record ApiResult(
    ApiStatus Status,
    ManagedApi? Api = null,
    IReadOnlyList<ManagedPermission>? Permissions = null,
    IReadOnlyList<ApiFieldError>? Errors = null,
    IReadOnlyList<ManagedApiGrant>? Grants = null);

/// <summary>A page of APIs when <see cref="Status"/> is <see cref="ApiStatus.Done"/>: the built-in first, then newest, and the next page's cursor.</summary>
public sealed record ApiPageResult(ApiStatus Status, IReadOnlyList<ManagedApi> Apis, Guid? NextAfter);

/// <summary>An API's settings as a save sends them (Story 3.6): a full replace, the lifetimes in whole seconds.</summary>
public sealed record ApiSettingsInput(
    bool OfflineAccess,
    bool Rbac,
    int AccessTokenLifetime,
    int IdTokenLifetime,
    int RefreshTokenAbsoluteLifetime,
    int RefreshTokenInactivityLifetime);

/// <summary>
/// A Tenant's APIs and their Permissions (Story 3.6, FR-16): listed and read with <c>tenant.configuration.read</c>,
/// written with <c>tenant.apis.manage</c>, which Editors, Owners and machine principals may hold, with no fresh
/// assertion. Each call runs in the path Tenant's own context and decides the capability again (AD-5) from the grant
/// the request checks read. Directory owns the rows.
/// </summary>
public interface IApiManagement
{
    /// <summary>One page of the path Tenant's APIs, at most <paramref name="limit"/>: the built-in Management API first, then newest, after <paramref name="after"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<ApiPageResult> ListAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, Guid? after, int limit, CancellationToken cancellationToken);

    /// <summary>The path Tenant's API <paramref name="apiId"/> with its Permissions, or <see cref="ApiStatus.NotFound"/>.</summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    Task<ApiResult> GetAsync(
        CommandContext tenantContext, Principal principal, TenantRoleGrant? grant, Guid tenantId, Guid apiId, CancellationToken cancellationToken);

    /// <summary>
    /// Creates an API named <paramref name="name"/>, trimmed, 1 to 200 characters (duplicates allowed), with
    /// <paramref name="identifier"/> exactly as given: 1 to 255 characters, an absolute URI with no fragment, not under
    /// <c>urn:gatekeep:</c>, and unique in the Tenant. Then <c>directory.api.created</c> by the caller, an Admin or a machine
    /// client, in the caller's transaction.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApiResult> CreateAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string name,
        string identifier,
        CancellationToken cancellationToken);

    /// <summary>
    /// Saves the API <paramref name="apiId"/>'s offline access, RBAC and four token lifetimes, each lifetime within the
    /// Application's limits (Story 3.4), every problem named. A save equal to what is stored writes nothing; otherwise the
    /// row and <c>directory.api.updated</c> by the caller, in the caller's transaction. The built-in Management API's settings
    /// may be saved too.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApiResult> UpdateSettingsAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        ApiSettingsInput input,
        CancellationToken cancellationToken);

    /// <summary>
    /// Adds the Permission <paramref name="value"/>, <c>resource:action</c>, with <paramref name="description"/> of 0 to
    /// 200 characters, to the API <paramref name="apiId"/>, and writes <c>directory.api.permission_added</c> by the caller.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApiResult> AddPermissionAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        string value,
        string? description,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes the Permission <paramref name="value"/> from the API <paramref name="apiId"/>, with every grant of it (Story
    /// 3.7), and writes <c>directory.api.permission_removed</c> by the caller.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApiResult> RemovePermissionAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        string value,
        CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the Permissions of the API <paramref name="apiId"/> granted to the machine-to-machine Application
    /// <paramref name="applicationId"/> with <paramref name="permissions"/> (Story 3.7, FR-16): 1 to 200 distinct values,
    /// each one of the API's Permissions, every problem named by its index. A set equal to what is stored writes nothing;
    /// otherwise the rows and <c>directory.api.grant_updated</c> by the caller, in the caller's transaction. Another kind of
    /// Application is <see cref="ApiStatus.ApplicationNotMachine"/>; the built-in Management API is <see cref="ApiStatus.BuiltIn"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApiResult> SetGrantAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        Guid applicationId,
        IReadOnlyList<string?> permissions,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes the Application <paramref name="applicationId"/>'s grant on the API <paramref name="apiId"/> (Story 3.7), and
    /// writes <c>directory.api.grant_removed</c> by the caller. When it holds none, nothing is written and the result is
    /// <see cref="ApiStatus.Unchanged"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    Task<ApiResult> RemoveGrantAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid apiId,
        Guid applicationId,
        CancellationToken cancellationToken);
}
