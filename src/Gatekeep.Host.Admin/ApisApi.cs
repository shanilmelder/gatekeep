using System.Data.Common;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>Create API's body (Story 3.6): a name and an identifier, and nothing else.</summary>
public sealed class CreateApiRequest
{
    /// <summary>Trimmed, then 1 to 200 characters with no control character. Two APIs may share a name.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// The audience its tokens will name: 1 to 255 characters, an absolute URI with a scheme and no fragment, such as
    /// <c>https://api.example.com</c>, matched exactly and unique in the Tenant. Never <c>urn:gatekeep:</c>, and never changed.
    /// </summary>
    public required string Identifier { get; init; }
}

/// <summary>
/// An API's settings (Story 3.6): offline access, RBAC and its four token lifetimes, in whole seconds, all required. The
/// save replaces what is stored; each lifetime has the Application's limits.
/// </summary>
[System.Text.Json.Serialization.JsonNumberHandling(System.Text.Json.Serialization.JsonNumberHandling.Strict)]
public sealed class ApiSettingsRequest
{
    /// <summary>Whether refresh tokens are issued for this API (Story 3.7 enforces it).</summary>
    public required bool OfflineAccess { get; init; }

    /// <summary>Whether role-based access control applies to this API's Permissions (Epic 5 enforces it).</summary>
    public required bool Rbac { get; init; }

    /// <summary>Access tokens: at most 3600 (1 hour).</summary>
    public required int AccessTokenLifetime { get; init; }

    /// <summary>ID tokens: at most 3600 (1 hour).</summary>
    public required int IdTokenLifetime { get; init; }

    /// <summary>A refresh token family's absolute lifetime: at most 7776000 (90 days).</summary>
    public required int RefreshTokenAbsoluteLifetime { get; init; }

    /// <summary>A refresh token's inactivity lifetime: at most 2592000 (30 days).</summary>
    public required int RefreshTokenInactivityLifetime { get; init; }
}

/// <summary>Add Permission's body (Story 3.6): its value and an optional description.</summary>
public sealed class AddApiPermissionRequest
{
    /// <summary><c>resource:action</c>, lowercase, such as <c>invoices:read</c>: unique in the API.</summary>
    public required string Value { get; init; }

    /// <summary>Trimmed, then 0 to 200 characters with no control character. Absent is empty.</summary>
    public string? Description { get; init; }
}

/// <summary>
/// Set grant's body (Story 3.7): the values of the API's Permissions to grant the machine-to-machine Application, which
/// replace whatever it holds.
/// </summary>
public sealed class SetApiGrantRequest
{
    /// <summary>1 to 200 distinct values, each one of this API's Permissions, such as <c>invoices:read</c>.</summary>
    public required IReadOnlyList<string?> Permissions { get; init; }
}

/// <summary>One machine-to-machine Application's grant on an API (Story 3.7).</summary>
public sealed class ApiGrantResponse
{
    /// <summary>The Application's public ID, <c>app_</c> and 26 base32 characters: its <c>client_id</c>.</summary>
    public required string ApplicationId { get; init; }

    /// <summary>The Application's name.</summary>
    public required string Name { get; init; }

    /// <summary>The values of this API's Permissions it holds, in ordinal order: never empty.</summary>
    public required IReadOnlyList<string> Permissions { get; init; }
}

/// <summary>One API (Story 3.6).</summary>
public sealed class ApiResourceResponse
{
    /// <summary>Its public ID, <c>api_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary>The audience its tokens will name, as created: it never changes.</summary>
    public required string Identifier { get; init; }

    /// <summary>Whether it is the Tenant's built-in Gatekeep Management API, whose identifier and Permissions are fixed.</summary>
    public required bool BuiltIn { get; init; }

    /// <summary>Whether refresh tokens are issued for it: false by default.</summary>
    public required bool OfflineAccess { get; init; }

    /// <summary>Whether role-based access control applies to it: false by default.</summary>
    public required bool Rbac { get; init; }

    /// <summary>How long its access tokens live, in seconds: 900 by default, 1 to 3600. A token lives the shorter of this and its Application's.</summary>
    public required int AccessTokenLifetime { get; init; }

    /// <summary>How long ID tokens live, in seconds: 900 by default, 1 to 3600.</summary>
    public required int IdTokenLifetime { get; init; }

    /// <summary>How long a refresh token family lives from its authorization, in seconds: 2592000 (30 days) by default, 1 to 7776000.</summary>
    public required int RefreshTokenAbsoluteLifetime { get; init; }

    /// <summary>How long one refresh token lives unused, in seconds: 604800 (7 days) by default, 1 to 2592000.</summary>
    public required int RefreshTokenInactivityLifetime { get; init; }

    /// <summary>When it was created, ISO 8601 in UTC.</summary>
    public required string CreatedAt { get; init; }
}

/// <summary>One API's Permission (Story 3.6).</summary>
public sealed class ApiPermissionResponse
{
    /// <summary><c>resource:action</c>.</summary>
    public required string Value { get; init; }

    /// <summary>0 to 200 characters; empty when none was given.</summary>
    public required string Description { get; init; }
}

/// <summary>One API with its Permissions, by value (Story 3.6), and from Story 3.7 its grants.</summary>
public sealed class ApiResourceDetailResponse
{
    public required ApiResourceResponse Api { get; init; }

    public required IReadOnlyList<ApiPermissionResponse> Permissions { get; init; }

    /// <summary>
    /// Each machine-to-machine Application authorized on this API, ordered by name, with the Permissions it holds
    /// (Story 3.7). Always empty for the built-in Management API, which only a Tenant Owner grants (Epic 17).
    /// </summary>
    public required IReadOnlyList<ApiGrantResponse> Grants { get; init; }
}

/// <summary>A page of the Tenant's APIs: the built-in Management API first, then the others newest first.</summary>
public sealed class ApiResourceListResponse
{
    public required IReadOnlyList<ApiResourceResponse> Apis { get; init; }

    /// <summary>The last API's ID when another page follows, else null: pass it back as <c>cursor</c>.</summary>
    public required string? NextCursor { get; init; }
}

/// <summary>
/// A Tenant's APIs and their Permissions (Story 3.6, FR-16): listed and read with any Tenant Role, written by Editors,
/// Owners and machine principals holding <c>tenant.apis.manage</c>, all in the path Tenant's own scope. The request
/// checks have decided the capability, and Management decides it again from the same grant.
/// </summary>
internal static class ApisApi
{
    /// <summary>The route value naming an API: its <c>api_</c> public ID.</summary>
    public const string ApiRouteValue = "apiId";

    /// <summary>The route value naming one of an API's Permissions: its value.</summary>
    public const string PermissionRouteValue = "value";

    /// <summary>The route value naming the Application a grant is for: its <c>app_</c> public ID (Story 3.7).</summary>
    public const string ApplicationRouteValue = "applicationId";

    /// <summary>
    /// The largest grant body (Story 3.7): room for 200 Permissions of the longest value. Anything bigger is 400
    /// <c>api_invalid</c>, unread past it.
    /// </summary>
    public const int MaxGrantBody = 32768;

    /// <summary>The list's query parameter: the previous page's <c>nextCursor</c>.</summary>
    public const string CursorQuery = "cursor";

    /// <summary>APIs per page (Conventions).</summary>
    public const int PageSize = 50;

    /// <summary>The largest body any API route reads: anything bigger is 400 <c>api_invalid</c>, unread past it.</summary>
    public const int MaxBody = 4096;

    public static async Task ListAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        Guid? after = null;
        if (context.Request.Query.TryGetValue(CursorQuery, out var cursors))
        {
            // One canonical api_ ID, or nothing: anything else names no page.
            if (cursors.Count != 1 || !PublicId.TryParse(PublicIdType.Api, cursors[0], out var cursor))
            {
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.InvalidRequest);
                return;
            }

            after = cursor;
        }

        ApiPageResult read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.Apis.ListAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, after, PageSize, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (read.Status != ApiStatus.Done)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
            return;
        }

        await AdminResponses.JsonAsync(context, new ApiResourceListResponse
        {
            Apis = [.. read.Apis.Select(Response)],
            NextCursor = read.NextAfter is { } next ? PublicId.Format(PublicIdType.Api, next) : null,
        });
    }

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        if (!TryApiId(context, out var apiId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        await RunAsync(context, services, write: false, (c, principal, path, ct) =>
            services.Apis.GetAsync(c, principal, path.Grant, path.TenantId, apiId, ct));
    }

    public static async Task CreateAsync(HttpContext context, AdminApiServices services)
    {
        // Under a deadline and a size cap, as application/json only: anything else is malformed.
        var body = await AdminApi.ReadJsonAsync<CreateApiRequest>(context.Request, MaxBody, context.RequestAborted);
        if (body?.Name is null || body.Identifier is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApiInvalid);
            return;
        }

        await RunAsync(
            context,
            services,
            write: true,
            (c, principal, path, ct) => services.Apis.CreateAsync(c, principal, path.Grant, path.TenantId, body.Name, body.Identifier, ct),
            created: (path, result) => $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, path.TenantId)}/apis/{PublicId.Format(PublicIdType.Api, result.Api!.Id)}");
    }

    public static async Task UpdateSettingsAsync(HttpContext context, AdminApiServices services)
    {
        if (!TryApiId(context, out var apiId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        // Every field given, the lifetimes as JSON whole numbers: anything else, a null included, is malformed.
        var body = await AdminApi.ReadJsonAsync<ApiSettingsRequest>(context.Request, MaxBody, context.RequestAborted);
        if (body is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApiInvalid);
            return;
        }

        var input = new ApiSettingsInput(
            body.OfflineAccess,
            body.Rbac,
            body.AccessTokenLifetime,
            body.IdTokenLifetime,
            body.RefreshTokenAbsoluteLifetime,
            body.RefreshTokenInactivityLifetime);

        await RunAsync(context, services, write: true, (c, principal, path, ct) =>
            services.Apis.UpdateSettingsAsync(c, principal, path.Grant, path.TenantId, apiId, input, ct));
    }

    public static async Task AddPermissionAsync(HttpContext context, AdminApiServices services)
    {
        if (!TryApiId(context, out var apiId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        var body = await AdminApi.ReadJsonAsync<AddApiPermissionRequest>(context.Request, MaxBody, context.RequestAborted);
        if (body?.Value is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApiInvalid);
            return;
        }

        await RunAsync(
            context,
            services,
            write: true,
            (c, principal, path, ct) => services.Apis.AddPermissionAsync(c, principal, path.Grant, path.TenantId, apiId, body.Value, body.Description, ct),
            created: (path, result) => $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, path.TenantId)}/apis/{PublicId.Format(PublicIdType.Api, result.Api!.Id)}");
    }

    public static async Task RemovePermissionAsync(HttpContext context, AdminApiServices services)
    {
        // A malformed API ID or value names nothing: the same 404 as an unknown one, after the capability.
        if (!TryApiId(context, out var apiId) || context.GetRouteValue(PermissionRouteValue) is not string value)
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        await RunAsync(
            context,
            services,
            write: true,
            (c, principal, path, ct) => services.Apis.RemovePermissionAsync(c, principal, path.Grant, path.TenantId, apiId, value, ct),
            noContent: true);
    }

    public static async Task SetGrantAsync(HttpContext context, AdminApiServices services)
    {
        if (!TryApiId(context, out var apiId) || !TryApplicationId(context, out var applicationId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        var body = await AdminApi.ReadJsonAsync<SetApiGrantRequest>(context.Request, MaxGrantBody, context.RequestAborted);
        if (body?.Permissions is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApiInvalid);
            return;
        }

        await RunAsync(context, services, write: true, (c, principal, path, ct) =>
            services.Apis.SetGrantAsync(c, principal, path.Grant, path.TenantId, apiId, applicationId, body.Permissions, ct));
    }

    public static async Task RemoveGrantAsync(HttpContext context, AdminApiServices services)
    {
        if (!TryApiId(context, out var apiId) || !TryApplicationId(context, out var applicationId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        // A grant that doesn't exist is removed all the same: 204, with nothing written.
        await RunAsync(
            context,
            services,
            write: true,
            (c, principal, path, ct) => services.Apis.RemoveGrantAsync(c, principal, path.Grant, path.TenantId, apiId, applicationId, ct),
            noContent: true);
    }

    /// <summary>
    /// One call in the path Tenant's own scope, and its answer: a write commits only when it wrote, past which a client gone
    /// mustn't undo it; 201 with <paramref name="created"/>'s Location for a create, 204 for <paramref name="noContent"/>.
    /// </summary>
    private static async Task RunAsync(
        HttpContext context,
        AdminApiServices services,
        bool write,
        Func<CommandContext, Gatekeep.Modules.Admins.Contracts.Principal, PathTenantFeature, CancellationToken, Task<ApiResult>> call,
        Func<PathTenantFeature, ApiResult, string>? created = null,
        bool noContent = false)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        ApiResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await call(scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path, cancellationToken);

            if (!write)
            {
                await scope.CommitAsync(cancellationToken);
            }
            else if (result.Status == ApiStatus.Done)
            {
                // The rows and their event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case ApiStatus.Done or ApiStatus.Unchanged when noContent:
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                context.Response.Headers.CacheControl = "no-store";
                return;

            case ApiStatus.Done when created is not null:
                context.Response.StatusCode = StatusCodes.Status201Created;
                context.Response.Headers.Location = created(path, result);
                await AdminResponses.JsonAsync(context, Detail(result), cancellationToken: CancellationToken.None);
                return;

            case ApiStatus.Done:
            case ApiStatus.Unchanged:
                await AdminResponses.JsonAsync(context, Detail(result), cancellationToken: CancellationToken.None);
                return;

            case ApiStatus.Invalid:
                LogRefusal(context, AdminResponses.ApiInvalid);
                await AdminResponses.ProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AdminResponses.ApiInvalid,
                    [.. (result.Errors ?? []).Select(e => new ApiProblemError { Field = e.Field, Index = e.Index, Reason = e.Reason, Maximum = e.Maximum })]);
                return;

            case ApiStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            case ApiStatus.IdentifierTaken:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.ApiIdentifierTaken);
                return;

            case ApiStatus.PermissionTaken:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.PermissionTaken);
                return;

            case ApiStatus.PermissionLimitReached:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.PermissionLimitReached);
                return;

            case ApiStatus.BuiltIn:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.ApiBuiltIn);
                return;

            case ApiStatus.ApplicationNotMachine:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.ApplicationNotMachine);
                return;

            case ApiStatus.Forbidden:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;

            default:
                throw new System.Diagnostics.UnreachableException($"Unhandled API status {result.Status}.");
        }
    }

    /// <summary>The route's API ID: a malformed one names no API, the same 404 as an unknown one, after the capability.</summary>
    private static bool TryApiId(HttpContext context, out Guid apiId) =>
        PublicId.TryParse(PublicIdType.Api, context.GetRouteValue(ApiRouteValue) as string, out apiId);

    /// <summary>The route's Application ID (Story 3.7): a malformed one names no Application, the same 404 as an unknown one.</summary>
    private static bool TryApplicationId(HttpContext context, out Guid applicationId) =>
        PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationRouteValue) as string, out applicationId);

    private static ApiResourceDetailResponse Detail(ApiResult result) => new()
    {
        Api = Response(result.Api!),
        Permissions = [.. (result.Permissions ?? []).Select(p => new ApiPermissionResponse { Value = p.Value, Description = p.Description })],
        Grants = [.. (result.Grants ?? []).Select(g => new ApiGrantResponse
        {
            ApplicationId = PublicId.Format(PublicIdType.Application, g.ApplicationId),
            Name = g.Name,
            Permissions = g.Permissions,
        })],
    };

    private static ApiResourceResponse Response(ManagedApi api) => new()
    {
        Id = PublicId.Format(PublicIdType.Api, api.Id),
        Name = api.Name,
        Identifier = api.Identifier,
        BuiltIn = api.BuiltIn,
        OfflineAccess = api.OfflineAccess,
        Rbac = api.Rbac,
        AccessTokenLifetime = api.AccessTokenLifetime,
        IdTokenLifetime = api.IdTokenLifetime,
        RefreshTokenAbsoluteLifetime = api.RefreshTokenAbsoluteLifetime,
        RefreshTokenInactivityLifetime = api.RefreshTokenInactivityLifetime,
        CreatedAt = ApplicationsApi.Timestamp(api.CreatedAt),
    };

    /// <summary>A refusal, logged under its fixed code only: never a name, identifier, value or ID.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        LogRefusal(context, problem);
        return AdminResponses.ProblemAsync(context, status, problem);
    }

    private static void LogRefusal(HttpContext context, string problem) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("An APIs request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
}
