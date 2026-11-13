using System.Data.Common;
using System.Globalization;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>Create Application's body (Story 3.1): a name and a type, and nothing else. URLs and grants come later.</summary>
public sealed class CreateApplicationRequest
{
    /// <summary>Trimmed, then 1 to 200 characters with no control character. Two Applications may share a name.</summary>
    public required string Name { get; init; }

    /// <summary><c>spa</c> (single-page), <c>web</c> (regular web), <c>native</c> or <c>machine</c> (machine-to-machine).</summary>
    public required string Type { get; init; }
}

/// <summary>One Application (Story 3.1). It never carries a secret.</summary>
public sealed class ApplicationResponse
{
    /// <summary>Its public ID, <c>app_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    /// <summary>Its OAuth <c>client_id</c>: the same <c>app_</c> public ID.</summary>
    public required string ClientId { get; init; }

    public required string Name { get; init; }

    /// <summary><c>spa</c>, <c>web</c>, <c>native</c> or <c>machine</c>.</summary>
    public required string Type { get; init; }

    /// <summary>Whether the type authenticates with a client secret: true for <c>web</c> and <c>machine</c> only.</summary>
    public required bool CredentialRequired { get; init; }

    /// <summary>When it was created, ISO 8601 in UTC.</summary>
    public required string CreatedAt { get; init; }

    /// <summary>Its Allowed Callback URLs, the OAuth redirect URIs, as stored and matched exactly. Always empty for <c>machine</c>.</summary>
    public required IReadOnlyList<string> CallbackUrls { get; init; }

    /// <summary>Its Allowed Logout URLs, as stored. Always empty for <c>machine</c>.</summary>
    public required IReadOnlyList<string> LogoutUrls { get; init; }

    /// <summary>Its Allowed Web Origins, each <c>scheme://host[:port]</c>. Always empty for <c>native</c> and <c>machine</c>.</summary>
    public required IReadOnlyList<string> WebOrigins { get; init; }

    /// <summary>Its grant types, sorted: <c>authorization_code</c>, <c>client_credentials</c> or <c>refresh_token</c>.</summary>
    public required IReadOnlyList<string> GrantTypes { get; init; }

    /// <summary>How long its access tokens live, in seconds (Story 3.4): 900 by default, 1 to 3600.</summary>
    public required int AccessTokenLifetime { get; init; }

    /// <summary>How long its ID tokens live, in seconds (Story 3.4): 900 by default, 1 to 3600.</summary>
    public required int IdTokenLifetime { get; init; }

    /// <summary>
    /// How long a family of its refresh tokens lives from its authorization, however often it rotates, in seconds
    /// (Story 3.4): 2592000 (30 days) by default, 1 to 7776000 (90 days).
    /// </summary>
    public required int RefreshTokenAbsoluteLifetime { get; init; }

    /// <summary>How long one of its refresh tokens lives unused, in seconds (Story 3.4): 604800 (7 days) by default, 1 to 2592000 (30 days).</summary>
    public required int RefreshTokenInactivityLifetime { get; init; }
}

/// <summary>
/// An Application's four token lifetimes (Story 3.4), each in whole seconds: all required, and the save replaces
/// what is stored. Each is at least 1 and at most its hard limit.
/// </summary>
[System.Text.Json.Serialization.JsonNumberHandling(System.Text.Json.Serialization.JsonNumberHandling.Strict)]
public sealed class ApplicationTokensRequest
{
    /// <summary>Access tokens: at most 3600 (1 hour).</summary>
    public required int AccessTokenLifetime { get; init; }

    /// <summary>ID tokens: at most 3600 (1 hour).</summary>
    public required int IdTokenLifetime { get; init; }

    /// <summary>A refresh token family's absolute lifetime: at most 7776000 (90 days).</summary>
    public required int RefreshTokenAbsoluteLifetime { get; init; }

    /// <summary>A refresh token's inactivity lifetime: at most 2592000 (30 days).</summary>
    public required int RefreshTokenInactivityLifetime { get; init; }
}

/// <summary>
/// An Application's full settings (Story 3.2): every list is required and replaces what is stored. Each URL
/// is one line of its field, kept exactly as sent; grant order doesn't matter.
/// </summary>
public sealed class ApplicationSettingsRequest
{
    /// <summary>Allowed Callback URLs: at most 10, each absolute, with no wildcard. None for <c>machine</c>.</summary>
    public required IReadOnlyList<string> CallbackUrls { get; init; }

    /// <summary>Allowed Logout URLs: the same rules as callbacks.</summary>
    public required IReadOnlyList<string> LogoutUrls { get; init; }

    /// <summary>Allowed Web Origins: at most 10, each <c>scheme://host[:port]</c>. None for <c>native</c> or <c>machine</c>.</summary>
    public required IReadOnlyList<string> WebOrigins { get; init; }

    /// <summary>
    /// The grant types: <c>[]</c> or <c>[client_credentials]</c> for <c>machine</c>; <c>[]</c>,
    /// <c>[authorization_code]</c> or <c>[authorization_code, refresh_token]</c> otherwise.
    /// </summary>
    public required IReadOnlyList<string> GrantTypes { get; init; }

    /// <summary>In a Prod Tenant, true acknowledges a new custom-scheme callback or logout URL. It isn't stored.</summary>
    public bool? AcknowledgeCustomScheme { get; init; }
}

/// <summary>A page of the Tenant's Applications, newest first.</summary>
public sealed class ApplicationListResponse
{
    public required IReadOnlyList<ApplicationResponse> Applications { get; init; }

    /// <summary>The last Application's ID when an older page follows, else null: pass it back as <c>cursor</c>.</summary>
    public required string? NextCursor { get; init; }
}

/// <summary>
/// A Tenant's Applications (Story 3.1, FR-11, FR-44): listed and read with any Tenant Role, created by
/// Editors and Owners, all in the path Tenant's own scope. The request checks have decided the
/// capability, and Management decides it again from the same grant. The hidden <c>system</c>
/// Application is never listed or read.
/// </summary>
internal static class ApplicationsApi
{
    /// <summary>The route value naming an Application: its <c>app_</c> public ID.</summary>
    public const string ApplicationRouteValue = "applicationId";

    /// <summary>The list's query parameter: the previous page's <c>nextCursor</c>.</summary>
    public const string CursorQuery = "cursor";

    /// <summary>Applications per page (Conventions).</summary>
    public const int PageSize = 50;

    /// <summary>The largest create body read: anything bigger is 400 <c>application_invalid</c>, unread past it.</summary>
    public const int MaxCreateBody = 4096;

    /// <summary>The largest settings body read (Story 3.2): anything bigger is 400 <c>application_invalid</c>, unread past it.</summary>
    public const int MaxSettingsBody = 131072;

    /// <summary>The largest tokens body read (Story 3.4): anything bigger is 400 <c>application_invalid</c>, unread past it.</summary>
    public const int MaxTokensBody = 4096;

    /// <summary>The types an Admin creates, from Directory through Management, for the OpenAPI document.</summary>
    public static IReadOnlyList<string> Types => ManagementContract.ApplicationTypes;

    /// <summary>The grant types an Application can hold, sorted, for the OpenAPI document.</summary>
    public static IReadOnlyList<string> GrantTypes => ManagementContract.ApplicationGrantTypes;

    public static async Task ListAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        Guid? after = null;
        if (context.Request.Query.TryGetValue(CursorQuery, out var cursors))
        {
            // One canonical app_ ID, or nothing: anything else names no page.
            if (cursors.Count != 1 || !PublicId.TryParse(PublicIdType.Application, cursors[0], out var cursor))
            {
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.InvalidRequest);
                return;
            }

            after = cursor;
        }

        ApplicationPageResult read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.Applications.ListAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, after, PageSize, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (read.Status != ApplicationStatus.Done)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
            return;
        }

        await AdminResponses.JsonAsync(context, new ApplicationListResponse
        {
            Applications = [.. read.Applications.Select(Response)],
            NextCursor = read.NextAfter is { } next ? PublicId.Format(PublicIdType.Application, next) : null,
        });
    }

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no Application: the same 404 as an unknown one, after the capability.
        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationRouteValue) as string, out var applicationId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        ApplicationResult read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.Applications.GetAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, applicationId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (read.Status)
        {
            case ApplicationStatus.Done:
                await AdminResponses.JsonAsync(context, Response(read.Application!));
                return;

            case ApplicationStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    public static async Task CreateAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        // Under a deadline and a size cap, as application/json only: anything else is malformed.
        var body = await AdminApi.ReadJsonAsync<CreateApplicationRequest>(context.Request, MaxCreateBody, cancellationToken);
        if (body?.Name is null || body.Type is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApplicationInvalid);
            return;
        }

        ApplicationResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.Applications.CreateAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, body.Name, body.Type, cancellationToken);

            if (result.Status == ApplicationStatus.Done)
            {
                // The row and its event are written: a client gone now mustn't undo them.
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
            case ApplicationStatus.Done:
                var application = Response(result.Application!);
                context.Response.StatusCode = StatusCodes.Status201Created;
                context.Response.Headers.Location =
                    $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, path.TenantId)}/applications/{application.Id}";
                await AdminResponses.JsonAsync(context, application, cancellationToken: CancellationToken.None);
                return;

            case ApplicationStatus.Invalid:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApplicationInvalid);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    public static async Task UpdateSettingsAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no Application: the same 404 as an unknown one, after the capability.
        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationRouteValue) as string, out var applicationId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        // Under a deadline and a size cap, as application/json only, every list given and no line null:
        // anything else is malformed, and refused before anything is locked or any grant is used.
        var body = await AdminApi.ReadJsonAsync<ApplicationSettingsRequest>(context.Request, MaxSettingsBody, cancellationToken);
        if (body is null
            || body.CallbackUrls is null || body.LogoutUrls is null || body.WebOrigins is null || body.GrantTypes is null
            || body.CallbackUrls.Contains(null!) || body.LogoutUrls.Contains(null!) || body.WebOrigins.Contains(null!) || body.GrantTypes.Contains(null!))
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApplicationInvalid);
            return;
        }

        var input = new ApplicationSettingsInput(body.CallbackUrls, body.LogoutUrls, body.WebOrigins, body.GrantTypes, body.AcknowledgeCustomScheme == true);

        ApplicationSettingsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.Applications.UpdateSettingsAsync(
                scope.CreateCommandContext(),
                principal,
                path.Grant,
                path.TenantId,
                applicationId,
                input,
                gate => FreshAssertionGate.RequireAsync(context, services, gate),
                cancellationToken);

            if (result.Status == ApplicationSettingsStatus.Saved)
            {
                // The row and its events are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (e.SqlState == AdminResponses.SystemApplicationEdited && !context.Response.HasStarted)
        {
            // The guard the visibility filter should have met first: the system Application is no Application here.
            AdminRequestChecks.Log(context, e);
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case ApplicationSettingsStatus.Saved:
            case ApplicationSettingsStatus.Unchanged:
                await AdminResponses.JsonAsync(context, Response(result.Application!), cancellationToken: CancellationToken.None);
                return;

            case ApplicationSettingsStatus.FreshAssertionRequired:
                // The gate has already answered 403 fresh_assertion_required.
                return;

            case ApplicationSettingsStatus.Invalid:
                LogRefusal(context, AdminResponses.ApplicationInvalid);
                await AdminResponses.ProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AdminResponses.ApplicationInvalid,
                    [.. (result.Errors ?? []).Select(e => new ApiProblemError { Field = e.Field, Index = e.Index, Reason = e.Reason })]);
                return;

            case ApplicationSettingsStatus.AcknowledgementRequired:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.CustomSchemeAcknowledgementRequired);
                return;

            case ApplicationSettingsStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    public static async Task UpdateTokensAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no Application: the same 404 as an unknown one, after the capability.
        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationRouteValue) as string, out var applicationId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        // Under a deadline and a size cap, as application/json only, every lifetime given as a whole number:
        // anything else, a null included, is malformed, and refused before anything is locked.
        var body = await AdminApi.ReadJsonAsync<ApplicationTokensRequest>(context.Request, MaxTokensBody, cancellationToken);
        if (body is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ApplicationInvalid);
            return;
        }

        ApplicationLifetimesResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.Applications.UpdateLifetimesAsync(
                scope.CreateCommandContext(),
                AdminRequestChecks.Principal(context),
                path.Grant,
                path.TenantId,
                applicationId,
                new ApplicationLifetimesInput(
                    body.AccessTokenLifetime, body.IdTokenLifetime, body.RefreshTokenAbsoluteLifetime, body.RefreshTokenInactivityLifetime),
                cancellationToken);

            if (result.Status == ApplicationLifetimesStatus.Saved)
            {
                // The row and its event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (e.SqlState == AdminResponses.SystemApplicationEdited && !context.Response.HasStarted)
        {
            // The guard the visibility filter should have met first: the system Application is no Application here.
            AdminRequestChecks.Log(context, e);
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case ApplicationLifetimesStatus.Saved:
            case ApplicationLifetimesStatus.Unchanged:
                await AdminResponses.JsonAsync(context, Response(result.Application!), cancellationToken: CancellationToken.None);
                return;

            case ApplicationLifetimesStatus.Invalid:
                LogRefusal(context, AdminResponses.ApplicationInvalid);
                await AdminResponses.ProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AdminResponses.ApplicationInvalid,
                    [.. (result.Errors ?? []).Select(e => new ApiProblemError { Field = e.Field, Index = null, Reason = e.Reason, Maximum = e.Maximum })]);
                return;

            case ApplicationLifetimesStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    private static ApplicationResponse Response(ManagedApplication application) => new()
    {
        Id = application.ClientId,
        ClientId = application.ClientId,
        Name = application.Name,
        Type = application.Type,
        CredentialRequired = application.CredentialRequired,
        CreatedAt = Timestamp(application.CreatedAt),
        CallbackUrls = application.CallbackUrls,
        LogoutUrls = application.LogoutUrls,
        WebOrigins = application.WebOrigins,
        GrantTypes = application.GrantTypes,
        AccessTokenLifetime = application.AccessTokenLifetime,
        IdTokenLifetime = application.IdTokenLifetime,
        RefreshTokenAbsoluteLifetime = application.RefreshTokenAbsoluteLifetime,
        RefreshTokenInactivityLifetime = application.RefreshTokenInactivityLifetime,
    };

    /// <summary>An instant as the Applications responses write one: ISO 8601 in UTC, to the millisecond.</summary>
    internal static string Timestamp(DateTimeOffset instant) =>
        instant.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    /// <summary>A refusal, logged under its fixed code only: never the name, the type, a URL, a secret or an ID.</summary>
    internal static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        LogRefusal(context, problem);
        return AdminResponses.ProblemAsync(context, status, problem);
    }

    private static void LogRefusal(HttpContext context, string problem) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("An Applications request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
}
