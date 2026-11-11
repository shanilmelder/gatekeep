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

    /// <summary>The types an Admin creates, from Directory through Management, for the OpenAPI document.</summary>
    public static IReadOnlyList<string> Types => ManagementContract.ApplicationTypes;

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

    private static ApplicationResponse Response(ManagedApplication application) => new()
    {
        Id = application.ClientId,
        ClientId = application.ClientId,
        Name = application.Name,
        Type = application.Type,
        CredentialRequired = application.CredentialRequired,
        CreatedAt = application.CreatedAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
    };

    /// <summary>A refusal, logged under its fixed code only: never the name, the type or an ID.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("An Applications request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, status, problem);
    }
}
