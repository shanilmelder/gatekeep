using System.Data.Common;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>One live client secret (Story 3.3): never its value, hash or any part of either.</summary>
public sealed class ApplicationSecretResponse
{
    /// <summary>Its public ID, <c>sec_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    /// <summary>When it was created, ISO 8601 in UTC.</summary>
    public required string CreatedAt { get; init; }

    /// <summary>When a rotated-out secret stops working, ISO 8601 in UTC; null for the current secret.</summary>
    public required string? ExpiresAt { get; init; }
}

/// <summary>An Application's live client secrets, newest first: at most the current one and one rotated-out one.</summary>
public sealed class ApplicationSecretListResponse
{
    public required IReadOnlyList<ApplicationSecretResponse> Items { get; init; }
}

/// <summary>
/// A client secret just created or rotated in (Story 3.3, AD-24): the value, shown in this response only and
/// stored only as its SHA-256, and the live secrets after the write.
/// </summary>
public sealed class ApplicationSecretCreatedResponse
{
    /// <summary><c>{tenantPublicId}.{base64url of 32 random bytes}</c>. Never shown again.</summary>
    public required RevealOnce<string> Secret { get; init; }

    public required IReadOnlyList<ApplicationSecretResponse> Items { get; init; }
}

/// <summary>
/// An Application's client secrets (Story 3.3, FR-12, NFR-3, AD-24): listed with any Tenant Role, created,
/// rotated and revoked by Tenant Owners only, after a fresh assertion the request checks use up, all in the path
/// Tenant's own scope. Management decides the capability again; Directory owns the rows. No response but a
/// create's ever carries a secret, and no refusal or log line names one.
/// </summary>
internal static class ApplicationSecretsApi
{
    /// <summary>The route value naming one of an Application's secrets: its <c>sec_</c> public ID.</summary>
    public const string SecretRouteValue = "secretId";

    public static async Task ListAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationsApi.ApplicationRouteValue) as string, out var applicationId))
        {
            await ApplicationsApi.RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        ApplicationSecretsResult read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.Applications.ListSecretsAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, applicationId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (read.Status == ApplicationSecretStatus.Done)
        {
            await AdminResponses.JsonAsync(context, new ApplicationSecretListResponse { Items = Items(read) });
            return;
        }

        await RefuseAsync(context, read.Status);
    }

    public static async Task CreateAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no Application: the same 404 as an unknown one. The checks have used up the grant.
        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationsApi.ApplicationRouteValue) as string, out var applicationId))
        {
            await ApplicationsApi.RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        ApplicationSecretsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.Applications.CreateSecretAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, applicationId, cancellationToken);

            if (result.Status == ApplicationSecretStatus.Done)
            {
                // The secret's hash and its event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (e.SqlState == AdminResponses.SystemApplicationNamed && !context.Response.HasStarted)
        {
            // The guard the visibility filter should have met first: the system Application is no Application here.
            AdminRequestChecks.Log(context, e);
            await ApplicationsApi.RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (result.Status == ApplicationSecretStatus.Done)
        {
            // Sent with Cache-Control: no-store, as every Admin JSON response is.
            context.Response.StatusCode = StatusCodes.Status201Created;
            await AdminResponses.JsonAsync(
                context,
                new ApplicationSecretCreatedResponse { Secret = result.Secret!, Items = Items(result) },
                cancellationToken: CancellationToken.None);
            return;
        }

        await RefuseAsync(context, result.Status);
    }

    public static async Task RevokeAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        // A malformed Application or secret ID names nothing: the same 404 as an unknown one.
        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationsApi.ApplicationRouteValue) as string, out var applicationId)
            || !PublicId.TryParse(PublicIdType.ClientSecret, context.GetRouteValue(SecretRouteValue) as string, out var secretId))
        {
            await ApplicationsApi.RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        ApplicationSecretsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.Applications.RevokeSecretAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, applicationId, secretId, cancellationToken);

            if (result.Status == ApplicationSecretStatus.Done)
            {
                // The revocation and its event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (result.Status == ApplicationSecretStatus.Done)
        {
            await AdminResponses.JsonAsync(context, new ApplicationSecretListResponse { Items = Items(result) }, cancellationToken: CancellationToken.None);
            return;
        }

        await RefuseAsync(context, result.Status);
    }

    private static List<ApplicationSecretResponse> Items(ApplicationSecretsResult result) =>
        [.. result.Secrets.Select(s => new ApplicationSecretResponse
        {
            Id = PublicId.Format(PublicIdType.ClientSecret, s.Id),
            CreatedAt = ApplicationsApi.Timestamp(s.CreatedAt),
            ExpiresAt = s.ExpiresAt is { } expires ? ApplicationsApi.Timestamp(expires) : null,
        })];

    /// <summary>A refusal by its fixed code only, never a secret or an ID.</summary>
    private static Task RefuseAsync(HttpContext context, ApplicationSecretStatus status) => status switch
    {
        ApplicationSecretStatus.NotFound => ApplicationsApi.RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound),
        ApplicationSecretStatus.NotApplicable =>
            ApplicationsApi.RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.ClientSecretNotApplicable),
        ApplicationSecretStatus.LimitReached =>
            ApplicationsApi.RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.ClientSecretLimitReached),
        _ => ApplicationsApi.RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied),
    };
}
