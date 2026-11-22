using System.Data.Common;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>One Connection as an Application sees it (Story 4.12).</summary>
public sealed class ApplicationConnectionResponse
{
    /// <summary>The Connection's ID, which in v1 is its kind: always <c>database</c>.</summary>
    public required string ConnectionId { get; init; }

    /// <summary>Always <c>Username-Password</c>.</summary>
    public required string Name { get; init; }

    /// <summary>Always <c>database</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>Whether the Connection is enabled for the Application. Users sign in through it only when <see cref="TenantEnabled"/> is true too.</summary>
    public required bool Enabled { get; init; }

    /// <summary>Whether the Tenant enables the Connection at all.</summary>
    public required bool TenantEnabled { get; init; }
}

/// <summary>An Application's Connections (Story 4.12).</summary>
public sealed class ApplicationConnectionsResponse
{
    public required IReadOnlyList<ApplicationConnectionResponse> Connections { get; init; }
}

/// <summary>An Application's Connection toggle (Story 4.12): whether Users may sign in to it through the Connection.</summary>
public sealed class SetApplicationConnectionRequest
{
    public bool? Enabled { get; init; }
}

/// <summary>One Application a Connection is enabled for (Story 4.12).</summary>
public sealed class ConnectionApplicationResponse
{
    /// <summary>Its public ID, <c>app_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary><c>spa</c>, <c>web</c>, <c>native</c> or <c>machine</c>.</summary>
    public required string Type { get; init; }
}

/// <summary>The Applications a Connection is enabled for (Story 4.12), ordered by name.</summary>
public sealed class ConnectionApplicationsResponse
{
    public required IReadOnlyList<ConnectionApplicationResponse> Applications { get; init; }
}

/// <summary>
/// Which Connections each Application allows (Story 4.12, FR-14): an Application's Connections read with any Tenant Role and
/// toggled by Editors and Owners, and the Applications a Connection is enabled for, each in the path Tenant's own scope.
/// Management decides the capability again from the same grant. A toggle writes its row and one event together, and only
/// when the value changes. The hidden <c>system</c> Application is never read or toggled: it follows every Connection its
/// Tenant enables.
/// </summary>
internal static class ApplicationConnectionsApi
{
    /// <summary>The route value naming a Connection: in v1 its kind, <c>database</c>.</summary>
    public const string ConnectionRouteValue = "connectionId";

    /// <summary>The largest toggle body: anything bigger is 400 <c>connection_invalid</c>, unread past it.</summary>
    public const int MaxBody = 4096;

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no Application: the same 404 as an unknown one, after the capability.
        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationsApi.ApplicationRouteValue) as string, out var applicationId))
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        ApplicationConnectionsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.DatabaseConnections.GetApplicationConnectionsAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, applicationId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AnswerAsync(context, result, single: false, CancellationToken.None);
    }

    public static async Task SetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        if (!PublicId.TryParse(PublicIdType.Application, context.GetRouteValue(ApplicationsApi.ApplicationRouteValue) as string, out var applicationId)
            || context.GetRouteValue(ConnectionRouteValue) is not string connectionId)
        {
            await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        // Under a deadline and a size cap, as application/json only: a missing or non-boolean enabled is malformed.
        var body = await AdminApi.ReadJsonAsync<SetApplicationConnectionRequest>(context.Request, MaxBody, cancellationToken);
        if (body?.Enabled is not { } enabled)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ConnectionInvalid);
            return;
        }

        ApplicationConnectionsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.DatabaseConnections.SetApplicationConnectionAsync(
                scope.CreateCommandContext(), principal, path.Grant, path.TenantId, applicationId, connectionId, enabled, cancellationToken);

            if (result.Status == ConnectionStatus.Done)
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

        await AnswerAsync(context, result, single: true, CancellationToken.None);
    }

    public static async Task ListApplicationsAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        ConnectionApplicationsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.DatabaseConnections.GetConnectionApplicationsAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case ConnectionStatus.Done:
                await AdminResponses.JsonAsync(
                    context,
                    new ConnectionApplicationsResponse
                    {
                        Applications = [.. result.Applications.Select(a => new ConnectionApplicationResponse { Id = a.Id, Name = a.Name, Type = a.Type })],
                    },
                    cancellationToken: CancellationToken.None);
                return;

            case ConnectionStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    private static async Task AnswerAsync(HttpContext context, ApplicationConnectionsResult result, bool single, CancellationToken cancellationToken)
    {
        switch (result.Status)
        {
            case ConnectionStatus.Done when single:
                await AdminResponses.JsonAsync(context, Response(result.Connections.Single()), cancellationToken: cancellationToken);
                return;

            case ConnectionStatus.Done:
                await AdminResponses.JsonAsync(
                    context,
                    new ApplicationConnectionsResponse { Connections = [.. result.Connections.Select(Response)] },
                    cancellationToken: cancellationToken);
                return;

            case ConnectionStatus.Invalid:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ConnectionInvalid);
                return;

            case ConnectionStatus.NotActive:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantNotActive);
                return;

            case ConnectionStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    private static ApplicationConnectionResponse Response(ManagedApplicationConnection connection) =>
        new()
        {
            ConnectionId = connection.ConnectionId,
            Name = connection.Name,
            Kind = connection.Kind,
            Enabled = connection.Enabled,
            TenantEnabled = connection.TenantEnabled,
        };

    /// <summary>A refusal, logged under its fixed code only: never a value.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("An Application Connection request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, status, problem);
    }
}
