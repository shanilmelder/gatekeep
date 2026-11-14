using System.Data.Common;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>
/// The Deployment Log (Story 7.7, FR-40): bootstrap, Admin sign-in, recovery, Tenant and other
/// Deployment events in <c>deployment_audit_event</c>, read by the Deployment Owner alone
/// (<c>deployment.log.read</c>). Read-only, each read in one Deployment transaction, and in the
/// same shapes as a Tenant's Log (Stories 7.4 and 7.5), so one page and one drawer serve both.
/// A search takes an event type, an Admin by UUID, a Tenant by <c>ten_</c> ID, an outcome and a
/// time range, each at most once and ANDed; anything malformed is 400 <c>invalid_request</c>
/// before anything is read. Opening an event always sends <c>raw</c>: the capability that reads the
/// Log is the Deployment Owner's, and there is no Viewer tier here. Reading the Log isn't audited.
/// </summary>
internal static class DeploymentLogsApi
{
    public const string AdminQuery = "admin";

    public const string TenantQuery = "tenant";

    public static async Task SearchAsync(HttpContext context, AdminApiServices services)
    {
        var cancellationToken = context.RequestAborted;
        if (Parse(context.Request.Query) is not { } query)
        {
            await TenantLogsApi.RefuseAsync(context);
            return;
        }

        TenantLogPage page;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            page = await services.DeploymentLog.SearchAsync(scope.CreateCommandContext(), query, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, TenantLogsApi.Page(page));
    }

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var cancellationToken = context.RequestAborted;
        if (!PublicId.TryParse(PublicIdType.AuditEvent, context.GetRouteValue(TenantLogsApi.EventRouteValue) as string, out var eventId))
        {
            await TenantLogsApi.RefuseEventAsync(context, StatusCodes.Status400BadRequest, AdminResponses.InvalidRequest);
            return;
        }

        TenantLogEvent? found;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            found = await services.DeploymentLog.FindAsync(scope.CreateCommandContext(), eventId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (found is null)
        {
            // A Tenant Log event's ID is unknown here too: it isn't in the Deployment Log.
            await TenantLogsApi.RefuseEventAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        await AdminResponses.JsonAsync(context, TenantLogsApi.Opened(found, withRaw: true));
    }

    /// <summary>The search a query string names, or null when any parameter in it is malformed.</summary>
    internal static DeploymentLogQuery? Parse(IQueryCollection parameters)
    {
        if (TenantLogsApi.ParseShared(parameters) is not { } shared
            || !TenantLogsApi.Single(parameters, AdminQuery, out var admin)
            || !TenantLogsApi.Single(parameters, TenantQuery, out var tenant))
        {
            return null;
        }

        var query = new DeploymentLogQuery
        {
            Types = shared.Types,
            OutcomeTypes = shared.OutcomeTypes,
            From = shared.From,
            To = shared.To,
            After = shared.After,
        };

        if (admin is not null)
        {
            if (!TenantLogsApi.IsUuid(admin, out var adminId))
            {
                return null;
            }

            query = query with { AdminId = adminId };
        }

        if (tenant is not null)
        {
            if (!PublicId.TryParse(PublicIdType.Tenant, tenant, out var tenantId))
            {
                return null;
            }

            query = query with { TenantId = tenantId };
        }

        return query with { Limit = TenantLogsApi.PageSize };
    }
}
