using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>The label change's body (Story 1.28). Besides Create Tenant's, the only request that takes a label.</summary>
public sealed class SetTenantLabelRequest
{
    /// <summary><c>dev</c>, <c>staging</c> or <c>prod</c>.</summary>
    public required string Label { get; init; }
}

/// <summary>A Tenant's environment label, and its status, which says whether the label can change.</summary>
public sealed class TenantLabelResponse
{
    /// <summary><c>dev</c>, <c>staging</c> or <c>prod</c>.</summary>
    public required string Label { get; init; }

    /// <summary><c>creating</c> until its creation Operation succeeds, then <c>active</c>; only an active Tenant's label changes.</summary>
    public required string Status { get; init; }
}

/// <summary>
/// A Tenant's environment label (Story 1.28, FR-7): read with any Tenant Role, changed by its
/// Tenant Owner. Both run in the path Tenant's own scope, whose chain the change's event goes on.
/// The request checks have decided the capability; Management decides it again from the same
/// grant, and evaluates <c>WhenProdTenant</c> on the locked label before the gate is called.
/// </summary>
/// <remarks>
/// A change holds two pooled connections at most at once: its Tenant scope, which holds the row
/// lock, and the gate's own Deployment scope, which uses up the grant and commits before the
/// write. So the <c>gk_admin</c> pool (Npgsql's default of 100) bounds concurrent Prod removals at
/// half of it, and a removal waiting for a connection holds only its row lock, which no
/// foreign-key insert waits on (<c>FOR NO KEY UPDATE</c>).
/// </remarks>
internal static class TenantLabelApi
{
    /// <summary>The largest body read: anything bigger is 400 <c>tenant_invalid</c>, unread past it.</summary>
    public const int MaxBody = 4096;

    private const string Active = "active";

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        TenantLabelRead read;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            read = await services.Tenants.GetLabelAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (!read.Allowed || read.Label is not { } label || read.Status is not { } status)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
            return;
        }

        await AdminResponses.JsonAsync(context, new TenantLabelResponse { Label = label, Status = status });
    }

    public static async Task SetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        // Under a deadline and a size cap, as application/json only: anything else is malformed,
        // and refused before anything is locked or any grant is used.
        var body = await AdminApi.ReadJsonAsync<SetTenantLabelRequest>(context.Request, MaxBody, cancellationToken);
        if (body?.Label is not { } requested)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantInvalid);
            return;
        }

        LabelChangeResult result;
        var gatePassed = false;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.Tenants.ChangeLabelAsync(
                scope.CreateCommandContext(),
                principal,
                path.Grant,
                path.TenantId,
                requested,
                async gate => gatePassed = await FreshAssertionGate.RequireAsync(context, services, gate),
                cancellationToken);

            if (result.Status == LabelChangeStatus.Changed)
            {
                // A grant this Session holds for this Tenant's label was for the label just
                // replaced: used up now, so it can't serve a later change it wasn't earned for.
                if (!gatePassed)
                {
                    await FreshAssertionGate.DiscardAsync(context, services, CancellationToken.None);
                }

                // The label and its event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (e.SqlState == AdminResponses.LabelRefused && !context.Response.HasStarted)
        {
            // The guard the lock and status check should have met first: the same refusal, rolled back.
            AdminRequestChecks.Log(context, e);
            await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantNotActive);
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
            case LabelChangeStatus.Changed:
            case LabelChangeStatus.Unchanged:
                await AdminResponses.JsonAsync(
                    context, new TenantLabelResponse { Label = result.Label!, Status = Active }, cancellationToken: CancellationToken.None);
                return;

            case LabelChangeStatus.FreshAssertionRequired:
                // The gate has already answered 403 fresh_assertion_required.
                return;

            case LabelChangeStatus.Invalid:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantInvalid);
                return;

            case LabelChangeStatus.NotActive:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantNotActive);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    /// <summary>A refusal, logged under its fixed code only: never the label, the Tenant's name or its host.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("A Tenant label request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, status, problem);
    }
}
