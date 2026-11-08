using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>
/// Writes a refused cross-Tenant request to the refused Tenant's own Log (Story 7.4, AD-9, FR-40),
/// beside the Deployment Log's <c>admin.access.denied</c>, so the attacked Tenant sees it. This is
/// the one Host.Admin Tenant scope that isn't on <see cref="AdminRequestChecks.PathTenant"/>: the
/// request was refused, so there is no authorized path Tenant, and the scope only appends this
/// event to the Tenant the path named. <c>CapabilityRuleTests</c> names this file as the one exemption.
/// </summary>
internal static class CrossTenantRejection
{
    /// <summary>
    /// Appends <c>admin.cross_tenant.rejected</c> for <paramref name="principal"/> in
    /// <paramref name="rejectedTenant"/>'s own scope, and commits it. The request checks call it
    /// inside their Deployment transaction, after the cap allowed its <c>admin.access.denied</c> and
    /// before that commits, only for an Admin who holds no role in the Tenant. Returns false, having
    /// written nothing, when no Tenant has that ID: the event's foreign key to <c>tenant</c> is what
    /// says so, so nothing of Tenancy's is read. Any other database failure is thrown, and the
    /// checks answer it as they answer a failed Deployment write: 503, their transaction rolled back.
    /// </summary>
    public static async Task<bool> WriteAsync(
        AdminApiServices services,
        AdminPrincipal principal,
        Guid rejectedTenant,
        CancellationToken cancellationToken)
    {
        await using var scope = await TenantScope.BeginAsync(services.Source, rejectedTenant, cancellationToken);
        try
        {
            await services.Authorization.RejectCrossTenantAsync(scope.CreateCommandContext(), principal, cancellationToken);
        }
        catch (DbException e) when (e.SqlState == AdminResponses.ForeignKeyViolation)
        {
            // An unknown Tenant has no chain: the Deployment Log alone holds this refusal.
            return false;
        }

        await scope.CommitAsync(cancellationToken);
        return true;
    }
}
