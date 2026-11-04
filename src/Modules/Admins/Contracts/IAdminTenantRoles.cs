using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// The one <c>tenant_role</c> writer of Story 1.27: a Tenant's creator becomes its Tenant Owner
/// (FR-7), as part of <c>deployment.tenants.create</c>. It isn't a capability of its own, and it
/// isn't <c>deployment.admins.manage</c>, which grants roles to others after a fresh assertion (Epic 8).
/// </summary>
public interface IAdminTenantRoles
{
    /// <summary>
    /// Inserts <c>(tenantId, adminId, 'owner')</c> in a Deployment context, in the creating
    /// transaction. Called only by Tenant creation, for the Tenant it has just inserted.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task GrantCreatorOwnerAsync(CommandContext context, Guid adminId, Guid tenantId, CancellationToken cancellationToken);
}
