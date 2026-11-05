using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// The one <c>tenant_role</c> writer of Story 1.27, and the switcher's read of an Admin's Tenants (Story 1.28): a Tenant's creator becomes its Tenant Owner
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

    /// <summary>
    /// The IDs of the Tenants <paramref name="adminId"/> holds a <c>tenant_role</c> row in, in a
    /// Deployment context, through <c>tenant_role_admin</c> (Story 1.28): the Tenant switcher's only
    /// role read. It never returns the role.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    Task<IReadOnlyList<Guid>> ListTenantIdsAsync(CommandContext context, Guid adminId, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes every <c>tenant_role</c> row in <paramref name="tenantId"/>, in a Deployment context
    /// (Story 1.29), so every Tenant route refuses its former members at once: the authorizer reads
    /// roles on every request and caches nothing. Called only by Tenant deletion's start, once the
    /// Tenant is <c>deleting</c>; the trigger refuses it for any other Tenant.
    /// </summary>
    /// <returns>How many roles ended.</returns>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<int> RemoveAllForTenantAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken);
}
