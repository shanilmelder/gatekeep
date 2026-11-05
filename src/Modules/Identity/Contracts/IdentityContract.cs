using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Identity.Core;

namespace Gatekeep.Modules.Identity.Contracts;

/// <summary>What composition roots and other modules use to reach Identity.</summary>
public static class IdentityContract
{
    /// <summary>
    /// Identity's Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>user</c> rows.
    /// Tenant deletion calls it after Sessions' purge, whose rows reference them.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new IdentityPurge();
}
