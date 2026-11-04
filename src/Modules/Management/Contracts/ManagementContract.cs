using Gatekeep.Kernel.Audit;
using Gatekeep.Modules.Management.Core;

namespace Gatekeep.Modules.Management.Contracts;

/// <summary>What Host.Admin's composition root uses to wire Management (AD-1).</summary>
public static class ManagementContract
{
    /// <summary>
    /// Creating and listing Tenants (Story 1.27), under <paramref name="addressing"/>. It runs as
    /// <c>gk_admin</c>, in a Deployment scope, and writes its events through <paramref name="appender"/>.
    /// </summary>
    public static ITenantManagement CreateTenants(IAuditAppender appender, TenantAddressing addressing)
    {
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(addressing);
        return new TenantManagement(appender, addressing);
    }
}
