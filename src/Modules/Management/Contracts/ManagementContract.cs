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

    /// <summary>
    /// The Signing keys page's reads (Story 9.1), as <c>gk_admin</c>, in the path Tenant's own scope.
    /// They write nothing: <paramref name="appender"/> only builds the Tenancy reads they use.
    /// </summary>
    public static ISigningKeyManagement CreateSigningKeys(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new SigningKeyManagement(appender);
    }

    /// <summary>The Application types an Admin creates (Story 3.1), in a fixed order: <c>spa</c>, <c>web</c>, <c>native</c>, <c>machine</c>.</summary>
    public static IReadOnlyList<string> ApplicationTypes => Gatekeep.Modules.Directory.Contracts.DirectoryContract.CreatableKinds;

    /// <summary>The longest Application name, after trimming: 200 characters.</summary>
    public const int MaxApplicationNameLength = Gatekeep.Modules.Directory.Contracts.DirectoryContract.MaxNameLength;

    /// <summary>
    /// A Tenant's Applications (Story 3.1), as <c>gk_admin</c>, in the path Tenant's own scope, over
    /// Directory's contract. A create writes its event through <paramref name="appender"/>.
    /// </summary>
    public static IApplicationManagement CreateApplications(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new ApplicationManagement(appender);
    }
}
