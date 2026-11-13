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

    /// <summary>The grant types an Application can hold (Story 3.2), in their stored order.</summary>
    public static IReadOnlyList<string> ApplicationGrantTypes => Gatekeep.Modules.Directory.Contracts.DirectoryContract.GrantTypes;

    /// <summary>The fields a settings save's errors name (Story 3.2).</summary>
    public static IReadOnlyList<string> ApplicationSettingsFields => Gatekeep.Modules.Directory.Contracts.ApplicationSettingsFields.All;

    /// <summary>The reasons a settings save's errors give (Story 3.2).</summary>
    public static IReadOnlyList<string> ApplicationSettingsReasons => Gatekeep.Modules.Directory.Contracts.ApplicationSettingsReasons.All;

    /// <summary>The fields a lifetimes save's errors name (Story 3.4).</summary>
    public static IReadOnlyList<string> ApplicationLifetimeFields => Gatekeep.Modules.Directory.Contracts.ApplicationLifetimeFields.All;

    /// <summary>The reasons a lifetimes save's errors give (Story 3.4).</summary>
    public static IReadOnlyList<string> ApplicationLifetimeReasons => Gatekeep.Modules.Directory.Contracts.ApplicationLifetimeReasons.All;

    /// <summary>The most lines in each of an Application's URL lists (Story 3.2).</summary>
    public const int MaxApplicationUrls = Gatekeep.Modules.Directory.Contracts.DirectoryContract.MaxRedirectUris;

    /// <summary>The longest line in any of an Application's URL lists (Story 3.2).</summary>
    public const int MaxApplicationUrlLength = Gatekeep.Modules.Directory.Contracts.DirectoryContract.MaxRedirectUriLength;

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

    /// <summary>
    /// A Tenant's APIs and their Permissions (Story 3.6), as <c>gk_admin</c>, in the path Tenant's own scope, over
    /// Directory's contract. Each write's event goes through <paramref name="appender"/>.
    /// </summary>
    public static IApiManagement CreateApis(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new ApiManagement(appender);
    }

    /// <summary>The fields an API or Permission write's errors name (Story 3.6), lifetimes included.</summary>
    public static IReadOnlyList<string> ApiFields =>
        [.. Gatekeep.Modules.Directory.Contracts.ApiFields.All, .. Gatekeep.Modules.Directory.Contracts.ApplicationLifetimeFields.All];

    /// <summary>The reasons an API or Permission write's errors give (Story 3.6), lifetimes' included.</summary>
    public static IReadOnlyList<string> ApiReasons =>
        [.. Gatekeep.Modules.Directory.Contracts.ApiReasons.All, .. Gatekeep.Modules.Directory.Contracts.ApplicationLifetimeReasons.All];

    /// <summary>The longest API name, after trimming (Story 3.6).</summary>
    public const int MaxApiNameLength = Gatekeep.Kernel.Limits.SecurityLimits.MaxApiNameLength;

    /// <summary>The longest API identifier (Story 3.6).</summary>
    public const int MaxApiIdentifierLength = Gatekeep.Kernel.Limits.SecurityLimits.MaxApiIdentifierLength;

    /// <summary>The longest Permission description (Story 3.6).</summary>
    public const int MaxPermissionDescriptionLength = Gatekeep.Kernel.Limits.SecurityLimits.MaxPermissionDescriptionLength;

    /// <summary>The most Permissions one API holds (Story 3.6).</summary>
    public const int MaxPermissionsPerApi = Gatekeep.Kernel.Limits.SecurityLimits.MaxPermissionsPerApi;
}
