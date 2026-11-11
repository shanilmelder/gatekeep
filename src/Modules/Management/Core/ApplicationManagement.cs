using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>
/// The Applications pages' reads and create (Story 3.1), over Directory's contract: Host.Admin never
/// reaches Directory itself. Every call decides its capability again (AD-5) and refuses with
/// <see cref="ApplicationStatus.Forbidden"/>, as <see cref="SigningKeyManagement"/> does.
/// </summary>
internal sealed class ApplicationManagement(IAuditAppender appender) : IApplicationManagement
{
    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(appender, TimeProvider.System);

    public async Task<ApplicationPageResult> ListAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid? after,
        int limit,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApplicationPageResult(ApplicationStatus.Forbidden, [], null);
        }

        var page = await _directory.ListApplicationsPageAsync(tenantContext, after, limit, cancellationToken);
        return new ApplicationPageResult(ApplicationStatus.Done, [.. page.Applications.Select(Managed)], page.NextAfter);
    }

    public async Task<ApplicationResult> GetAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        Guid applicationId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return new ApplicationResult(ApplicationStatus.Forbidden);
        }

        return await _directory.FindApplicationAsync(tenantContext, applicationId, cancellationToken) is { } application
            ? new ApplicationResult(ApplicationStatus.Done, Managed(application))
            : new ApplicationResult(ApplicationStatus.NotFound);
    }

    public async Task<ApplicationResult> CreateAsync(
        CommandContext tenantContext,
        Principal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        string? name,
        string? type,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantApplicationsManage, principal, grant, tenantId))
        {
            return new ApplicationResult(ApplicationStatus.Forbidden);
        }

        var trimmed = name?.Trim();
        if (string.IsNullOrEmpty(trimmed)
            || trimmed.Length > DirectoryContract.MaxNameLength
            || trimmed.Any(char.IsControl)
            || type is null
            || !DirectoryContract.CreatableKinds.Contains(type, StringComparer.Ordinal))
        {
            return new ApplicationResult(ApplicationStatus.Invalid);
        }

        var actor = principal switch
        {
            AdminPrincipal admin => Actor.Admin(admin.AdminId),
            MachinePrincipal machine => Actor.Client(machine.ClientId),
            _ => throw new ArgumentOutOfRangeException(nameof(principal)),
        };

        var created = await _directory.CreateApplicationAsync(tenantContext, actor, trimmed, type, cancellationToken);
        return new ApplicationResult(ApplicationStatus.Done, Managed(created));
    }

    private static ManagedApplication Managed(DirectoryApplication application) =>
        new(application.Id, application.ClientId, application.Name, application.Kind, application.CredentialRequired, application.CreatedAt);

    private static void RequireOwnContext(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's Applications are read and created in its own context.");
        }
    }
}
