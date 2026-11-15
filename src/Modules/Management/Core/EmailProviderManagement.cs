using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Management.Core;

/// <summary>A Tenant's email provider (Story 4.4), over Notifications' contract, with the capability decided again here.</summary>
internal sealed class EmailProviderManagement(IAuditAppender appender) : IEmailProviderManagement
{
    private readonly IAuditAppender _appender = appender;

    public async Task<EmailProviderResult> GetAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        // Authorization runs in the module too (AD-5), from the grant the checks read: no second read.
        if (!AdminCapabilities.Allows(AdminCapabilities.TenantConfigurationRead, principal, grant, tenantId))
        {
            return Refused(EmailProviderStatus.Forbidden);
        }

        var provider = await NotificationsContract.ReadEmailProviderAsync(tenantContext, cancellationToken);
        return new EmailProviderResult(EmailProviderStatus.Done, Managed(provider), [], Changed: false);
    }

    public async Task<EmailProviderResult> SaveAsync(
        CommandContext tenantContext,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        EmailProviderSaveInput input,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(input);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantEmailProviderManage, principal, grant, tenantId))
        {
            return Refused(EmailProviderStatus.Forbidden);
        }

        var save = await NotificationsContract.SaveEmailProviderAsync(
            tenantContext,
            custody,
            _appender,
            Actor.Admin(principal.AdminId),
            new EmailProviderInput(input.Kind, input.Settings, input.FromAddress, input.FromName, input.Secret),
            cancellationToken);
        return save.Status switch
        {
            EmailProviderSaveStatus.Saved => new EmailProviderResult(EmailProviderStatus.Done, Managed(save.Provider), [], Changed: true),
            EmailProviderSaveStatus.Unchanged => new EmailProviderResult(EmailProviderStatus.Done, Managed(save.Provider), [], Changed: false),
            EmailProviderSaveStatus.Invalid => new EmailProviderResult(
                EmailProviderStatus.Invalid, null, [.. save.Errors.Select(e => new EmailProviderError(e.Field, e.Reason))], Changed: false),
            EmailProviderSaveStatus.Unavailable => Refused(EmailProviderStatus.Unavailable),
            _ => throw new InvalidOperationException("Unknown email provider save status."),
        };
    }

    public async Task<EmailProviderResult> RemoveAsync(
        CommandContext tenantContext,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        RequireOwnContext(tenantContext, tenantId);
        ArgumentNullException.ThrowIfNull(principal);

        if (!AdminCapabilities.Allows(AdminCapabilities.TenantEmailProviderManage, principal, grant, tenantId))
        {
            return Refused(EmailProviderStatus.Forbidden);
        }

        var removed = await NotificationsContract.RemoveEmailProviderAsync(
            tenantContext, _appender, Actor.Admin(principal.AdminId), cancellationToken);
        return new EmailProviderResult(EmailProviderStatus.Done, null, [], removed);
    }

    private static ManagedEmailProvider? Managed(EmailProviderConfiguration? provider) => provider is null
        ? null
        : new ManagedEmailProvider(
            provider.Kind,
            new ManagedEmailProviderSettings
            {
                Host = provider.Settings.Host,
                Port = provider.Settings.Port,
                Tls = provider.Settings.Tls,
                Username = provider.Settings.Username,
                Region = provider.Settings.Region,
                MessageStream = provider.Settings.MessageStream,
                Domain = provider.Settings.Domain,
                AccessKeyId = provider.Settings.AccessKeyId,
                Endpoint = provider.Settings.Endpoint,
                AuthHeaderName = provider.Settings.AuthHeaderName,
            },
            provider.FromAddress,
            provider.FromName,
            provider.UpdatedAt,
            provider.SecretSet);

    private static EmailProviderResult Refused(EmailProviderStatus status) => new(status, null, [], Changed: false);

    private static void RequireOwnContext(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's email provider is read and written in its own context.");
        }
    }
}
