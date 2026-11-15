using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>
/// Notifications' Tenant purge (Story 4.4, AD-30): its <c>email_provider</c> row, ciphertext and all. It runs in the
/// Tenant's own scope, so row-level security holds it to that Tenant too, and deletes nothing of any other module
/// (AD-1). A second run deletes nothing. The <c>email-</c> key the ciphertext is under is destroyed with the Tenant's
/// other secret class keys.
/// </summary>
internal sealed class NotificationsPurge : ITenantPurge
{
    public async Task PurgeAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Tenant purge runs in its Tenant's own scope.");

        await using var command = context.CreateCommand();
        command.CommandText = EmailProviderStore.Delete;
        EmailProviderStore.Add(command, "tenant_id", tenantId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
