using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// Directory's Tenant purge (Story 2.5): its client secrets, then their Applications, children before
/// parents. Sessions' and Authentication's purges run first, since their rows reference Applications.
/// It runs in the Tenant's own scope, so row-level security holds it to that Tenant too, and deletes
/// nothing of any other module (AD-1). A second run deletes nothing.
/// </summary>
internal sealed class DirectoryPurge : ITenantPurge
{
    private static readonly string[] Statements =
    [
        "DELETE FROM client_secret WHERE tenant_id = @tenant_id",
        "DELETE FROM application WHERE tenant_id = @tenant_id",
    ];

    public async Task PurgeAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Tenant purge runs in its Tenant's own scope.");

        foreach (var statement in Statements)
        {
            await using var command = context.CreateCommand();
            command.CommandText = statement;
            DirectoryService.Add(command, "tenant_id", tenantId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }
}
