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

/// <summary>
/// Directory's side of deleted Applications' purge (Story 3.5, AD-30): it names the context Tenant's deleted
/// Applications for Sessions' and Authentication's purges, which run first, and then deletes the client secrets and
/// the rows of exactly the Applications it is given, children before parents, and of those only the ones whose
/// <c>deleted_at</c> is set: never a visible or <c>system</c> Application. It runs in the Tenant's own scope. A second
/// run deletes nothing.
/// </summary>
internal static class DirectoryApplicationPurge
{
    private const string Deleted = "SELECT id FROM application WHERE tenant_id = @tenant_id AND deleted_at IS NOT NULL ORDER BY id";

    private static readonly string[] Statements =
    [
        """
        DELETE FROM client_secret
        WHERE tenant_id = @tenant_id
          AND application_id IN (
            SELECT id FROM application WHERE tenant_id = @tenant_id AND id = ANY (@application_ids) AND deleted_at IS NOT NULL)
        """,
        "DELETE FROM application WHERE tenant_id = @tenant_id AND id = ANY (@application_ids) AND deleted_at IS NOT NULL",
    ];

    public static async Task<IReadOnlyList<Guid>> DeletedAsync(CommandContext context, CancellationToken cancellationToken)
    {
        var tenantId = TenantOf(context);

        await using var command = context.CreateCommand();
        command.CommandText = Deleted;
        DirectoryService.Add(command, "tenant_id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var ids = new List<Guid>();
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetGuid(0));
        }

        return ids;
    }

    public static async Task PurgeAsync(CommandContext context, IReadOnlyCollection<Guid> applicationIds, CancellationToken cancellationToken)
    {
        var tenantId = TenantOf(context);
        ArgumentNullException.ThrowIfNull(applicationIds);

        if (applicationIds.Count == 0)
        {
            return;
        }

        foreach (var statement in Statements)
        {
            await using var command = context.CreateCommand();
            command.CommandText = statement;
            DirectoryService.Add(command, "tenant_id", tenantId);
            DirectoryService.Add(command, "application_ids", applicationIds.ToArray());
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static Guid TenantOf(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.TenantId
            ?? throw new InvalidOperationException("An Application purge runs in its Tenant's own scope.");
    }
}
