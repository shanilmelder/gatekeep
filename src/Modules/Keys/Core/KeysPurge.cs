using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Keys.Core;

/// <summary>
/// Keys' Tenant purge (Story 1.29, merged after Story 2.3): its <c>signing_key</c> rows and its
/// <c>protection_key_wrap</c> row. It runs in the Tenant's own scope, so row-level security holds it
/// to that Tenant too, and deletes nothing of any other module (AD-1). A second run deletes nothing.
/// The Transit keys the rows named are the deletion's destroy stage's (<see cref="DestroyRowKeysAsync"/>).
/// </summary>
internal sealed class KeysPurge : ITenantPurge
{
    private static readonly string[] Statements =
    [
        "DELETE FROM signing_key WHERE tenant_id = @tenant_id",
        "DELETE FROM protection_key_wrap WHERE tenant_id = @tenant_id",
    ];

    private const string SelectRowKeys = "SELECT transit_name FROM signing_key WHERE tenant_id = @tenant_id";

    public async Task PurgeAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Tenant purge runs in its Tenant's own scope.");

        foreach (var statement in Statements)
        {
            await using var command = context.CreateCommand();
            command.CommandText = statement;
            TenantKeys.Add(command, "tenant_id", tenantId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Destroys every Signing and Management Transit key of the context's Tenant, in any state: those
    /// its <c>signing_key</c> rows still name, and those custody lists under its ID, which covers a
    /// purge that ran first and a key whose row was never written. A key already gone counts as
    /// destroyed, so a rerun finishes what is left. A key custody couldn't read when listing, with its
    /// row already purged, is left to the orphan sweep, which deletes unnamed keys after 24 hours.
    /// </summary>
    public static async Task DestroyRowKeysAsync(CommandContext context, IKeyCustody custody, Guid tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(custody);
        TenantKeys.RequireTenant(context, tenantId);

        var keys = new HashSet<KeyName>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectRowKeys;
            TenantKeys.Add(command, "tenant_id", tenantId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (KeyName.TryParseRowKey(reader.GetString(0), out var key) && key.TenantId == tenantId)
                {
                    keys.Add(key);
                }
            }
        }

        foreach (var listed in await custody.ListRowKeysAsync(cancellationToken))
        {
            if (listed.Key.TenantId == tenantId)
            {
                keys.Add(listed.Key);
            }
        }

        foreach (var key in keys.OrderBy(k => k.Value, StringComparer.Ordinal))
        {
            await custody.DeleteAsync(key, cancellationToken);
        }
    }
}
