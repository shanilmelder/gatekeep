using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Sessions.Core;

/// <summary>
/// Sessions' purge of expired state (Story 4.3, FR-8, AD-13, AD-15), children before parents: tokens past their expiry,
/// then Token Families no token references any more, then Sessions that are over and anchor no family. A live
/// Session is never deleted, and an over one that still anchors a family stays, since its natural expiry doesn't end
/// the family (AD-13). Every statement names the scope's Tenant, and row-level security holds it there too; it deletes
/// nothing of any other module (AD-1). It reads only the columns its <c>WHERE</c> clauses name. A second run with the
/// same clock deletes nothing.
/// </summary>
internal static class SessionsExpiredStatePurge
{
    private static readonly string[] Statements =
    [
        "DELETE FROM token WHERE tenant_id = @tenant_id AND expiration_date <= @now",
        """
        DELETE FROM "authorization" a
        WHERE a.tenant_id = @tenant_id
          AND NOT EXISTS (SELECT 1 FROM token t WHERE t.tenant_id = a.tenant_id AND t.authorization_id = a.id)
        """,
        """
        DELETE FROM user_session s
        WHERE s.tenant_id = @tenant_id
          AND (s.ended_at IS NOT NULL OR s.idle_expires_at <= @now OR s.absolute_expires_at <= @now)
          AND NOT EXISTS (SELECT 1 FROM "authorization" a WHERE a.tenant_id = s.tenant_id AND a.user_session_id = s.id)
        """,
    ];

    /// <returns>How many rows it deleted, over all three tables.</returns>
    public static async Task<int> PurgeAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An expired-state purge runs in its Tenant's own scope.");

        var deleted = 0;
        foreach (var statement in Statements)
        {
            await using var command = context.CreateCommand();
            command.CommandText = statement;
            var tenant = command.CreateParameter();
            tenant.ParameterName = "tenant_id";
            tenant.Value = tenantId;
            command.Parameters.Add(tenant);
            var clock = command.CreateParameter();
            clock.ParameterName = "now";
            clock.Value = now.ToUniversalTime();
            command.Parameters.Add(clock);
            deleted += await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return deleted;
    }
}
