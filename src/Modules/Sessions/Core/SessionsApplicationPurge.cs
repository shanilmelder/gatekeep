using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Sessions.Core;

/// <summary>
/// Sessions' purge of deleted Applications (Story 3.5, AD-30): the tokens of the given Applications, or of their
/// Token Families, then those families, children before parents. Directory names the Applications, so this reads
/// nothing of its tables. It runs in the Tenant's own scope, so row-level security holds it to that Tenant too, and
/// deletes nothing of any other module (AD-1) and no Session. A second run deletes nothing.
/// </summary>
internal static class SessionsApplicationPurge
{
    private static readonly string[] Statements =
    [
        """
        DELETE FROM token
        WHERE tenant_id = @tenant_id
          AND (application_id = ANY (@application_ids)
               OR authorization_id IN (
                 SELECT a.id FROM "authorization" a
                 WHERE a.tenant_id = @tenant_id AND a.application_id = ANY (@application_ids)))
        """,
        "DELETE FROM \"authorization\" WHERE tenant_id = @tenant_id AND application_id = ANY (@application_ids)",
    ];

    public static async Task PurgeAsync(CommandContext context, IReadOnlyCollection<Guid> applicationIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(applicationIds);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An Application purge runs in its Tenant's own scope.");

        if (applicationIds.Count == 0)
        {
            return;
        }

        foreach (var statement in Statements)
        {
            await using var command = context.CreateCommand();
            command.CommandText = statement;
            Add(command, "tenant_id", tenantId);
            Add(command, "application_ids", applicationIds.ToArray());
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static void Add(System.Data.Common.DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
