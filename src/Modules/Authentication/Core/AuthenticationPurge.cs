using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// Authentication's Tenant purge (Story 1.29): its pending sign-in transactions, and from Story 2.5 its attempt counters.
/// It runs in the Tenant's own scope, so row-level security holds it to that Tenant too, and deletes nothing of any other module (AD-1). A second run deletes nothing.
/// </summary>
internal sealed class AuthenticationPurge : ITenantPurge
{
    private static readonly string[] Statements =
    [
        "DELETE FROM signin_transaction WHERE tenant_id = @tenant_id",
        "DELETE FROM tenant_attempt WHERE tenant_id = @tenant_id",
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
            var parameter = command.CreateParameter();
            parameter.ParameterName = "tenant_id";
            parameter.Value = tenantId;
            command.Parameters.Add(parameter);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Story 3.5 (AD-30): the pending sign-in transactions of the given deleted Applications only, which Directory
    /// names, so this reads nothing of its tables. A second run deletes nothing.
    /// </summary>
    public static async Task PurgeApplicationsAsync(CommandContext context, IReadOnlyCollection<Guid> applicationIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(applicationIds);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An Application purge runs in its Tenant's own scope.");

        if (applicationIds.Count == 0)
        {
            return;
        }

        await using var command = context.CreateCommand();
        command.CommandText = "DELETE FROM signin_transaction WHERE tenant_id = @tenant_id AND application_id = ANY (@application_ids)";
        var tenant = command.CreateParameter();
        tenant.ParameterName = "tenant_id";
        tenant.Value = tenantId;
        command.Parameters.Add(tenant);
        var ids = command.CreateParameter();
        ids.ParameterName = "application_ids";
        ids.Value = applicationIds.ToArray();
        command.Parameters.Add(ids);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
