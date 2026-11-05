using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// Authentication's Tenant purge (Story 1.29): its pending sign-in transactions.
/// It runs in the Tenant's own scope, so row-level security holds it to that Tenant too, and deletes nothing of any other module (AD-1). A second run deletes nothing.
/// </summary>
internal sealed class AuthenticationPurge : ITenantPurge
{
    private static readonly string[] Statements =
    [
        "DELETE FROM signin_transaction WHERE tenant_id = @tenant_id",
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
}
