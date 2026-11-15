using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// Authentication's purge of expired state (Story 4.3, FR-8, NFR-3, AD-12): the sign-in transactions more than
/// <see cref="SecurityLimits.SignInRestartRetention"/> past their expiry, completed or not, and with them the email kept
/// for a restart. One still inside it stays, so a restart keeps the email. The statement names the scope's Tenant, and
/// row-level security holds it there too; it deletes nothing of any other module (AD-1) and reads only
/// <c>expires_at</c>. A second run with the same clock deletes nothing.
/// </summary>
internal static class AuthenticationExpiredStatePurge
{
    private const string DeleteExpired =
        "DELETE FROM signin_transaction WHERE tenant_id = @tenant_id AND expires_at <= @cutoff";

    /// <returns>How many transactions it deleted.</returns>
    public static async Task<int> PurgeAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An expired-state purge runs in its Tenant's own scope.");

        await using var command = context.CreateCommand();
        command.CommandText = DeleteExpired;
        var tenant = command.CreateParameter();
        tenant.ParameterName = "tenant_id";
        tenant.Value = tenantId;
        command.Parameters.Add(tenant);
        var cutoff = command.CreateParameter();
        cutoff.ParameterName = "cutoff";
        cutoff.Value = (now - SecurityLimits.SignInRestartRetention).ToUniversalTime();
        command.Parameters.Add(cutoff);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
