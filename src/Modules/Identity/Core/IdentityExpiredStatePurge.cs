using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Identity.Core;

/// <summary>
/// Identity's purge of expired state (Story 4.7, AD-12): the verification links more than
/// <see cref="SecurityLimits.OneTimeTokenRetention"/> past their expiry, used or not. The statement names the scope's
/// Tenant, and row-level security holds it there too; it deletes nothing of any other module (AD-1) and reads only
/// <c>expires_at</c>. A second run with the same clock deletes nothing.
/// </summary>
internal static class IdentityExpiredStatePurge
{
    private const string DeleteExpired =
        "DELETE FROM one_time_token WHERE tenant_id = @tenant_id AND expires_at <= @cutoff";

    /// <returns>How many links it deleted.</returns>
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
        cutoff.Value = (now - SecurityLimits.OneTimeTokenRetention).ToUniversalTime();
        command.Parameters.Add(cutoff);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
