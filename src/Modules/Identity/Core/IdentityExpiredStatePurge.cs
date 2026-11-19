using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Identity.Core;

/// <summary>
/// Identity's purge of expired state (Story 4.7, AD-12): the verification links more than
/// <see cref="SecurityLimits.OneTimeTokenRetention"/> past their expiry, used or not; then the pending credentials left
/// with no link, an abandoned sign-up's; then the unverified Users a sign-up made that hold no credential and that no sign-in
/// transaction names. Each statement names the scope's Tenant, and row-level security holds it there too; it deletes nothing
/// of any other module (AD-1) and reads no hash. A second run with the same clock deletes nothing.
/// </summary>
internal static class IdentityExpiredStatePurge
{
    private const string DeleteExpired =
        "DELETE FROM one_time_token WHERE tenant_id = @tenant_id AND expires_at <= @cutoff";

    // A pending credential is written with its link, so one with none left is an abandoned sign-up's.
    private const string DeleteAbandonedCredentials =
        """
        DELETE FROM password_credential c
        WHERE c.tenant_id = @tenant_id AND c.status = 'pending'
          AND NOT EXISTS (SELECT 1 FROM one_time_token t WHERE t.tenant_id = c.tenant_id AND t.credential_id = c.id)
        """;

    // Only a User a sign-up made (it has an email), never verified, holding no credential and named by no transaction.
    private const string DeleteAbandonedUsers =
        """
        DELETE FROM "user" u
        WHERE u.tenant_id = @tenant_id AND u.email IS NOT NULL AND u.email_verified_at IS NULL
          AND NOT EXISTS (SELECT 1 FROM password_credential c WHERE c.tenant_id = u.tenant_id AND c.user_id = u.id)
          AND NOT EXISTS (SELECT 1 FROM signin_transaction s WHERE s.tenant_id = u.tenant_id AND s.signup_user_id = u.id)
        """;

    /// <returns>How many rows it deleted.</returns>
    public static async Task<int> PurgeAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An expired-state purge runs in its Tenant's own scope.");

        var deleted = 0;
        foreach (var statement in new[] { DeleteExpired, DeleteAbandonedCredentials, DeleteAbandonedUsers })
        {
            await using var command = context.CreateCommand();
            command.CommandText = statement;
            var tenant = command.CreateParameter();
            tenant.ParameterName = "tenant_id";
            tenant.Value = tenantId;
            command.Parameters.Add(tenant);
            if (statement == DeleteExpired)
            {
                var cutoff = command.CreateParameter();
                cutoff.ParameterName = "cutoff";
                cutoff.Value = (now - SecurityLimits.OneTimeTokenRetention).ToUniversalTime();
                command.Parameters.Add(cutoff);
            }

            deleted += await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return deleted;
    }
}
