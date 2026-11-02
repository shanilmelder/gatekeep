using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Admin attempts, counted in the <c>UNLOGGED</c> <c>control</c> table <c>admin_attempt</c>
/// (AD-14). One statement counts, resets an elapsed window and saturates the count, so
/// concurrent attempts can't lose one. The subject reaches the table only as its SHA-256.
/// </summary>
internal sealed class AdminAttemptLimiter : IRateLimiter
{
    // now() is the transaction's time, so every attempt in one command uses the same clock.
    // The count stops at limit + 1: enough to say "refused", with no growth after that.
    private const string Upsert =
        """
        INSERT INTO admin_attempt (policy, subject_hash, window_start, attempts)
        VALUES (@policy, @hash, now(), 1)
        ON CONFLICT (policy, subject_hash) DO UPDATE SET
          window_start = CASE WHEN admin_attempt.window_start + @window <= now() THEN now() ELSE admin_attempt.window_start END,
          attempts     = CASE WHEN admin_attempt.window_start + @window <= now() THEN 1 ELSE least(admin_attempt.attempts, @limit) + 1 END
        RETURNING attempts, window_start + @window - now()
        """;

    public async Task<RateLimitDecision> AttemptAsync(
        CommandContext context,
        RateLimitPolicy policy,
        string subject,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        if (context.TenantId is not null)
        {
            // Tenant counters are keyed by Tenant and live in their own table (Story 2.5).
            throw new InvalidOperationException("Admin attempts are counted only in a Deployment scope.");
        }

        await using var command = context.CreateCommand();
        command.CommandText = Upsert;
        Add(command, "policy", policy.Code);
        Add(command, "hash", SHA256.HashData(Encoding.UTF8.GetBytes(subject)));
        Add(command, "window", policy.Window);
        Add(command, "limit", policy.Limit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw new InvalidOperationException("The attempt upsert returned no row.");
        }

        var attempts = reader.GetInt32(0);
        var remaining = reader.GetFieldValue<TimeSpan>(1);

        if (attempts <= policy.Limit)
        {
            return RateLimitDecision.Allow;
        }

        // The window always ends after now(), but a clock this coarse could round it to zero.
        return RateLimitDecision.Refuse(remaining > TimeSpan.Zero ? remaining : TimeSpan.FromTicks(1));
    }

    private static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
