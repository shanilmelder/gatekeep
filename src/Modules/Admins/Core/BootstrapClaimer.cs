using System.Globalization;
using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Consumes the bootstrap token over <c>bootstrap_state</c> (Story 1.21, AD-31). The row lock is
/// taken first and held to the commit, so a second claim waits, then reads the completed row and
/// finds nothing to claim. Completion is the only write this story makes to the row, and the
/// table's trigger makes it final. A wait for the lock past <paramref name="lockTimeout"/> fails.
/// </summary>
internal sealed class BootstrapClaimer(IAuditAppender appender, TimeSpan lockTimeout) : IBootstrapClaimer
{
    // Under READ COMMITTED a waiting FOR UPDATE reads the row the first claim committed.
    private const string Isolation = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED";

    private const string Lock =
        """
        SELECT token_sha256, completed_at IS NOT NULL, expires_at <= clock_timestamp()
        FROM bootstrap_state
        WHERE id = 1
        FOR UPDATE
        """;

    private const string State = "SELECT completed_at IS NOT NULL FROM bootstrap_state WHERE id = 1";

    private const string CreateAdmin = "INSERT INTO admin (id, deployment_owner) VALUES (@id, true)";

    private const string Complete =
        "UPDATE bootstrap_state SET completed_at = clock_timestamp() WHERE id = 1 AND completed_at IS NULL";

    private static readonly AuditTypeCode Created = AdminsEvents.BootstrapAdminCreated.Code;

    // SET takes no parameter: a whole number of milliseconds, formatted here.
    private readonly string _lockTimeout = string.Create(
        CultureInfo.InvariantCulture,
        $"SET LOCAL lock_timeout = '{(long)lockTimeout.TotalMilliseconds}ms'");

    public async Task<BootstrapOpenness> ReadStateAsync(CommandContext context, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);

        await using var command = context.CreateCommand();
        command.CommandText = State;
        return await command.ExecuteScalarAsync(cancellationToken) switch
        {
            null or DBNull => BootstrapOpenness.NotIssued,
            true => BootstrapOpenness.Complete,
            _ => BootstrapOpenness.Open,
        };
    }

    public async Task<BootstrapClaimResult> ClaimAsync(
        CommandContext context,
        Secret<byte[]> submittedToken,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(submittedToken);

        foreach (var setting in new[] { Isolation, _lockTimeout })
        {
            await using var command = context.CreateCommand();
            command.CommandText = setting;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        byte[] stored;
        bool expired;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Lock;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken) || reader.GetBoolean(1))
            {
                // No token issued, or bootstrap complete: nothing to claim.
                return BootstrapClaimResult.NotFound;
            }

            stored = reader.GetFieldValue<byte[]>(0);
            expired = reader.GetBoolean(2);
        }

        // Hashed and compared even when expired, so an expired token takes the same time as a wrong one.
        var matches = submittedToken.Use(token => Matches(token, stored));
        if (!matches || expired)
        {
            return BootstrapClaimResult.Refused;
        }

        var adminId = Guid.CreateVersion7();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = CreateAdmin;
            AdminSessions.Add(command, "id", adminId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Complete;
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("Bootstrap completed under the row lock.");
            }
        }

        var session = await AdminSessions.StartAsync(context, adminId, AdminSessionKind.Setup, cancellationToken);

        await appender.AppendAsync(
            context,
            new AuditEvent(Created, Actor.Admin(adminId), AuditTargetKind.Admin, adminId),
            detail: null,
            cancellationToken);

        return new BootstrapClaimResult(BootstrapClaimStatus.Claimed, session);
    }

    /// <summary>A malformed token never matches, and never throws past here.</summary>
    private static bool Matches(byte[] submitted, byte[] stored)
    {
        byte[] hash;
        try
        {
            hash = BootstrapToken.Hash(submitted.AsSpan());
        }
        catch (ArgumentException)
        {
            // Still one comparison, against a hash nothing has.
            hash = new byte[stored.Length];
            CryptographicOperations.FixedTimeEquals(hash, stored);
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(hash, stored);
    }
}
