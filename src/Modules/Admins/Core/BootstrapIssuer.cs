using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// The bootstrap token over the single-row <c>control</c> table <c>bootstrap_state</c> (Story 1.19).
/// One upsert takes the row lock: on an empty table a concurrent insert waits on the primary key
/// until the first commits, then updates. A completed row is never updated, so a completion by
/// Story 1.21 between the precheck and the upsert returns no row.
/// </summary>
internal sealed class BootstrapIssuer(IAuditAppender appender) : IBootstrapIssuer
{
    // The row lock serialises issues only under READ COMMITTED, where a waiting upsert sees the
    // committed row. A wait longer than the timeout fails with 55P03.
    private const string Isolation = "SET TRANSACTION ISOLATION LEVEL READ COMMITTED";

    private const string LockTimeout = "SET LOCAL lock_timeout = '30s'";

    private const string Read = "SELECT completed_at IS NOT NULL FROM bootstrap_state WHERE id = 1";

    // One clock_timestamp(), taken in this statement, so the expiry is exactly 15 minutes after
    // the issue and both come from the database clock. xmax <> 0 marks a row that was updated.
    private const string Upsert =
        """
        INSERT INTO bootstrap_state (id, token_sha256, issued_at, expires_at)
        SELECT 1, @hash, c.t, c.t + interval '15 minutes'
        FROM (SELECT clock_timestamp() AS t) AS c
        ON CONFLICT (id) DO UPDATE SET
          token_sha256 = EXCLUDED.token_sha256,
          issued_at    = EXCLUDED.issued_at,
          expires_at   = EXCLUDED.expires_at
        WHERE bootstrap_state.completed_at IS NULL
        RETURNING issued_at, expires_at, xmax <> 0
        """;

    private static readonly AuditTypeCode Issued = AdminsEvents.BootstrapTokenIssued.Code;

    private static readonly AuditTypeCode Reissued = AdminsEvents.BootstrapTokenReissued.Code;

    public async Task<bool> IsCompleteAsync(CommandContext context, CancellationToken cancellationToken)
    {
        RequireDeployment(context);

        await using var command = context.CreateCommand();
        command.CommandText = Read;
        return await command.ExecuteScalarAsync(cancellationToken) is true;
    }

    public async Task<BootstrapIssue?> IssueAsync(
        CommandContext context,
        Secret<byte[]> token,
        CancellationToken cancellationToken)
    {
        RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(token);

        var hash = token.Use(t => BootstrapToken.Hash(t));

        foreach (var setting in new[] { Isolation, LockTimeout })
        {
            await using var command = context.CreateCommand();
            command.CommandText = setting;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        DateTimeOffset issuedAt;
        DateTimeOffset expiresAt;
        bool reissued;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Upsert;
            var parameter = command.CreateParameter();
            parameter.ParameterName = "hash";
            parameter.Value = hash;
            command.Parameters.Add(parameter);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                // The row was completed after the precheck.
                return null;
            }

            issuedAt = reader.GetFieldValue<DateTimeOffset>(0);
            expiresAt = reader.GetFieldValue<DateTimeOffset>(1);
            reissued = reader.GetBoolean(2);
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(reissued ? Reissued : Issued, Actor.System),
            detail: null,
            cancellationToken);

        return new BootstrapIssue(issuedAt, expiresAt, reissued);
    }

    private static void RequireDeployment(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("The bootstrap token is issued only in a Deployment scope.");
        }
    }
}
