using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Retention;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// AD-16 retention on one chain, under the sealer's chain lock. A cut deletes the contiguous
/// sealed prefix <c>seq &lt;= S</c>, where S is one below the lowest sealed event at or after
/// the cutoff, or one below the last event when every one is older. Checkpoints don't count
/// as events there, so the last event and the head always stay, the chain never restarts at
/// <c>seq = 1</c>, and a dormant chain gets no new checkpoint each day. A prefix holding only
/// checkpoints isn't cut. A late writer's old row sealed after a newer one stays with it. The
/// cutoff is taken from the database's clock, the one <c>occurred_at</c> uses. The database's
/// guards still refuse an unsealed delete, and any role but <c>gk_retention</c>.
/// </summary>
internal sealed class AuditRetention : IAuditRetention
{
    public const string CheckpointType = "audit.retention.checkpoint";

    private const string Cutoff = "now() - make_interval(days => @days)";

    private static readonly ChainSql Tenant = new(
        Bounds: $"""
            SELECT min(seq),
                   max(seq) FILTER (WHERE type_code <> @checkpoint),
                   min(seq) FILTER (WHERE occurred_at >= {Cutoff} AND type_code <> @checkpoint)
            FROM audit_event WHERE tenant_id = @tenant_id AND seq IS NOT NULL
            """,
        CountRange: """
            SELECT count(*), count(*) FILTER (WHERE type_code <> @checkpoint)
            FROM audit_event WHERE tenant_id = @tenant_id AND seq BETWEEN @first AND @last
            """,
        Row: "SELECT epoch, hash FROM audit_event WHERE tenant_id = @tenant_id AND seq = @last",
        DeleteDetail: """
            DELETE FROM audit_detail d USING audit_event e
            WHERE d.tenant_id = @tenant_id AND e.tenant_id = @tenant_id AND d.event_id = e.id
              AND e.seq IS NOT NULL AND e.seq <= @last
            """,
        DeleteEvents: "DELETE FROM audit_event WHERE tenant_id = @tenant_id AND seq IS NOT NULL AND seq <= @last",
        InsertCheckpoint: """
            INSERT INTO audit_event (tenant_id, id, type_code, actor_kind, checkpoint_epoch, checkpoint_seq, checkpoint_hash)
            VALUES (@tenant_id, @id, @checkpoint, 'system', @checkpoint_epoch, @checkpoint_seq, @checkpoint_hash)
            """);

    private static readonly ChainSql Deployment = new(
        Bounds: $"""
            SELECT min(seq),
                   max(seq) FILTER (WHERE type_code <> @checkpoint),
                   min(seq) FILTER (WHERE occurred_at >= {Cutoff} AND type_code <> @checkpoint)
            FROM deployment_audit_event WHERE seq IS NOT NULL
            """,
        CountRange: """
            SELECT count(*), count(*) FILTER (WHERE type_code <> @checkpoint)
            FROM deployment_audit_event WHERE seq BETWEEN @first AND @last
            """,
        Row: "SELECT epoch, hash FROM deployment_audit_event WHERE seq = @last",
        DeleteDetail: """
            DELETE FROM deployment_audit_detail d USING deployment_audit_event e
            WHERE d.event_id = e.id AND e.seq IS NOT NULL AND e.seq <= @last
            """,
        DeleteEvents: "DELETE FROM deployment_audit_event WHERE seq IS NOT NULL AND seq <= @last",
        InsertCheckpoint: """
            INSERT INTO deployment_audit_event (id, type_code, actor_kind, checkpoint_epoch, checkpoint_seq, checkpoint_hash)
            VALUES (@id, @checkpoint, 'system', @checkpoint_epoch, @checkpoint_seq, @checkpoint_hash)
            """);

    // Checkpoints are retention's own record, not events, so a recent one doesn't hold a purge back.
    private const string PurgeBlocked =
        $"""
        SELECT EXISTS (
          SELECT 1 FROM audit_event
          WHERE tenant_id = @tenant_id
            AND (seq IS NULL OR (occurred_at >= {Cutoff} AND type_code <> @checkpoint)))
        """;

    private const string PurgeDetail =
        """
        DELETE FROM audit_detail d USING audit_event e
        WHERE d.tenant_id = @tenant_id AND e.tenant_id = @tenant_id AND d.event_id = e.id AND e.seq IS NOT NULL
        """;

    private const string PurgeEvents = "DELETE FROM audit_event WHERE tenant_id = @tenant_id AND seq IS NOT NULL";

    private const string ChainEmpty = "SELECT NOT EXISTS (SELECT 1 FROM audit_event WHERE tenant_id = @tenant_id)";

    public async Task<int> ApplyAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId;
        var sql = tenantId is null ? Deployment : Tenant;

        await ChainLock.TakeAsync(context, cancellationToken);

        long first;
        long lastEvent;
        long? firstRecent;
        await using (var command = Command(context, sql.Bounds, tenantId))
        {
            ChainLock.Add(command, "days", RetentionPeriods.LogDays);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);

            // No sealed row, or only checkpoints: nothing an event could be cut from.
            if (reader.IsDBNull(0) || reader.IsDBNull(1))
            {
                return 0;
            }

            first = reader.GetInt64(0);
            lastEvent = reader.GetInt64(1);
            firstRecent = reader.IsDBNull(2) ? null : reader.GetInt64(2);
        }

        // Every row below the first recent event is old. The last event, and so the head, stays.
        var last = (firstRecent ?? lastEvent) - 1;
        if (last < first)
        {
            return 0;
        }

        await using (var command = Command(context, sql.CountRange, tenantId))
        {
            ChainLock.Add(command, "first", first);
            ChainLock.Add(command, "last", last);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);

            // A cut over a gap would hide it from verification for good.
            if (reader.GetInt64(0) != last - first + 1)
            {
                throw new InvalidOperationException("The audit chain has a gap in its expired range, so retention leaves it for verification.");
            }

            // Cutting checkpoints alone would only replace them with another.
            if (reader.GetInt64(1) == 0)
            {
                return 0;
            }
        }

        long lastEpoch;
        byte[] lastHash;
        await using (var command = Command(context, sql.Row, tenantId))
        {
            ChainLock.Add(command, "last", last);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            await reader.ReadAsync(cancellationToken);
            lastEpoch = reader.GetInt64(0);
            lastHash = reader.GetFieldValue<byte[]>(1);
        }

        await using (var command = Command(context, sql.DeleteDetail, tenantId))
        {
            ChainLock.Add(command, "last", last);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        int deleted;
        await using (var command = Command(context, sql.DeleteEvents, tenantId))
        {
            ChainLock.Add(command, "last", last);
            deleted = await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = Command(context, sql.InsertCheckpoint, tenantId))
        {
            ChainLock.Add(command, "id", Guid.CreateVersion7());
            ChainLock.Add(command, "checkpoint_epoch", lastEpoch);
            ChainLock.Add(command, "checkpoint_seq", last);
            ChainLock.Add(command, "checkpoint_hash", lastHash);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return deleted;
    }

    public async Task<bool> PurgeAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Only a Tenant's chain is purged, never the Deployment's.");

        await ChainLock.TakeAsync(context, cancellationToken);

        await using (var command = Command(context, PurgeBlocked, tenantId))
        {
            ChainLock.Add(command, "days", RetentionPeriods.LogDays);

            if ((bool)(await command.ExecuteScalarAsync(cancellationToken))!)
            {
                return false;
            }
        }

        await using (var command = Command(context, PurgeDetail, tenantId))
        {
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = Command(context, PurgeEvents, tenantId))
        {
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // A writer may have committed a row since the check: then the chain isn't gone.
        await using (var command = Command(context, ChainEmpty, tenantId))
        {
            return (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
        }
    }

    private static DbCommand Command(CommandContext context, string sql, Guid? tenantId)
    {
        var command = context.CreateCommand();
        command.CommandText = sql;
        ChainLock.Add(command, "checkpoint", CheckpointType);

        if (tenantId is not null)
        {
            ChainLock.Add(command, "tenant_id", tenantId);
        }

        return command;
    }

    private sealed record ChainSql(
        string Bounds,
        string CountRange,
        string Row,
        string DeleteDetail,
        string DeleteEvents,
        string InsertCheckpoint);
}
