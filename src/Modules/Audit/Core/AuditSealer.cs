using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// Writers take no lock and read no head. Only this touches the seal columns, under a
/// transaction-level advisory lock on the chain, so two sealers can't fork it. The caller's
/// transaction must be READ COMMITTED, the <c>TenantScope</c> and <c>DeploymentScope</c>
/// default: then each statement after the lock reads a fresh snapshot, so a sealer that waited
/// sees the head the other left. At a stricter level a waiting sealer would read the old head
/// and fail, on the unique <c>seq</c> key or as a serialization failure, rather than fork the chain.
/// </summary>
internal sealed class AuditSealer : IAuditSealer
{
    /// <summary>The first key of every chain lock, so no other advisory lock can collide with one.</summary>
    private const int LockNamespace = 0x41554454;

    private const string DeploymentChain = "deployment";

    private const string LockChain = "SELECT pg_advisory_xact_lock(@namespace, hashtext(@chain))";

    private static readonly ChainSql Tenant = new(
        """
        SELECT epoch, seq, hash FROM audit_event
        WHERE tenant_id = @tenant_id AND seq IS NOT NULL
        ORDER BY seq DESC
        LIMIT 1
        """,
        """
        SELECT id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id FROM audit_event
        WHERE tenant_id = @tenant_id AND seq IS NULL
        ORDER BY id
        LIMIT @max
        """,
        """
        UPDATE audit_event SET epoch = @epoch, seq = @seq, prev_hash = @prev_hash, hash = @hash
        WHERE tenant_id = @tenant_id AND id = @id AND seq IS NULL
        """);

    private static readonly ChainSql Deployment = new(
        """
        SELECT epoch, seq, hash FROM deployment_audit_event
        WHERE seq IS NOT NULL
        ORDER BY seq DESC
        LIMIT 1
        """,
        """
        SELECT id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id FROM deployment_audit_event
        WHERE seq IS NULL
        ORDER BY id
        LIMIT @max
        """,
        """
        UPDATE deployment_audit_event SET epoch = @epoch, seq = @seq, prev_hash = @prev_hash, hash = @hash
        WHERE id = @id AND seq IS NULL
        """);

    public async Task<int> SealAsync(CommandContext context, int maxEvents, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEvents, 1);

        var tenantId = context.TenantId;
        var sql = tenantId is null ? Deployment : Tenant;

        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockChain;
            Add(command, "namespace", LockNamespace);
            Add(command, "chain", tenantId?.ToString("D") ?? DeploymentChain);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var head = await ReadHeadAsync(context, sql, tenantId, cancellationToken);
        var waiting = await ReadUnsealedAsync(context, sql, tenantId, maxEvents, cancellationToken);

        // A restore starts a new epoch (Epic 12). Until then the chain keeps its genesis epoch.
        var epoch = head?.Epoch ?? 1;
        var seq = head?.Seq ?? 0;
        var previousHash = head?.Hash;

        foreach (var row in waiting)
        {
            seq = checked(seq + 1);
            var envelope = row with { TenantId = tenantId, Epoch = epoch, Seq = seq };
            var hash = ChainHash.Compute(previousHash, envelope);

            await using var command = context.CreateCommand();
            command.CommandText = sql.Seal;
            AddTenant(command, tenantId);
            Add(command, "id", row.Id);
            Add(command, "epoch", epoch);
            Add(command, "seq", seq);
            Add(command, "prev_hash", previousHash);
            Add(command, "hash", hash);

            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // Only a sealer holding this chain's lock seals, so this means the lock didn't hold.
                throw new InvalidOperationException("An audit row was sealed by something else while the chain was locked.");
            }

            previousHash = hash;
        }

        return waiting.Count;
    }

    private static async Task<Head?> ReadHeadAsync(
        CommandContext context,
        ChainSql sql,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql.Head;
        AddTenant(command, tenantId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new Head(reader.GetInt64(0), reader.GetInt64(1), reader.GetFieldValue<byte[]>(2));
    }

    private static async Task<List<ChainEnvelope>> ReadUnsealedAsync(
        CommandContext context,
        ChainSql sql,
        Guid? tenantId,
        int maxEvents,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql.Unsealed;
        AddTenant(command, tenantId);
        Add(command, "max", maxEvents);

        var rows = new List<ChainEnvelope>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new ChainEnvelope(
                TenantId: null,
                Id: reader.GetGuid(0),
                OccurredAt: reader.GetFieldValue<DateTimeOffset>(1),
                TypeCode: reader.GetString(2),
                ActorKind: reader.GetString(3),
                ActorId: reader.IsDBNull(4) ? null : reader.GetGuid(4),
                TargetKind: reader.IsDBNull(5) ? null : reader.GetString(5),
                TargetId: reader.IsDBNull(6) ? null : reader.GetGuid(6),
                Epoch: 0,
                Seq: 0));
        }

        return rows;
    }

    private static void AddTenant(DbCommand command, Guid? tenantId)
    {
        if (tenantId is not null)
        {
            Add(command, "tenant_id", tenantId);
        }
    }

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    private sealed record ChainSql(string Head, string Unsealed, string Seal);

    private sealed record Head(long Epoch, long Seq, byte[] Hash);
}
