using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// Walks one chain's sealed rows in <c>seq</c> order, streaming, and reports each problem by
/// position (AD-16). It only reads. Unsealed rows aren't part of a chain yet, so they're not
/// walked, but an unsealed checkpoint can account for the cut it was written by: only
/// <c>gk_retention</c> can insert one, and the next seal pass links it in. A tail deletion,
/// head included, can't be seen here: the off-server heads of Story 7.2 are what show it.
/// </summary>
internal sealed class AuditVerifier : IAuditVerifier
{
    private const string Columns =
        """
        id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, epoch, seq, prev_hash, hash,
          checkpoint_epoch, checkpoint_seq, checkpoint_hash
        """;

    private static readonly string TenantRows =
        $"SELECT {Columns} FROM audit_event WHERE tenant_id = @tenant_id AND seq IS NOT NULL ORDER BY seq";

    private static readonly string DeploymentRows =
        $"SELECT {Columns} FROM deployment_audit_event WHERE seq IS NOT NULL ORDER BY seq";

    private const string TenantUnsealedCheckpoints =
        """
        SELECT checkpoint_epoch, checkpoint_seq, checkpoint_hash FROM audit_event
        WHERE tenant_id = @tenant_id AND seq IS NULL AND type_code = @checkpoint
        """;

    private const string DeploymentUnsealedCheckpoints =
        """
        SELECT checkpoint_epoch, checkpoint_seq, checkpoint_hash FROM deployment_audit_event
        WHERE seq IS NULL AND type_code = @checkpoint
        """;

    public async Task<ChainReport> VerifyAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId;

        var problems = new List<ChainProblem>();
        var checkpoints = new List<Named>();
        Row? first = null;
        Row? previous = null;
        long rows = 0;

        await using (var command = context.CreateCommand())
        {
            command.CommandText = tenantId is null ? DeploymentRows : TenantRows;
            AddTenant(command, tenantId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var row = new Row(
                    new ChainEnvelope(
                        tenantId,
                        reader.GetGuid(0),
                        reader.GetFieldValue<DateTimeOffset>(1),
                        reader.GetString(2),
                        reader.GetString(3),
                        reader.IsDBNull(4) ? null : reader.GetGuid(4),
                        reader.IsDBNull(5) ? null : reader.GetString(5),
                        reader.IsDBNull(6) ? null : reader.GetGuid(6),
                        reader.GetInt64(7),
                        reader.GetInt64(8),
                        reader.IsDBNull(11) ? null : reader.GetInt64(11),
                        reader.IsDBNull(12) ? null : reader.GetInt64(12),
                        reader.IsDBNull(13) ? null : reader.GetFieldValue<byte[]>(13)),
                    reader.IsDBNull(9) ? null : reader.GetFieldValue<byte[]>(9),
                    reader.GetFieldValue<byte[]>(10));

                rows++;
                first ??= row;
                var envelope = row.Envelope;

                // Reported once, where it changes, so one altered row doesn't flag every row after it.
                if (previous is not null && envelope.Epoch != previous.Envelope.Epoch)
                {
                    problems.Add(Altered(row, $"epoch changed from {previous.Envelope.Epoch}"));
                }

                // The CHECK that pairs genesis with no previous hash can be dropped, so it's checked here too.
                if (envelope.Seq == 1 && row.PreviousHash is not null)
                {
                    problems.Add(Altered(row, "genesis has a prev_hash"));
                }

                if (previous is not null && envelope.Seq != previous.Envelope.Seq + 1)
                {
                    problems.Add(new ChainProblem(
                        ChainProblemKind.Missing,
                        Epoch: null,
                        previous.Envelope.Seq + 1,
                        envelope.Seq - 1,
                        $"no row between seq {previous.Envelope.Seq} and seq {envelope.Seq}"));
                }
                else if (previous is not null && !Same(row.PreviousHash, previous.Hash))
                {
                    problems.Add(Altered(row, $"prev_hash doesn't match seq {previous.Envelope.Seq}"));
                }

                var hashMatches = Same(ChainHash.Compute(row.PreviousHash, envelope), row.Hash);
                if (!hashMatches)
                {
                    problems.Add(Altered(row, "hash doesn't match"));
                }

                // Only a checkpoint whose own hash holds can account for deleted rows.
                if (hashMatches && envelope.TypeCode == AuditEvents.RetentionCheckpoint.Code.Value && envelope.CheckpointSeq is { } seq)
                {
                    checkpoints.Add(new Named(envelope.CheckpointEpoch, seq, envelope.CheckpointHash));
                }

                previous = row;
            }
        }

        if (first is not null && first.Envelope.Seq > 1)
        {
            checkpoints.AddRange(await UnsealedCheckpointsAsync(context, tenantId, cancellationToken));

            var named = first.Envelope.Seq - 1;
            var naming = checkpoints.Where(c => c.Seq == named).ToList();
            var accounted = naming.Any(c => c.Epoch == first.Envelope.Epoch && Same(c.Hash, first.PreviousHash));

            if (!accounted)
            {
                problems.Insert(0, new ChainProblem(
                    ChainProblemKind.Missing,
                    Epoch: null,
                    1,
                    named,
                    naming.Count == 0 ? $"no checkpoint names seq {named}" : $"checkpoint for seq {named} doesn't match"));
            }
        }

        return new ChainReport(rows, problems);
    }

    private static async Task<List<Named>> UnsealedCheckpointsAsync(
        CommandContext context,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = tenantId is null ? DeploymentUnsealedCheckpoints : TenantUnsealedCheckpoints;
        AddTenant(command, tenantId);
        ChainLock.Add(command, "checkpoint", AuditEvents.RetentionCheckpoint.Code.Value);

        var named = new List<Named>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            named.Add(new Named(reader.GetInt64(0), reader.GetInt64(1), reader.GetFieldValue<byte[]>(2)));
        }

        return named;
    }

    private static void AddTenant(System.Data.Common.DbCommand command, Guid? tenantId)
    {
        if (tenantId is not null)
        {
            ChainLock.Add(command, "tenant_id", tenantId);
        }
    }

    private static ChainProblem Altered(Row row, string reason) =>
        new(ChainProblemKind.Altered, row.Envelope.Epoch, row.Envelope.Seq, row.Envelope.Seq, reason);

    private static bool Same(byte[]? a, byte[]? b) =>
        a is null || b is null ? a is null && b is null : a.AsSpan().SequenceEqual(b);

    private sealed record Row(ChainEnvelope Envelope, byte[]? PreviousHash, byte[] Hash);

    /// <summary>What one checkpoint names: the last row its cut deleted.</summary>
    private sealed record Named(long? Epoch, long Seq, byte[]? Hash);
}
