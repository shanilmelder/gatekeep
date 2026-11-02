using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>One sealed row as read back, with its stored seal.</summary>
internal sealed record SealedRow(ChainEnvelope Envelope, byte[]? PreviousHash, byte[] Hash);

/// <summary>
/// Reads a chain back as the superuser, which row-level security doesn't limit, and checks
/// every link by recomputing each hash in C# from the stored columns.
/// </summary>
internal static class ChainCheck
{
    private const string Columns =
        "id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, epoch, seq, prev_hash, hash";

    /// <summary>The sealed rows of one chain in <c>seq</c> order. A null Tenant reads the Deployment chain.</summary>
    public static async Task<List<SealedRow>> ReadAsync(string superuserConnection, Guid? tenantId)
    {
        var sql = tenantId is null
            ? $"SELECT {Columns} FROM deployment_audit_event WHERE seq IS NOT NULL ORDER BY seq"
            : $"SELECT {Columns} FROM audit_event WHERE tenant_id = '{tenantId}' AND seq IS NOT NULL ORDER BY seq";

        await using var connection = new NpgsqlConnection(superuserConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync();

        var rows = new List<SealedRow>();
        while (await reader.ReadAsync())
        {
            rows.Add(new SealedRow(
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
                    reader.GetInt64(8)),
                reader.IsDBNull(9) ? null : reader.GetFieldValue<byte[]>(9),
                reader.GetFieldValue<byte[]>(10)));
        }

        return rows;
    }

    /// <summary>Reads the chain and asserts it holds exactly <paramref name="expected"/> rows, all linked.</summary>
    public static async Task<List<SealedRow>> AssertIntactAsync(string superuserConnection, Guid? tenantId, int expected)
    {
        var rows = await ReadAsync(superuserConnection, tenantId);

        Assert.Equal(expected, rows.Count);
        AssertLinked(rows);
        return rows;
    }

    /// <summary><c>seq</c> 1 up with no gap, epoch 1, genesis with no previous hash, and each hash recomputed.</summary>
    public static void AssertLinked(IReadOnlyList<SealedRow> rows)
    {
        byte[]? previous = null;

        for (var i = 0; i < rows.Count; i++)
        {
            var row = rows[i];

            Assert.Equal(i + 1, row.Envelope.Seq);
            Assert.Equal(1, row.Envelope.Epoch);
            Assert.Equal(previous, row.PreviousHash);
            Assert.Equal(AuditContract.ChainHashOf(previous, row.Envelope), row.Hash);

            previous = row.Hash;
        }
    }
}
