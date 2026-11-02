using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Audit.AuditChains;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>AD-16 retention cuts, as <c>gk_retention</c>: whole sealed prefixes only, and a checkpoint.</summary>
public sealed class RetentionTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";
    private const string RaisedByTrigger = "P0001";

    public static TheoryData<Guid?> Chains => [TenantA, (Guid?)null];

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Old_prefix_and_its_detail_are_cut_and_a_sealed_checkpoint_keeps_the_chain_verifiable(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 5, 1, 2, 3);
        var third = (await ChainCheck.ReadAsync(chains.Superuser, tenantId))[2];

        Assert.Equal(3, await chains.ApplyRetentionAsync(tenantId));

        Assert.Equal([4L, 5L], await chains.SeqsAsync(tenantId));
        Assert.Equal(2, await chains.CountAsync(DetailTable(tenantId), tenantId));

        // The checkpoint names seq 3 and its hash, unsealed until the next pass.
        var checkpoint = await CheckpointAsync(chains, tenantId);
        Assert.Equal((1L, 3L, false), (checkpoint.Epoch, checkpoint.Seq, checkpoint.Sealed));
        Assert.Equal(third.Hash, checkpoint.Hash);

        Assert.Equal(1, await chains.SealAsync(tenantId));
        Assert.Equal([4L, 5L, 6L], await chains.SeqsAsync(tenantId));

        var report = await chains.VerifyAsync(tenantId);
        Assert.True(report.Intact, string.Join("; ", report.Problems));
        Assert.Equal(3, report.SealedRows);
    }

    [Fact]
    public async Task Late_old_row_past_a_newer_one_stays()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3, 1, 3);

        Assert.Equal(1, await chains.ApplyRetentionAsync(TenantA));

        Assert.Equal([2L, 3L], await chains.SeqsAsync(TenantA));
        await chains.SealAsync(TenantA);
        Assert.True((await chains.VerifyAsync(TenantA)).Intact);
    }

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Whole_old_chain_keeps_its_head(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 4, 1, 2, 3, 4);

        Assert.Equal(3, await chains.ApplyRetentionAsync(tenantId));

        Assert.Equal([4L], await chains.SeqsAsync(tenantId));
        await chains.SealAsync(tenantId);
        Assert.Equal([4L, 5L], await chains.SeqsAsync(tenantId));
        Assert.True((await chains.VerifyAsync(tenantId)).Intact);
    }

    [Fact]
    public async Task Nothing_old_cuts_nothing_and_writes_no_checkpoint()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3);

        Assert.Equal(0, await chains.ApplyRetentionAsync(TenantA));
        Assert.Equal(0, await chains.ApplyRetentionAsync(null));

        Assert.Equal(3, await chains.CountAsync("audit_event", TenantA));
    }

    [Fact]
    public async Task Unsealed_old_rows_are_never_cut()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.AppendAsync(TenantA, 3);
        await chains.SuperuserAsync(
            """
            SET session_replication_role = replica;
            UPDATE audit_event SET occurred_at = occurred_at - interval '100 days';
            """);

        Assert.Equal(0, await chains.ApplyRetentionAsync(TenantA));
        Assert.Equal(3, await chains.CountAsync("audit_event", TenantA));
    }

    [Fact]
    public async Task Second_cut_after_the_checkpoint_is_sealed_still_verifies()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5, 1, 2, 4);
        Assert.Equal(2, await chains.ApplyRetentionAsync(TenantA));
        await chains.SealAsync(TenantA);

        // Later, seq 3 is past retention too. Backdating breaks its hash, but the cut takes it.
        await chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            UPDATE audit_event SET occurred_at = occurred_at - interval '100 days' WHERE tenant_id = '{TenantA}' AND seq = 3;
            """);
        Assert.Equal(2, await chains.ApplyRetentionAsync(TenantA));
        await chains.SealAsync(TenantA);

        Assert.Equal([5L, 6L, 7L], await chains.SeqsAsync(TenantA));
        var report = await chains.VerifyAsync(TenantA);
        Assert.True(report.Intact, string.Join("; ", report.Problems));
    }

    [Fact]
    public async Task Dormant_chain_cut_on_two_days_gets_one_checkpoint_and_stays_purgeable()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3, 1, 2, 3);

        // Day one keeps the last event; day two finds only it and the fresh checkpoint.
        Assert.Equal(2, await chains.ApplyRetentionAsync(TenantA));
        await chains.SealAsync(TenantA);
        Assert.Equal(0, await chains.ApplyRetentionAsync(TenantA));
        await chains.SealAsync(TenantA);

        Assert.Equal([3L, 4L], await chains.SeqsAsync(TenantA));
        Assert.Equal(1, await chains.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{AuditEvents.RetentionCheckpoint.Code.Value}'"));
        Assert.True((await chains.VerifyAsync(TenantA)).Intact);

        // The checkpoint is new, but it's retention's own record: the purge goes ahead.
        Assert.True(await chains.PurgeAsync(TenantA));
        Assert.Equal(0, await chains.CountAsync("audit_event", TenantA));
        Assert.Equal(0, await chains.CountAsync("audit_detail", TenantA));
    }

    [Fact]
    public async Task Rerun_with_nothing_newly_due_cuts_nothing()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 4, 1, 2);
        Assert.Equal(2, await chains.ApplyRetentionAsync(TenantA));
        await chains.SealAsync(TenantA);

        Assert.Equal(0, await chains.ApplyRetentionAsync(TenantA));
        Assert.Equal(1, await chains.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE type_code = '{AuditEvents.RetentionCheckpoint.Code.Value}'"));
    }

    [Fact]
    public async Task Prefix_with_a_gap_is_refused_and_left_for_verification()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5, 1, 2, 3);
        await chains.SuperuserAsync(
            """
            SET session_replication_role = replica;
            DELETE FROM audit_detail WHERE event_id IN (SELECT id FROM audit_event WHERE seq = 2);
            DELETE FROM audit_event WHERE seq = 2;
            """);

        await Assert.ThrowsAsync<InvalidOperationException>(() => chains.ApplyRetentionAsync(TenantA));

        Assert.Equal([1L, 3L, 4L, 5L], await chains.SeqsAsync(TenantA));
        Assert.False((await chains.VerifyAsync(TenantA)).Intact);
    }

    [Theory]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Worker)]
    [InlineData(TableRegistry.Sealer)]
    [InlineData(TableRegistry.Cli)]
    public async Task Role_other_than_retention_cant_cut(string role)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3, 1, 2);

        var error = await Assert.ThrowsAsync<PostgresException>(() => chains.InScopeAsync(role, TenantA, context =>
            AuditContract.CreateRetention().ApplyAsync(context, Cancellation)));

        Assert.Contains(error.SqlState, new[] { PermissionDenied, RaisedByTrigger });
        Assert.Equal([1L, 2L, 3L], await chains.SeqsAsync(TenantA));
    }

    [Fact]
    public async Task Cut_waits_for_a_seal_holding_the_chain_lock()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3, 1, 2);
        await chains.AppendAsync(TenantA, 1);

        // An open seal holds the lock; the cut can't start until it commits.
        await using var sealerSource = NpgsqlDataSource.Create(chains.Connection(TableRegistry.Sealer));
        await using var seal = await TenantScope.BeginAsync(sealerSource, TenantA, Cancellation);
        Assert.Equal(1, await AuditContract.CreateSealer().SealAsync(seal.CreateCommandContext(), 500, Cancellation));

        var cut = chains.ApplyRetentionAsync(TenantA);
        await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);
        Assert.False(cut.IsCompleted);

        await seal.CommitAsync(Cancellation);
        Assert.Equal(2, await cut);

        await chains.SealAsync(TenantA);
        Assert.Equal([3L, 4L, 5L], await chains.SeqsAsync(TenantA));
        Assert.True((await chains.VerifyAsync(TenantA)).Intact);
    }

    private static async Task<(long Epoch, long Seq, byte[] Hash, bool Sealed)> CheckpointAsync(AuditChains chains, Guid? tenantId)
    {
        await using var connection = new NpgsqlConnection(chains.Superuser);
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            $"""
            SELECT checkpoint_epoch, checkpoint_seq, checkpoint_hash, seq IS NOT NULL, actor_kind, target_kind
            FROM {EventTable(tenantId)} WHERE {TenantFilter(tenantId)} type_code = '{AuditEvents.RetentionCheckpoint.Code.Value}'
            """,
            connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);

        Assert.True(await reader.ReadAsync(Cancellation));
        var checkpoint = (reader.GetInt64(0), reader.GetInt64(1), reader.GetFieldValue<byte[]>(2), reader.GetBoolean(3));
        Assert.Equal("system", reader.GetString(4));
        Assert.True(reader.IsDBNull(5));
        Assert.False(await reader.ReadAsync(Cancellation));
        return checkpoint;
    }
}
