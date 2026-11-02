using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Audit.AuditChains;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>AD-16 verification of one chain, as <c>gk_cli</c>: each problem by position.</summary>
public sealed class VerifyTests(PostgresFixture postgres)
{
    private const string RaisedByTrigger = "P0001";

    public static TheoryData<Guid?> Chains => [TenantA, (Guid?)null];

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Intact_chain_verifies_with_its_row_count(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 5);

        var report = await chains.VerifyAsync(tenantId);

        Assert.True(report.Intact, string.Join("; ", report.Problems));
        Assert.Equal(5, report.SealedRows);
    }

    [Fact]
    public async Task Empty_chain_verifies_with_no_rows()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);

        var report = await chains.VerifyAsync(TenantA);

        Assert.True(report.Intact);
        Assert.Equal(0, report.SealedRows);
    }

    [Fact]
    public async Task Unsealed_rows_arent_walked()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 2);
        await chains.AppendAsync(TenantA, 3);

        var report = await chains.VerifyAsync(TenantA);

        Assert.True(report.Intact);
        Assert.Equal(2, report.SealedRows);
    }

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Altered_sealed_row_is_named_by_epoch_and_seq(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 5);

        await chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            UPDATE {EventTable(tenantId)} SET type_code = 'tenancy.settings.deleted' WHERE {TenantFilter(tenantId)} seq = 3;
            """);

        var report = await chains.VerifyAsync(tenantId);

        var problem = Assert.Single(report.Problems);
        Assert.Equal(new ChainProblem(ChainProblemKind.Altered, 1, 3, 3, "hash doesn't match"), problem);
        Assert.Equal("epoch 1 seq 3: altered (hash doesn't match)", problem.ToString());
    }

    [Fact]
    public async Task Row_rewritten_with_its_hash_recomputed_breaks_the_next_link()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5);

        // Row 3 changed and rehashed: its own hash holds, but row 4 still names the old one.
        var row = (await ChainCheck.ReadAsync(chains.Superuser, TenantA))[2];
        var changed = row.Envelope with { TypeCode = "tenancy.settings.deleted" };
        await using (var connection = new NpgsqlConnection(chains.Superuser))
        {
            await connection.OpenAsync(Cancellation);
            await using var command = new NpgsqlCommand(
                """
                SET session_replication_role = replica;
                UPDATE audit_event SET type_code = 'tenancy.settings.deleted', hash = @hash WHERE tenant_id = @tenant_id AND seq = 3;
                """,
                connection);
            command.Parameters.AddWithValue("hash", AuditContract.ChainHashOf(row.PreviousHash, changed));
            command.Parameters.AddWithValue("tenant_id", TenantA);
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        var report = await chains.VerifyAsync(TenantA);

        var problem = Assert.Single(report.Problems);
        Assert.Equal("epoch 1 seq 4: altered (prev_hash doesn't match seq 3)", problem.ToString());
    }

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Missing_middle_row_is_named(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 5);

        await DeleteAsSuperuserAsync(chains, tenantId, "seq = 3");

        var report = await chains.VerifyAsync(tenantId);

        var problem = Assert.Single(report.Problems);
        Assert.Equal(new ChainProblem(ChainProblemKind.Missing, null, 3, 3, "no row between seq 2 and seq 4"), problem);
        Assert.Equal(4, report.SealedRows);
    }

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Missing_start_with_no_checkpoint_is_named(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 5);

        await DeleteAsSuperuserAsync(chains, tenantId, "seq <= 2");

        var report = await chains.VerifyAsync(tenantId);

        var problem = Assert.Single(report.Problems);
        Assert.Equal(new ChainProblem(ChainProblemKind.Missing, null, 1, 2, "no checkpoint names seq 2"), problem);
        Assert.Equal("seq 1-2: missing (no checkpoint names seq 2)", problem.ToString());
    }

    [Fact]
    public async Task Altered_first_epoch_is_named_once_not_on_every_later_row()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 4);

        await chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            UPDATE audit_event SET epoch = 2 WHERE tenant_id = '{TenantA}' AND seq = 1;
            """);

        var report = await chains.VerifyAsync(TenantA);

        Assert.Equal(
            ["epoch 2 seq 1: altered (hash doesn't match)", "epoch 1 seq 2: altered (epoch changed from 2)"],
            report.Problems.Select(p => p.ToString()));
    }

    [Fact]
    public async Task Genesis_with_a_prev_hash_is_named_even_without_its_CHECK()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 2);

        await chains.SuperuserAsync(
            $"""
            ALTER TABLE audit_event DROP CONSTRAINT audit_event_seal_chain;
            SET session_replication_role = replica;
            UPDATE audit_event SET prev_hash = '\x01' WHERE tenant_id = '{TenantA}' AND seq = 1;
            """);

        var report = await chains.VerifyAsync(TenantA);

        Assert.Contains(report.Problems, p => p.ToString() == "epoch 1 seq 1: altered (genesis has a prev_hash)");
    }

    [Fact]
    public async Task Rows_deleted_after_a_sealed_cut_are_missing_from_seq_1()
    {
        var chains = await CutAndSealedAsync();
        await DeleteAsSuperuserAsync(chains, TenantA, "seq = 3");

        var report = await chains.VerifyAsync(TenantA);

        var problem = Assert.Single(report.Problems);
        Assert.Equal(new ChainProblem(ChainProblemKind.Missing, null, 1, 3, "no checkpoint names seq 3"), problem);
    }

    [Theory]
    [InlineData("checkpoint_hash = '\\x01'")]
    [InlineData("checkpoint_seq = 1")]
    public async Task Altered_sealed_checkpoint_is_named_and_accounts_for_nothing(string assignment)
    {
        var chains = await CutAndSealedAsync();
        await chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            UPDATE audit_event SET {assignment} WHERE tenant_id = '{TenantA}' AND type_code = '{AuditEvents.RetentionCheckpoint.Code.Value}';
            """);

        var report = await chains.VerifyAsync(TenantA);

        Assert.Equal(
            ["seq 1-2: missing (no checkpoint names seq 2)", "epoch 1 seq 6: altered (hash doesn't match)"],
            report.Problems.Select(p => p.ToString()));
    }

    [Fact]
    public async Task Rehashed_checkpoint_naming_the_seq_with_another_hash_doesnt_match()
    {
        var chains = await CutAndSealedAsync();

        // The checkpoint is the head, so rehashing it breaks no link: only what it names is wrong.
        var checkpoint = (await ChainCheck.ReadAsync(chains.Superuser, TenantA))[^1];
        var forged = checkpoint.Envelope with { CheckpointHash = [0x01] };
        await using (var connection = new NpgsqlConnection(chains.Superuser))
        {
            await connection.OpenAsync(Cancellation);
            await using var command = new NpgsqlCommand(
                """
                SET session_replication_role = replica;
                UPDATE audit_event SET checkpoint_hash = '\x01', hash = @hash WHERE tenant_id = @tenant_id AND id = @id;
                """,
                connection);
            command.Parameters.AddWithValue("hash", AuditContract.ChainHashOf(checkpoint.PreviousHash, forged));
            command.Parameters.AddWithValue("tenant_id", TenantA);
            command.Parameters.AddWithValue("id", checkpoint.Envelope.Id);
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        var report = await chains.VerifyAsync(TenantA);

        var problem = Assert.Single(report.Problems);
        Assert.Equal("seq 1-2: missing (checkpoint for seq 2 doesn't match)", problem.ToString());
    }

    [Fact]
    public async Task Unsealed_checkpoint_accounts_for_its_cut()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5, 1, 2);
        Assert.Equal(2, await chains.ApplyRetentionAsync(TenantA));

        var report = await chains.VerifyAsync(TenantA);

        Assert.True(report.Intact, string.Join("; ", report.Problems));
        Assert.Equal(3, report.SealedRows);
    }

    [Fact]
    public async Task Changed_epoch_is_named()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 3);

        await chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            UPDATE audit_event SET epoch = 2 WHERE tenant_id = '{TenantA}' AND seq = 3;
            """);

        var report = await chains.VerifyAsync(TenantA);

        Assert.Contains(report.Problems, p => p.ToString() == "epoch 2 seq 3: altered (epoch changed from 1)");
        Assert.Contains(report.Problems, p => p.ToString() == "epoch 2 seq 3: altered (hash doesn't match)");
    }

    [Fact]
    public async Task Verify_reads_one_Tenants_chain_only()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA, TenantB);
        await chains.SealedChainAsync(TenantA, 2);
        await chains.SealedChainAsync(TenantB, 3);
        await DeleteAsSuperuserAsync(chains, TenantB, "seq = 2");

        Assert.True((await chains.VerifyAsync(TenantA)).Intact);
        Assert.Equal(2, (await chains.VerifyAsync(TenantA)).SealedRows);
        Assert.False((await chains.VerifyAsync(TenantB)).Intact);
    }

    [Theory]
    [MemberData(nameof(Chains))]
    public async Task Erasing_detail_as_the_Worker_leaves_the_chain_verifiable(Guid? tenantId)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(tenantId, 3);
        Assert.Equal(3, await chains.CountAsync(DetailTable(tenantId), tenantId));

        await chains.InScopeAsync(TableRegistry.Worker, tenantId, async context =>
        {
            await using var command = context.CreateCommand();
            command.CommandText = $"DELETE FROM {DetailTable(tenantId)}";
            return await command.ExecuteNonQueryAsync(Cancellation);
        });

        Assert.Equal(0, await chains.CountAsync(DetailTable(tenantId), tenantId));
        var report = await chains.VerifyAsync(tenantId);
        Assert.True(report.Intact, string.Join("; ", report.Problems));
        Assert.Equal(3, report.SealedRows);
    }

    [Theory]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Worker)]
    [InlineData(TableRegistry.Cli)]
    [InlineData(TableRegistry.Hosted)]
    public async Task Role_other_than_retention_cant_insert_a_checkpoint(string role)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);

        var error = await Assert.ThrowsAsync<PostgresException>(() => chains.InScopeAsync(role, TenantA, async context =>
        {
            await using var command = context.CreateCommand();
            command.CommandText =
                $"""
                INSERT INTO audit_event (tenant_id, id, type_code, actor_kind, checkpoint_epoch, checkpoint_seq, checkpoint_hash)
                VALUES ('{TenantA}', gen_random_uuid(), '{AuditEvents.RetentionCheckpoint.Code.Value}', 'system', 1, 2, '\x01')
                """;
            return await command.ExecuteNonQueryAsync(Cancellation);
        }));

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Equal(0, await chains.CountAsync("audit_event", TenantA));
    }

    [Theory]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Worker)]
    [InlineData(TableRegistry.Cli)]
    public async Task Role_other_than_retention_cant_insert_a_Deployment_checkpoint(string role)
    {
        var chains = await AuditChains.CreateAsync(postgres);

        var error = await Assert.ThrowsAsync<PostgresException>(() => chains.InScopeAsync(role, null, async context =>
        {
            await using var command = context.CreateCommand();
            command.CommandText =
                $"""
                INSERT INTO deployment_audit_event (id, type_code, actor_kind, checkpoint_epoch, checkpoint_seq, checkpoint_hash)
                VALUES (gen_random_uuid(), '{AuditEvents.RetentionCheckpoint.Code.Value}', 'system', 1, 2, '\x01')
                """;
            return await command.ExecuteNonQueryAsync(Cancellation);
        }));

        Assert.Equal(RaisedByTrigger, error.SqlState);
    }

    [Theory]
    [InlineData("'tenancy.settings.updated', 1, 2, '\\x01'", "audit_event_checkpoint")]
    [InlineData("'audit.retention.checkpoint', NULL, 2, '\\x01'", "audit_event_checkpoint")]
    [InlineData("'audit.retention.checkpoint', 1, NULL, '\\x01'", "audit_event_checkpoint")]
    [InlineData("'audit.retention.checkpoint', 1, 2, NULL", "audit_event_checkpoint")]
    [InlineData("'audit.retention.checkpoint', 1, 0, '\\x01'", "audit_event_checkpoint")]
    public async Task Checkpoint_columns_are_set_exactly_on_a_checkpoint(string values, string constraint)
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);

        var error = await Assert.ThrowsAsync<PostgresException>(() => chains.InScopeAsync(TableRegistry.Retention, TenantA, async context =>
        {
            await using var command = context.CreateCommand();
            command.CommandText =
                $"""
                INSERT INTO audit_event (tenant_id, id, actor_kind, type_code, checkpoint_epoch, checkpoint_seq, checkpoint_hash)
                VALUES ('{TenantA}', gen_random_uuid(), 'system', {values})
                """;
            return await command.ExecuteNonQueryAsync(Cancellation);
        }));

        Assert.Equal("23514", error.SqlState);
        Assert.Equal(constraint, error.ConstraintName);
    }

    /// <summary>Tenant A's rows 1 and 2 cut by retention, and the checkpoint sealed as seq 6.</summary>
    private async Task<AuditChains> CutAndSealedAsync()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5, 1, 2);
        Assert.Equal(2, await chains.ApplyRetentionAsync(TenantA));
        Assert.Equal(1, await chains.SealAsync(TenantA));
        Assert.True((await chains.VerifyAsync(TenantA)).Intact);
        return chains;
    }

    private static Task DeleteAsSuperuserAsync(AuditChains chains, Guid? tenantId, string seqCondition) =>
        chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            DELETE FROM {DetailTable(tenantId)} WHERE event_id IN (SELECT id FROM {EventTable(tenantId)} WHERE {TenantFilter(tenantId)} {seqCondition});
            DELETE FROM {EventTable(tenantId)} WHERE {TenantFilter(tenantId)} {seqCondition};
            """);
}
