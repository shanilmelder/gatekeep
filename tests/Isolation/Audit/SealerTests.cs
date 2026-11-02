using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>AD-16 sealing: the Audit sealer on one chain, and the Operations loop over all of them.</summary>
public sealed class SealerTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";
    private const string RaisedByTrigger = "P0001";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000001a");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000001b");
    private static readonly Guid AdminId = Guid.Parse("01900000-0000-7000-8000-0000000001a1");

    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);

    private readonly IAuditAppender _appender = AuditContract.CreateAppender();
    private readonly IAuditSealer _sealer = AuditContract.CreateSealer();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static AuditEvent Event(Guid target) => new(
        new AuditTypeCode("tenancy.settings.updated"),
        Actor.Admin(AdminId),
        AuditTargetKind.Tenant,
        target);

    private static AuditEvent SystemEvent => new(new AuditTypeCode("operations.job.dead"), Actor.System);

    public static TheoryData<string, string> SealedRowChanges => new()
    {
        { "audit_event", "epoch = 2" },
        { "audit_event", "seq = 9" },
        { "audit_event", "hash = '\\x01'" },
        { "audit_event", "prev_hash = '\\x01'" },
        { "audit_event", "epoch = 2, seq = 9, hash = '\\x01'" },
        { "audit_event", "type_code = 'x.y.z'" },
        { "audit_event", "occurred_at = now()" },
        { "deployment_audit_event", "epoch = 2" },
        { "deployment_audit_event", "seq = 9" },
        { "deployment_audit_event", "hash = '\\x01'" },
        { "deployment_audit_event", "type_code = 'x.y.z'" },
    };

    [Fact]
    public async Task First_seal_numbers_the_chain_from_genesis_in_ID_order()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 3);

        Assert.Equal(3, await SealAsync(database, TenantA));

        var rows = await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 3);
        Assert.Null(rows[0].PreviousHash);
        Assert.Equal(rows.Select(r => r.Envelope.Id).Order(), rows.Select(r => r.Envelope.Id));
        Assert.Equal(0, await UnsealedAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Later_seal_links_to_the_head()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 3);
        await SealAsync(database, TenantA);
        await AppendAsync(database, TenantA, 2);

        Assert.Equal(2, await SealAsync(database, TenantA));

        var rows = await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 5);
        Assert.Equal(rows[2].Hash, rows[3].PreviousHash);
    }

    [Fact]
    public async Task Deployment_chain_seals_in_a_Deployment_scope()
    {
        var database = await DatabaseAsync();
        await AppendAsync(database, tenantId: null, 2);

        Assert.Equal(2, await SealAsync(database, tenantId: null));

        var rows = await ChainCheck.AssertIntactAsync(Superuser(database), tenantId: null, 2);
        Assert.All(rows, r => Assert.Null(r.Envelope.TenantId));
    }

    [Fact]
    public async Task Seal_takes_at_most_the_limit_and_the_rest_follow()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 5);

        Assert.Equal(2, await SealAsync(database, TenantA, maxEvents: 2));
        Assert.Equal(3, await UnsealedAsync(database, "audit_event"));
        Assert.Equal(3, await SealAsync(database, TenantA, maxEvents: 2 + 3));

        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 5);
    }

    [Fact]
    public async Task Nothing_to_seal_changes_nothing()
    {
        var database = await DatabaseAsync(TenantA);

        Assert.Equal(0, await SealAsync(database, TenantA));
        Assert.Equal(0, await SealAsync(database, tenantId: null));

        await AppendAsync(database, TenantA, 1);
        await SealAsync(database, TenantA);
        var before = await ChainCheck.ReadAsync(Superuser(database), TenantA);

        Assert.Equal(0, await SealAsync(database, TenantA));
        Assert.Equivalent(before, await ChainCheck.ReadAsync(Superuser(database), TenantA), strict: true);
    }

    [Fact]
    public async Task Loop_seals_two_Tenants_and_the_Deployment_as_three_chains()
    {
        var database = await DatabaseAsync(TenantA, TenantB);
        await AppendAsync(database, TenantA, 3);
        await AppendAsync(database, TenantB, 2);
        await AppendAsync(database, tenantId: null, 1);

        await using var loop = Loop(TableRegistry.Sealer, database, logger: null);

        Assert.Equal(6, await loop.PassAsync(Cancellation));
        Assert.Equal(0, await loop.PassAsync(Cancellation));

        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 3);
        await ChainCheck.AssertIntactAsync(Superuser(database), TenantB, 2);
        await ChainCheck.AssertIntactAsync(Superuser(database), tenantId: null, 1);
    }

    [Fact]
    public async Task Loop_logs_a_failing_Tenant_by_ID_and_seals_the_rest()
    {
        var database = await DatabaseAsync(TenantA, TenantB);
        await AppendAsync(database, TenantA, 1);
        await AppendAsync(database, TenantB, 2);

        // Tenant B's head is at the largest seq, so its next row can't be numbered. Only a
        // superuser that skips the triggers can do this.
        await PostgresFixture.ExecuteAsync(
            Superuser(database),
            $"""
            SET session_replication_role = replica;
            UPDATE audit_event SET epoch = 1, seq = 9223372036854775807, prev_hash = '\x00', hash = '\x01'
            WHERE id = (SELECT id FROM audit_event WHERE tenant_id = '{TenantB}' ORDER BY id LIMIT 1);
            """);

        var logger = new RecordingLogger();
        await using var loop = Loop(TableRegistry.Sealer, database, logger);

        Assert.Equal(1, await loop.PassAsync(Cancellation));

        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 1);
        var line = Assert.Single(logger.Lines);
        Assert.Contains(TenantB.ToString(), line);
        Assert.Contains(nameof(OverflowException), line);
    }

    [Fact]
    public async Task Loop_on_a_connection_for_another_role_refuses_and_seals_nothing()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 1);

        await using var loop = Loop(TableRegistry.Worker, database, logger: null);

        // The exception type is internal to Operations, so its exact name stands in for it.
        var pass = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => loop.PassAsync(Cancellation));
        var run = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => loop.RunAsync(Cancellation));

        Assert.Equal("WrongJobRoleException", pass.GetType().Name);
        Assert.Equal("WrongJobRoleException", run.GetType().Name);
        Assert.Equal(1, await UnsealedAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Loop_logs_a_failing_Deployment_chain_and_seals_the_Tenants()
    {
        var database = await DatabaseAsync(TenantA, TenantB);
        await AppendAsync(database, TenantA, 1);
        await AppendAsync(database, TenantB, 1);
        await AppendAsync(database, tenantId: null, 2);

        // The Deployment head is at the largest seq, so its next row can't be numbered.
        await PostgresFixture.ExecuteAsync(
            Superuser(database),
            """
            SET session_replication_role = replica;
            UPDATE deployment_audit_event SET epoch = 1, seq = 9223372036854775807, prev_hash = '\x00', hash = '\x01'
            WHERE id = (SELECT id FROM deployment_audit_event ORDER BY id LIMIT 1);
            """);

        var logger = new RecordingLogger();
        await using var loop = Loop(TableRegistry.Sealer, database, logger);

        Assert.Equal(2, await loop.PassAsync(Cancellation));

        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 1);
        await ChainCheck.AssertIntactAsync(Superuser(database), TenantB, 1);
        Assert.Equal(1, await UnsealedAsync(database, "deployment_audit_event"));
        var line = Assert.Single(logger.Lines);
        Assert.Contains("Deployment chain", line);
        Assert.Contains(nameof(OverflowException), line);
    }

    [Fact]
    public async Task Loop_logs_a_failed_pass_and_keeps_sealing()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 1);

        var logger = new RecordingLogger();
        await using var loop = Loop(TableRegistry.Sealer, database, logger);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        var running = Task.Run(() => loop.RunAsync(stop.Token), Cancellation);

        await WaitForAsync(database, "SELECT count(*) FROM audit_event WHERE seq IS NOT NULL", 1);

        // Listing the Tenant chains now fails, so the whole pass does.
        await PostgresFixture.ExecuteAsync(Superuser(database), "REVOKE SELECT (id) ON tenant FROM gk_sealer");
        await WaitForLineAsync(logger, "seal pass failed");
        Assert.False(running.IsCompleted, "The loop stopped after an ordinary failed pass.");

        await PostgresFixture.ExecuteAsync(Superuser(database), "GRANT SELECT (id) ON tenant TO gk_sealer");
        await AppendAsync(database, TenantA, 1);
        await WaitForAsync(database, "SELECT count(*) FROM audit_event WHERE seq IS NOT NULL", 2);

        await stop.CancelAsync();
        await running.WaitAsync(Wait, Cancellation);
        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 2);
    }

    [Fact]
    public async Task Concurrent_sealers_make_one_chain_with_no_gap()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 6);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Sealer, database));

        await using (var first = await TenantScope.BeginAsync(source, TenantA, Cancellation))
        {
            Assert.Equal(2, await _sealer.SealAsync(first.CreateCommandContext(), 2, Cancellation));

            var second = SealAsync(database, TenantA);
            await WaitForAsync(
                database,
                """
                SELECT count(*) FROM pg_locks
                WHERE locktype = 'advisory' AND NOT granted
                  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
                """,
                1);
            Assert.False(second.IsCompleted);

            await first.CommitAsync(Cancellation);
            Assert.Equal(4, await second.WaitAsync(Wait, Cancellation));
        }

        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 6);
    }

    [Fact]
    public async Task Fifty_appends_during_an_open_seal_all_finish_before_it_ends()
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, TenantA, 3);
        await using var sealerSource = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Sealer, database));

        // A small pool keeps the connection count down. Appends still run while the seal holds its lock.
        var writers = new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Admin, database))
        {
            Pooling = true,
            MaxPoolSize = 10,
        };
        await using var writerSource = NpgsqlDataSource.Create(writers.ConnectionString);

        await using (var seal = await TenantScope.BeginAsync(sealerSource, TenantA, Cancellation))
        {
            Assert.Equal(3, await _sealer.SealAsync(seal.CreateCommandContext(), 500, Cancellation));

            var appends = Enumerable.Range(0, 50).Select(_ => Task.Run(async () =>
            {
                await using var scope = await TenantScope.BeginAsync(writerSource, TenantA, Cancellation);
                await _appender.AppendAsync(scope.CreateCommandContext(), Event(TenantA), null, Cancellation);
                await scope.CommitAsync(Cancellation);
            }));

            await Task.WhenAll(appends).WaitAsync(Wait, Cancellation);
            await seal.CommitAsync(Cancellation);
        }

        Assert.Equal(50, await UnsealedAsync(database, "audit_event"));
        Assert.Equal(50, await SealAsync(database, TenantA));
        await ChainCheck.AssertIntactAsync(Superuser(database), TenantA, 53);
    }

    [Theory]
    [MemberData(nameof(SealedRowChanges))]
    public async Task Sealer_cant_change_a_sealed_row(string table, string assignment)
    {
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, table == "audit_event" ? TenantA : null, 1);
        await SealAsync(database, table == "audit_event" ? TenantA : null);
        var before = await RowTextAsync(database, table);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Sealer, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"UPDATE {table} SET {assignment}";

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Contains(error.SqlState, new[] { PermissionDenied, RaisedByTrigger });
        Assert.Equal(before, await RowTextAsync(database, table));
    }

    [Theory]
    [MemberData(nameof(OtherRolesOnEachChain))]
    public async Task Other_role_cant_change_a_sealed_row(string table, string role)
    {
        var tenantId = table == "audit_event" ? TenantA : (Guid?)null;
        var database = await DatabaseAsync(TenantA);
        await AppendAsync(database, tenantId, 1);
        await SealAsync(database, tenantId);
        var before = await RowTextAsync(database, table);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"UPDATE {table} SET epoch = 2";

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Contains(error.SqlState, new[] { PermissionDenied, RaisedByTrigger });
        Assert.Equal(before, await RowTextAsync(database, table));
    }

    public static TheoryData<string, string> OtherRolesOnEachChain()
    {
        var data = new TheoryData<string, string>();
        foreach (var table in new[] { "audit_event", "deployment_audit_event" })
        {
            foreach (var role in TableRegistry.RuntimeRoles.Append(TableRegistry.Migrator).Where(r => r != TableRegistry.Sealer))
            {
                data.Add(table, role);
            }
        }

        return data;
    }

    private IAuditSealLoop Loop(string role, string database, RecordingLogger? logger) =>
        OperationsContract.CreateSealLoop(postgres.RoleConnection(role, database), TimeSpan.FromMilliseconds(50), logger);

    private string Superuser(string database) => postgres.SuperuserConnection(database);

    private async Task<string> DatabaseAsync(params Guid[] tenants)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        foreach (var tenant in tenants)
        {
            await PostgresFixture.ExecuteAsync(Superuser(database), $"INSERT INTO tenant (id) VALUES ('{tenant}')");
        }

        return database;
    }

    /// <summary>Appends through the real writer path, as <c>gk_admin</c>, one transaction each.</summary>
    private async Task AppendAsync(string database, Guid? tenantId, int count)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));

        for (var i = 0; i < count; i++)
        {
            await using CommandScope scope = tenantId is { } id
                ? await TenantScope.BeginAsync(source, id, Cancellation)
                : await DeploymentScope.BeginAsync(source, Cancellation);

            await _appender.AppendAsync(
                scope.CreateCommandContext(),
                i % 2 == 0 ? Event(tenantId ?? TenantA) : SystemEvent,
                null,
                Cancellation);
            await scope.CommitAsync(Cancellation);
        }
    }

    /// <summary>One seal in its own scope as <c>gk_sealer</c>, committed.</summary>
    private async Task<int> SealAsync(string database, Guid? tenantId, int maxEvents = 500)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Sealer, database));
        await using CommandScope scope = tenantId is { } id
            ? await TenantScope.BeginAsync(source, id, Cancellation)
            : await DeploymentScope.BeginAsync(source, Cancellation);

        var count = await _sealer.SealAsync(scope.CreateCommandContext(), maxEvents, Cancellation);
        await scope.CommitAsync(Cancellation);
        return count;
    }

    private Task<long> UnsealedAsync(string database, string table) =>
        PostgresFixture.ScalarAsync<long>(Superuser(database), $"SELECT count(*) FROM {table} WHERE seq IS NULL");

    private Task<string> RowTextAsync(string database, string table) =>
        PostgresFixture.ScalarAsync<string>(Superuser(database), $"SELECT to_jsonb(e)::text FROM {table} e");

    private static async Task WaitForLineAsync(RecordingLogger logger, string text)
    {
        var deadline = DateTimeOffset.UtcNow + Wait;

        while (!HasLine(logger, text))
        {
            Assert.True(DateTimeOffset.UtcNow < deadline, $"Timed out waiting for a log line holding: {text}");
            await Task.Delay(TimeSpan.FromMilliseconds(50), Cancellation);
        }
    }

    /// <summary>The loop logs from its own task, so a read can race a write: that read counts as not yet.</summary>
    private static bool HasLine(RecordingLogger logger, string text)
    {
        try
        {
            return logger.Lines.ToArray().Any(l => l.Contains(text, StringComparison.Ordinal));
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private async Task WaitForAsync(string database, string countSql, long expected)
    {
        var deadline = DateTimeOffset.UtcNow + Wait;

        while (await PostgresFixture.ScalarAsync<long>(Superuser(database), countSql) != expected)
        {
            Assert.True(DateTimeOffset.UtcNow < deadline, $"Timed out waiting for: {countSql}");
            await Task.Delay(TimeSpan.FromMilliseconds(50), Cancellation);
        }
    }
}
