using System.Net;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class AuditTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";
    private const string CheckViolation = "23514";
    private const string ForeignKeyViolation = "23503";
    private const string RestrictViolation = "23001";
    private const string RaisedByTrigger = "P0001";
    private const string UndefinedSetting = "42704";
    private const string InvalidUuidText = "22P02";

    private const string Email = "person@example.test";
    private const string UserAgent = "Canary-Agent/1.0";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000000b");
    private static readonly Guid EventA = Guid.Parse("01900000-0000-7000-8000-0000000000e1");
    private static readonly Guid EventB = Guid.Parse("01900000-0000-7000-8000-0000000000e2");
    private static readonly Guid EventBWithoutDetail = Guid.Parse("01900000-0000-7000-8000-0000000000e3");
    private static readonly Guid AdminId = Guid.Parse("01900000-0000-7000-8000-0000000000a1");

    private static readonly AuditDetail Detail = new(IPAddress.Parse("192.0.2.1"), UserAgent, Email);

    private static readonly string[] EventTables = ["audit_event", "deployment_audit_event"];

    private readonly IAuditAppender _appender = AuditContract.CreateAppender();

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static AuditEvent SettingsUpdated => new(
        new AuditTypeCode("tenancy.settings.updated"),
        Actor.Admin(AdminId),
        AuditTargetKind.Tenant,
        TenantA);

    public static TheoryData<string> AllRolesButTheSealer =>
        [.. TableRegistry.RuntimeRoles.Append(TableRegistry.Migrator).Where(r => r != TableRegistry.Sealer)];

    public static TheoryData<string> AllRolesButRetention =>
        [.. TableRegistry.RuntimeRoles.Append(TableRegistry.Migrator).Where(r => r != TableRegistry.Retention)];

    public static TheoryData<string, string> TenantAuditReaders => TenantAuditRoles("SELECT");

    public static TheoryData<string, string> TenantAuditInserters => TenantAuditRoles("INSERT");

    public static TheoryData<string, ActorKind> ActorKinds => EveryKindOnEveryChain<ActorKind>();

    public static TheoryData<string, AuditTargetKind> TargetKinds => EveryKindOnEveryChain<AuditTargetKind>();

    [Fact]
    public async Task Tenant_command_commits_state_event_and_detail_together()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await using (var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation))
        {
            var context = scope.CreateCommandContext();
            await InsertSettingsAsync(context);
            await _appender.AppendAsync(context, SettingsUpdated, Detail, Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(1, await CountAsync(database, "tenant_settings"));
        Assert.Equal(1, await CountAsync(database, "audit_event"));
        Assert.Equal(1, await CountAsync(database, "audit_detail"));
        Assert.Equal(0, await CountAsync(database, "deployment_audit_event"));

        var stored = await TextAsync(
            database,
            """
            SELECT concat_ws('|', e.tenant_id, e.type_code, e.actor_kind, e.actor_id, e.target_kind, e.target_id,
                             host(d.ip_address), d.user_agent, d.email)
            FROM audit_event e JOIN audit_detail d ON d.tenant_id = e.tenant_id AND d.event_id = e.id
            """);

        Assert.Equal(
            $"{TenantA}|tenancy.settings.updated|admin|{AdminId}|tenant|{TenantA}|192.0.2.1|{UserAgent}|{Email}",
            stored);
    }

    [Fact]
    public async Task Tenant_command_rollback_leaves_nothing()
    {
        var database = await TenantDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await using (var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation))
        {
            var context = scope.CreateCommandContext();
            await InsertSettingsAsync(context);
            await _appender.AppendAsync(context, SettingsUpdated, Detail, Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "tenant_settings"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));
        Assert.Equal(0, await CountAsync(database, "audit_detail"));
    }

    [Fact]
    public async Task Appending_with_no_detail_writes_only_the_event()
    {
        var database = await TenantDatabaseAsync();
        await AppendTenantEventAsync(database, TableRegistry.Hosted, new AuditEvent(
            new AuditTypeCode("auth.signin.failed"), Actor.Anonymous), null);

        Assert.Equal(1, await CountAsync(database, "audit_event"));
        Assert.Equal(0, await CountAsync(database, "audit_detail"));
    }

    [Fact]
    public async Task Event_IDs_are_version_7_and_the_time_is_assigned()
    {
        var database = await TenantDatabaseAsync();
        await AppendTenantEventAsync(database, TableRegistry.Admin, SettingsUpdated, null);

        Assert.Equal("7", await TextAsync(database, "SELECT uuid_extract_version(id)::text FROM audit_event"));
        Assert.Equal(
            "true",
            await TextAsync(database, "SELECT (now() - occurred_at < interval '1 minute')::text FROM audit_event"));
    }

    [Fact]
    public async Task Deployment_command_writes_the_Deployment_chain_with_detail_apart()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await using (var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation))
        {
            var context = scope.CreateCommandContext();
            Assert.Null(context.TenantId);

            await _appender.AppendAsync(
                context, new AuditEvent(new AuditTypeCode("bootstrap.admin.created"), Actor.System), Detail, Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(1, await CountAsync(database, "deployment_audit_event"));
        Assert.Equal(1, await CountAsync(database, "deployment_audit_detail"));
        Assert.Equal(0, await CountAsync(database, "audit_event"));

        var envelope = await TextAsync(database, "SELECT to_jsonb(e)::text FROM deployment_audit_event e");
        Assert.DoesNotContain(Email, envelope);
        Assert.DoesNotContain(UserAgent, envelope);
        Assert.DoesNotContain("192.0.2.1", envelope);

        Assert.Equal(Email, await TextAsync(database, "SELECT email FROM deployment_audit_detail"));
    }

    [Fact]
    public async Task Deployment_command_rollback_leaves_nothing()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);

        await using (var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation))
        {
            await _appender.AppendAsync(
                scope.CreateCommandContext(),
                new AuditEvent(new AuditTypeCode("bootstrap.admin.created"), Actor.System),
                Detail,
                Cancellation);
        }

        Assert.Equal(0, await CountAsync(database, "deployment_audit_event"));
        Assert.Equal(0, await CountAsync(database, "deployment_audit_detail"));
    }

    [Fact]
    public async Task Tenant_table_in_a_Deployment_scope_is_refused_on_a_fresh_connection()
    {
        var database = await SeededSettingsDatabaseAsync();
        await using var dataSource = Source(TableRegistry.Admin, database);
        await using var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation);

        var error = await RunExpectingErrorAsync(scope, "SELECT count(*) FROM tenant_settings");

        Assert.Equal(UndefinedSetting, error.SqlState);
    }

    [Fact]
    public async Task Tenant_table_in_a_Deployment_scope_is_refused_on_a_reused_connection()
    {
        var database = await SeededSettingsDatabaseAsync();
        var builder = new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Admin, database))
        {
            Pooling = true,
            MaxPoolSize = 1,
        };
        await using var dataSource = NpgsqlDataSource.Create(builder.ConnectionString);

        await using (var tenantScope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation))
        {
            await tenantScope.CommitAsync(Cancellation);
        }

        await using var scope = await DeploymentScope.BeginAsync(dataSource, Cancellation);

        var error = await RunExpectingErrorAsync(scope, "SELECT count(*) FROM tenant_settings");

        Assert.Equal(InvalidUuidText, error.SqlState);
    }

    [Theory]
    [InlineData("SELECT count(*) FROM deployment_audit_event")]
    [InlineData("SELECT count(*) FROM deployment_audit_detail")]
    [InlineData("INSERT INTO deployment_audit_event (id, type_code, actor_kind) VALUES (gen_random_uuid(), 'a.b.c', 'system')")]
    [InlineData("INSERT INTO deployment_audit_detail (event_id) VALUES (gen_random_uuid())")]
    public async Task Hosted_role_has_no_access_to_Deployment_tables(string statement)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var error = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Hosted, database), statement));

        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Theory]
    [InlineData("SELECT count(*) FROM audit_event")]
    [InlineData("SELECT count(*) FROM audit_detail")]
    public async Task Hosted_role_can_append_but_not_read(string statement)
    {
        var database = await TenantDatabaseAsync();
        await AppendTenantEventAsync(database, TableRegistry.Hosted, SettingsUpdated, Detail);

        await using var dataSource = Source(TableRegistry.Hosted, database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);

        var error = await RunExpectingErrorAsync(scope, statement);

        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Theory]
    [MemberData(nameof(AllRolesButTheSealer))]
    public async Task Update_of_audit_event_is_refused(string role)
    {
        var database = await EventDatabaseAsync();
        var before = await EventRowAsync(database, "audit_event");

        var error = await RunScopedExpectingErrorAsync(role, database, "UPDATE audit_event SET occurred_at = now()");

        AssertRefused(error);
        Assert.Equal(before, await EventRowAsync(database, "audit_event"));
    }

    [Theory]
    [MemberData(nameof(AllRolesButTheSealer))]
    public async Task Update_of_deployment_audit_event_is_refused(string role)
    {
        var database = await EventDatabaseAsync();
        var before = await EventRowAsync(database, "deployment_audit_event");

        var error = await RunScopedExpectingErrorAsync(role, database, "UPDATE deployment_audit_event SET occurred_at = now()");

        AssertRefused(error);
        Assert.Equal(before, await EventRowAsync(database, "deployment_audit_event"));
    }

    [Theory]
    [MemberData(nameof(AllRolesButRetention))]
    public async Task Delete_of_audit_event_is_refused(string role)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(role, database, "DELETE FROM audit_event");

        AssertRefused(error);
        Assert.Equal(1, await CountAsync(database, "audit_event"));
    }

    [Theory]
    [MemberData(nameof(AllRolesButRetention))]
    public async Task Delete_of_deployment_audit_event_is_refused(string role)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(role, database, "DELETE FROM deployment_audit_event");

        AssertRefused(error);
        Assert.Equal(1, await CountAsync(database, "deployment_audit_event"));
    }

    [Theory]
    [InlineData("audit_event, audit_detail")]
    [InlineData("deployment_audit_event, deployment_audit_detail")]
    [InlineData("audit_detail")]
    [InlineData("deployment_audit_detail")]
    public async Task Owner_cant_truncate(string tables)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Migrator, database, $"TRUNCATE {tables}");

        Assert.Equal(RaisedByTrigger, error.SqlState);
    }

    [Theory]
    [InlineData("UPDATE audit_detail SET email = 'x'")]
    [InlineData("UPDATE deployment_audit_detail SET email = 'x'")]
    [InlineData("DELETE FROM audit_detail")]
    [InlineData("DELETE FROM deployment_audit_detail")]
    public async Task Owner_cant_change_detail(string statement)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Migrator, database, statement);

        Assert.Equal(RaisedByTrigger, error.SqlState);
    }

    [Theory]
    [InlineData("UPDATE audit_event SET type_code = 'x.y.z'")]
    [InlineData("UPDATE audit_event SET tenant_id = gen_random_uuid()")]
    [InlineData("UPDATE deployment_audit_event SET type_code = 'x.y.z'")]
    public async Task Sealer_cant_change_the_envelope(string statement)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Sealer, database, statement);

        Assert.Equal(PermissionDenied, error.SqlState);
    }

    [Theory]
    [InlineData("audit_event")]
    [InlineData("deployment_audit_event")]
    public async Task Sealer_seals_once_and_cant_reseal(string table)
    {
        var database = await EventDatabaseAsync();
        var seal = $"UPDATE {table} SET epoch = 1, seq = 1, hash = '\\x01'";

        await RunScopedAsync(TableRegistry.Sealer, database, seal);
        Assert.Equal("1", await TextAsync(database, $"SELECT seq::text FROM {table}"));

        var error = await RunScopedExpectingErrorAsync(
            TableRegistry.Sealer, database, $"UPDATE {table} SET epoch = 1, seq = 2, prev_hash = '\\x01', hash = '\\x02'");

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Contains("already sealed", error.MessageText);
    }

    [Fact]
    public async Task Sealer_with_a_stray_column_grant_still_cant_change_the_envelope()
    {
        var database = await EventDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), "GRANT UPDATE (type_code) ON audit_event TO gk_sealer");

        var error = await RunScopedExpectingErrorAsync(
            TableRegistry.Sealer, database, "UPDATE audit_event SET type_code = 'x.y.z'");

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Contains("immutable", error.MessageText);
    }

    [Fact]
    public async Task Retention_deletes_detail_and_then_the_event()
    {
        var database = await EventDatabaseAsync();
        await SealAsync(database, "audit_event");

        var blocked = await RunScopedExpectingErrorAsync(TableRegistry.Retention, database, "DELETE FROM audit_event");
        Assert.Equal(RestrictViolation, blocked.SqlState);

        await RunScopedAsync(TableRegistry.Retention, database, "DELETE FROM audit_detail");
        await RunScopedAsync(TableRegistry.Retention, database, "DELETE FROM audit_event");

        Assert.Equal(0, await CountAsync(database, "audit_event"));
    }

    [Fact]
    public async Task Retention_deletes_Deployment_detail_and_then_the_event()
    {
        var database = await EventDatabaseAsync();
        await SealAsync(database, "deployment_audit_event");

        await RunScopedAsync(TableRegistry.Retention, database, "DELETE FROM deployment_audit_detail");
        await RunScopedAsync(TableRegistry.Retention, database, "DELETE FROM deployment_audit_event");

        Assert.Equal(0, await CountAsync(database, "deployment_audit_event"));
    }

    [Theory]
    [InlineData("audit_event", "audit_detail")]
    [InlineData("deployment_audit_event", "deployment_audit_detail")]
    public async Task Retention_cant_delete_an_unsealed_event(string table, string detailTable)
    {
        var database = await EventDatabaseAsync();
        await RunScopedAsync(TableRegistry.Retention, database, $"DELETE FROM {detailTable}");

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Retention, database, $"DELETE FROM {table}");

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Contains("unsealed", error.MessageText);
        Assert.Equal(1, await CountAsync(database, table));
    }

    [Theory]
    [InlineData("audit_event", "seq = 1")]
    [InlineData("audit_event", "hash = '\\x01'")]
    [InlineData("audit_event", "prev_hash = '\\x00'")]
    [InlineData("audit_event", "prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("deployment_audit_event", "seq = 1")]
    [InlineData("deployment_audit_event", "hash = '\\x01'")]
    [InlineData("deployment_audit_event", "prev_hash = '\\x00'")]
    [InlineData("deployment_audit_event", "prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("audit_event", "epoch = 1")]
    [InlineData("audit_event", "seq = 1, hash = '\\x01'")]
    [InlineData("deployment_audit_event", "epoch = 1")]
    [InlineData("deployment_audit_event", "seq = 1, hash = '\\x01'")]
    public async Task Partial_seal_is_refused(string table, string assignment)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Sealer, database, $"UPDATE {table} SET {assignment}");

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Theory]
    [InlineData("audit_event")]
    [InlineData("deployment_audit_event")]
    public async Task Genesis_row_can_keep_a_null_prev_hash(string table)
    {
        var database = await EventDatabaseAsync();

        await RunScopedAsync(TableRegistry.Sealer, database, $"UPDATE {table} SET epoch = 1, seq = 1, hash = '\\x01'");

        Assert.Equal("1", await TextAsync(database, $"SELECT seq::text FROM {table}"));
    }

    [Theory]
    [InlineData("audit_event", "epoch = 1, seq = 1, prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("audit_event", "epoch = 1, seq = 2, hash = '\\x01'")]
    [InlineData("audit_event", "epoch = 1, seq = 0, prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("audit_event", "epoch = 0, seq = 2, prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("deployment_audit_event", "epoch = 1, seq = 1, prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("deployment_audit_event", "epoch = 1, seq = 2, hash = '\\x01'")]
    [InlineData("deployment_audit_event", "epoch = 1, seq = 0, prev_hash = '\\x00', hash = '\\x01'")]
    [InlineData("deployment_audit_event", "epoch = 0, seq = 2, prev_hash = '\\x00', hash = '\\x01'")]
    public async Task Seal_off_the_chain_shape_is_refused(string table, string assignment)
    {
        var database = await EventDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Sealer, database, $"UPDATE {table} SET {assignment}");

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Theory]
    [InlineData("audit_event", "epoch = 2")]
    [InlineData("audit_event", "seq = 2")]
    [InlineData("audit_event", "hash = '\\x02'")]
    [InlineData("deployment_audit_event", "epoch = 2")]
    [InlineData("deployment_audit_event", "seq = 2")]
    [InlineData("deployment_audit_event", "hash = '\\x02'")]
    public async Task Sealer_cant_change_a_seal_column_once_sealed(string table, string assignment)
    {
        var database = await EventDatabaseAsync();
        await SealAsync(database, table);

        var error = await RunScopedExpectingErrorAsync(TableRegistry.Sealer, database, $"UPDATE {table} SET {assignment}");

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Contains("already sealed", error.MessageText);
    }

    [Theory]
    [InlineData("audit_event", "seq", "1")]
    [InlineData("audit_event", "prev_hash", "'\\x00'")]
    [InlineData("audit_event", "hash", "'\\x01'")]
    [InlineData("deployment_audit_event", "seq", "1")]
    [InlineData("deployment_audit_event", "prev_hash", "'\\x00'")]
    [InlineData("deployment_audit_event", "hash", "'\\x01'")]
    [InlineData("audit_event", "epoch", "1")]
    [InlineData("deployment_audit_event", "epoch", "1")]
    public async Task Insert_with_a_seal_column_is_refused(string table, string column, string value)
    {
        var database = await TenantDatabaseAsync();

        var error = await RunScopedExpectingErrorAsync(
            TableRegistry.Admin,
            database,
            InsertEvent(table, $"type_code, actor_kind, {column}", $"'a.b.c', 'system', {value}"));

        Assert.Equal(RaisedByTrigger, error.SqlState);
        Assert.Equal(0, await CountAsync(database, table));
    }

    [Theory]
    [InlineData("audit_event")]
    [InlineData("deployment_audit_event")]
    public async Task Supplied_time_is_replaced_on_insert(string table)
    {
        var database = await TenantDatabaseAsync();

        await RunScopedAsync(
            TableRegistry.Admin,
            database,
            InsertEvent(table, "type_code, actor_kind, occurred_at", "'a.b.c', 'system', '2000-01-01'"));

        Assert.Equal(
            "true",
            await TextAsync(database, $"SELECT (now() - occurred_at < interval '1 minute')::text FROM {table}"));
    }

    [Theory]
    [InlineData("audit_event", "tenant_id,id,occurred_at,type_code,actor_kind,actor_id,target_kind,target_id,seq,prev_hash,hash,epoch,checkpoint_epoch,checkpoint_seq,checkpoint_hash")]
    [InlineData("deployment_audit_event", "id,occurred_at,type_code,actor_kind,actor_id,target_kind,target_id,seq,prev_hash,hash,epoch,checkpoint_epoch,checkpoint_seq,checkpoint_hash")]
    public async Task Event_tables_have_exactly_these_columns(string table, string columns)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var actual = await TextAsync(
            database,
            $"""
            SELECT string_agg(column_name, ',' ORDER BY ordinal_position)
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = '{table}'
            """);

        Assert.Equal(columns, actual);
    }

    [Theory]
    [MemberData(nameof(TenantAuditReaders))]
    public async Task Role_in_one_Tenant_cant_see_another_Tenants_audit_rows(string table, string role)
    {
        var database = await TwoTenantDatabaseAsync();
        await using var dataSource = Source(role, database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"SELECT DISTINCT tenant_id FROM {table}";

        var seen = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        while (await reader.ReadAsync(Cancellation))
        {
            seen.Add(reader.GetGuid(0));
        }

        Assert.Equal([TenantA], seen);
    }

    [Theory]
    [MemberData(nameof(TenantAuditInserters))]
    public async Task Role_in_one_Tenant_cant_insert_audit_rows_for_another(string table, string role)
    {
        var database = await TwoTenantDatabaseAsync();
        var before = await CountAsync(database, table);
        var statement = table == "audit_event"
            ? $"INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{TenantB}', gen_random_uuid(), 'a.b.c', 'system')"
            : $"INSERT INTO audit_detail (tenant_id, event_id) VALUES ('{TenantB}', '{EventBWithoutDetail}')";

        var error = await RunScopedExpectingErrorAsync(role, database, statement);

        Assert.Equal(PermissionDenied, error.SqlState);
        Assert.Equal(before, await CountAsync(database, table));
    }

    [Theory]
    [MemberData(nameof(ActorKinds))]
    public async Task Every_actor_kind_is_stored_on_both_chains(string table, ActorKind kind)
    {
        var database = await TenantDatabaseAsync();
        var actor = kind switch
        {
            ActorKind.System => Actor.System,
            ActorKind.Anonymous => Actor.Anonymous,
            ActorKind.Admin => Actor.Admin(AdminId),
            ActorKind.User => Actor.User(AdminId),
            ActorKind.Client => Actor.Client(AdminId),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };

        await AppendOnChainAsync(database, table, new AuditEvent(new AuditTypeCode("a.b.c"), actor), null);

        Assert.Equal(kind.ToString().ToLowerInvariant(), await TextAsync(database, $"SELECT actor_kind FROM {table}"));
    }

    [Theory]
    [MemberData(nameof(TargetKinds))]
    public async Task Every_target_kind_is_stored_on_both_chains(string table, AuditTargetKind kind)
    {
        var database = await TenantDatabaseAsync();

        await AppendOnChainAsync(
            database, table, new AuditEvent(new AuditTypeCode("a.b.c"), Actor.System, kind, TenantA), null);

        Assert.Equal(kind.ToString().ToLowerInvariant(), await TextAsync(database, $"SELECT target_kind FROM {table}"));
    }

    [Theory]
    [InlineData("fe80::1%4", "fe80::1")]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    [InlineData("192.0.2.1", "192.0.2.1")]
    public async Task Address_is_stored_normalised_on_both_chains(string address, string expected)
    {
        var database = await TenantDatabaseAsync();

        foreach (var table in EventTables)
        {
            await AppendOnChainAsync(
                database,
                table,
                new AuditEvent(new AuditTypeCode("a.b.c"), Actor.System),
                new AuditDetail(IPAddress.Parse(address), null, null));

            Assert.Equal(expected, await TextAsync(database, $"SELECT host(ip_address) FROM {DetailTable(table)}"));
        }
    }

    [Theory]
    [InlineData("2001:db8::1", null, null, "2001:db8::1|-|-")]
    [InlineData(null, UserAgent, null, "-|" + UserAgent + "|-")]
    [InlineData(null, null, Email, "-|-|" + Email)]
    [InlineData(null, null, null, "-|-|-")]
    public async Task Partly_null_detail_is_stored_on_both_chains(
        string? address,
        string? userAgent,
        string? email,
        string expected)
    {
        var database = await TenantDatabaseAsync();

        foreach (var table in EventTables)
        {
            await AppendOnChainAsync(
                database,
                table,
                new AuditEvent(new AuditTypeCode("a.b.c"), Actor.System),
                new AuditDetail(address is null ? null : IPAddress.Parse(address), userAgent, email));

            var stored = await TextAsync(
                database,
                $"""
                SELECT concat_ws('|', coalesce(host(ip_address), '-'), coalesce(user_agent, '-'), coalesce(email, '-'))
                FROM {DetailTable(table)}
                """);

            Assert.Equal(expected, stored);
        }
    }

    [Theory]
    [InlineData("audit_detail")]
    [InlineData("deployment_audit_detail")]
    public async Task Worker_erases_detail_and_the_envelope_stays(string table)
    {
        var database = await EventDatabaseAsync();

        await RunScopedAsync(TableRegistry.Worker, database, $"DELETE FROM {table}");

        Assert.Equal(0, await CountAsync(database, table));
        Assert.Equal(1, await CountAsync(database, "audit_event"));
        Assert.Equal(1, await CountAsync(database, "deployment_audit_event"));
    }

    [Theory]
    [InlineData("Bad.Code")]
    [InlineData("two.segments")]
    [InlineData("four.whole.segments.here")]
    [InlineData("has space.in.it")]
    [InlineData("a..b")]
    [InlineData(".a.b")]
    [InlineData("a.b.c\n")]
    [InlineData("1a.b.c")]
    [InlineData("")]
    public void Bad_type_code_is_refused_in_code(string code)
    {
        Assert.Throws<ArgumentException>(() => new AuditTypeCode(code));
    }

    [Fact]
    public void Type_code_is_limited_to_128_characters()
    {
        Assert.Equal(128, new AuditTypeCode(CodeOfLength(128)).Value.Length);
        Assert.Throws<ArgumentException>(() => new AuditTypeCode(CodeOfLength(129)));
    }

    [Theory]
    [InlineData("audit_event")]
    [InlineData("deployment_audit_event")]
    public async Task Type_code_is_limited_to_128_characters_in_SQL(string table)
    {
        var database = await TenantDatabaseAsync();
        var insert = (int length) => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            InsertEvent(table, "type_code, actor_kind", $"'{CodeOfLength(length)}', 'system'"));

        await insert(128);

        var error = await Assert.ThrowsAsync<PostgresException>(() => insert(129));

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Theory]
    [InlineData("auth.signin.failed")]
    [InlineData("user.email_change.requested")]
    [InlineData("a1.b2.c3")]
    public void Good_type_code_is_accepted(string code)
    {
        Assert.Equal(code, new AuditTypeCode(code).ToString());
    }

    [Theory]
    [InlineData("Bad.Code")]
    [InlineData("two.segments")]
    [InlineData("four.whole.segments.here")]
    [InlineData("a.b.c\n")]
    public async Task Bad_type_code_is_refused_in_SQL(string code)
    {
        var database = await TenantDatabaseAsync();

        foreach (var insert in new[]
        {
            $"INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{TenantA}', gen_random_uuid(), @code, 'system')",
            "INSERT INTO deployment_audit_event (id, type_code, actor_kind) VALUES (gen_random_uuid(), @code, 'system')",
        })
        {
            await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
            await connection.OpenAsync(Cancellation);
            await using var command = new NpgsqlCommand(insert, connection);
            command.Parameters.AddWithValue("code", code);

            var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

            Assert.Equal(CheckViolation, error.SqlState);
        }
    }

    [Theory]
    // System and anonymous have no ID, and the others need one.
    [InlineData("actor_kind, actor_id", "'system', gen_random_uuid()")]
    [InlineData("actor_kind, actor_id", "'anonymous', gen_random_uuid()")]
    [InlineData("actor_kind, actor_id", "'admin', NULL")]
    [InlineData("actor_kind", "'robot'")]
    // A target is both or neither.
    [InlineData("actor_kind, target_kind", "'system', 'user'")]
    [InlineData("actor_kind, target_id", "'system', gen_random_uuid()")]
    [InlineData("actor_kind, target_kind, target_id", "'system', 'robot', gen_random_uuid()")]
    public async Task Malformed_actor_or_target_is_refused_in_SQL(string columns, string values)
    {
        var database = await TenantDatabaseAsync();

        foreach (var table in EventTables)
        {
            var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
                postgres.SuperuserConnection(database),
                InsertEvent(table, $"type_code, {columns}", $"'a.b.c', {values}")));

            Assert.Equal(CheckViolation, error.SqlState);
        }
    }

    [Fact]
    public void Actor_with_an_ID_kind_needs_a_real_ID()
    {
        Assert.Throws<ArgumentException>(() => Actor.Admin(Guid.Empty));
        Assert.Throws<ArgumentException>(() => Actor.User(Guid.Empty));
        Assert.Throws<ArgumentException>(() => Actor.Client(Guid.Empty));
    }

    [Fact]
    public void Target_needs_both_kind_and_ID()
    {
        var code = new AuditTypeCode("a.b.c");

        Assert.Throws<ArgumentException>(() => new AuditEvent(code, Actor.System, AuditTargetKind.User));
        Assert.Throws<ArgumentException>(() => new AuditEvent(code, Actor.System, null, TenantA));
        Assert.Throws<ArgumentException>(() => new AuditEvent(code, Actor.System, AuditTargetKind.User, Guid.Empty));
    }

    [Fact]
    public void Detail_prints_no_personal_data()
    {
        var printed = Detail.ToString();

        Assert.DoesNotContain(Email, printed);
        Assert.DoesNotContain(UserAgent, printed);
        Assert.DoesNotContain("192.0.2.1", printed);
    }

    [Fact]
    public async Task Detail_of_another_Tenant_cant_point_at_an_event()
    {
        var database = await EventDatabaseAsync();
        var other = Guid.NewGuid();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), TestTenants.InsertSql(other));

        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO audit_detail (tenant_id, event_id) VALUES ('{other}', '{EventA}')"));

        // The superuser passes row-level security, so this shows the composite key alone refuses it.
        Assert.Equal(ForeignKeyViolation, error.SqlState);
    }

    private const string Unchanged = "a.b.c";

    private static void AssertRefused(PostgresException error) =>
        Assert.Contains(error.SqlState, new[] { PermissionDenied, RaisedByTrigger });

    private static TheoryData<string, string> TenantAuditRoles(string privilege)
    {
        var data = new TheoryData<string, string>();
        foreach (var table in new[] { "audit_event", "audit_detail" })
        {
            var grants = TableRegistry.Tables.Single(t => t.Name == table).Grants;
            foreach (var role in grants.Where(g => g.Value.Contains(privilege)).Select(g => g.Key))
            {
                data.Add(table, role);
            }
        }

        return data;
    }

    private static TheoryData<string, TKind> EveryKindOnEveryChain<TKind>()
        where TKind : struct, Enum
    {
        var data = new TheoryData<string, TKind>();
        foreach (var table in EventTables)
        {
            foreach (var kind in Enum.GetValues<TKind>())
            {
                data.Add(table, kind);
            }
        }

        return data;
    }

    private static string DetailTable(string eventTable) => eventTable.Replace("_event", "_detail");

    private static string CodeOfLength(int length) => "a.b." + new string('c', length - 4);

    private static string InsertEvent(string table, string columns, string values) =>
        table == "audit_event"
            ? $"INSERT INTO audit_event (tenant_id, id, {columns}) VALUES ('{TenantA}', gen_random_uuid(), {values})"
            : $"INSERT INTO deployment_audit_event (id, {columns}) VALUES (gen_random_uuid(), {values})";

    private NpgsqlDataSource Source(string role, string database) =>
        NpgsqlDataSource.Create(postgres.RoleConnection(role, database));

    private async Task<string> TenantDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA));
        return database;
    }

    private async Task<string> SeededSettingsDatabaseAsync()
    {
        var database = await TenantDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')");
        return database;
    }

    /// <summary>One unsealed row with detail in each chain.</summary>
    private async Task<string> EventDatabaseAsync()
    {
        var database = await TenantDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{TenantA}', '{EventA}', '{Unchanged}', 'system');
            INSERT INTO audit_detail (tenant_id, event_id, email) VALUES ('{TenantA}', '{EventA}', '{Email}');
            INSERT INTO deployment_audit_event (id, type_code, actor_kind) VALUES ('{EventA}', '{Unchanged}', 'system');
            INSERT INTO deployment_audit_detail (event_id, email) VALUES ('{EventA}', '{Email}');
            """);
        return database;
    }

    private Task<string> EventRowAsync(string database, string table) =>
        TextAsync(database, $"SELECT to_jsonb(e)::text FROM {table} e");

    /// <summary><see cref="EventDatabaseAsync"/> plus Tenant B, with one event that has detail and one that has none.</summary>
    private async Task<string> TwoTenantDatabaseAsync()
    {
        var database = await EventDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            {TestTenants.InsertSql(TenantB)};
            INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{TenantB}', '{EventB}', '{Unchanged}', 'system');
            INSERT INTO audit_event (tenant_id, id, type_code, actor_kind) VALUES ('{TenantB}', '{EventBWithoutDetail}', '{Unchanged}', 'system');
            INSERT INTO audit_detail (tenant_id, event_id, email) VALUES ('{TenantB}', '{EventB}', '{Email}');
            """);
        return database;
    }

    private Task SealAsync(string database, string table) =>
        RunScopedAsync(TableRegistry.Sealer, database, $"UPDATE {table} SET epoch = 1, seq = 1, hash = '\\x01'");

    private async Task AppendOnChainAsync(string database, string eventTable, AuditEvent auditEvent, AuditDetail? detail)
    {
        await using var dataSource = Source(TableRegistry.Admin, database);
        await using CommandScope scope = eventTable == "audit_event"
            ? await TenantScope.BeginAsync(dataSource, TenantA, Cancellation)
            : await DeploymentScope.BeginAsync(dataSource, Cancellation);

        await _appender.AppendAsync(scope.CreateCommandContext(), auditEvent, detail, Cancellation);
        await scope.CommitAsync(Cancellation);
    }

    private async Task AppendTenantEventAsync(string database, string role, AuditEvent auditEvent, AuditDetail? detail)
    {
        await using var dataSource = Source(role, database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await _appender.AppendAsync(scope.CreateCommandContext(), auditEvent, detail, Cancellation);
        await scope.CommitAsync(Cancellation);
    }

    private static async Task InsertSettingsAsync(CommandContext context)
    {
        await using var command = context.CreateCommand();
        command.CommandText = $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')";
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    /// <summary>Runs in a Tenant scope, so a refusal comes from the grant or trigger and not from RLS.</summary>
    private async Task RunScopedAsync(string role, string database, string statement)
    {
        await using var dataSource = Source(role, database);
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = statement;
        await command.ExecuteNonQueryAsync(Cancellation);
        await scope.CommitAsync(Cancellation);
    }

    private Task<PostgresException> RunScopedExpectingErrorAsync(string role, string database, string statement) =>
        Assert.ThrowsAsync<PostgresException>(() => RunScopedAsync(role, database, statement));

    private static async Task<PostgresException> RunExpectingErrorAsync(CommandScope scope, string statement)
    {
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = statement;
        return await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
    }

    /// <summary>Reads as the superuser, which row-level security doesn't limit.</summary>
    private Task<long> CountAsync(string database, string table) =>
        PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), $"SELECT count(*) FROM {table}");

    private Task<string> TextAsync(string database, string sql) =>
        PostgresFixture.ScalarAsync<string>(postgres.SuperuserConnection(database), sql);
}
