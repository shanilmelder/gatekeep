using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class TenantBehaviourTests(PostgresFixture postgres)
{
    private const string UndefinedSetting = "42704";
    private const string InvalidUuidText = "22P02";
    private const string RowSecurityOrPermission = "42501";
    private const string CheckViolation = "23514";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000000b");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>Every runtime role the registry grants any access to <c>tenant_settings</c>.</summary>
    public static TheoryData<string> RolesWithSettings =>
        [.. TableRegistry.Tables.Single(t => t.Name == "tenant_settings").Grants.Keys];

    [Theory]
    [MemberData(nameof(RolesWithSettings))]
    public async Task Scoped_role_sees_its_own_row_and_no_other_Tenants(string role)
    {
        var database = await SeededDatabaseAsync();
        await using var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));

        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = "SELECT tenant_id FROM tenant_settings";

        var seen = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        while (await reader.ReadAsync(Cancellation))
        {
            seen.Add(reader.GetGuid(0));
        }

        Assert.Equal([TenantA], seen);
    }

    [Theory]
    [InlineData("INSERT INTO tenant_settings (tenant_id) VALUES ('{0}')", true)]
    [InlineData("UPDATE tenant_settings SET tenant_id = '{0}'", false)]
    public async Task Scoped_write_to_another_Tenant_is_refused(string statement, bool removeTargetRow)
    {
        var database = await SeededDatabaseAsync();
        if (removeTargetRow)
        {
            // So the insert fails on the policy, not on the primary key.
            await PostgresFixture.ExecuteAsync(
                postgres.SuperuserConnection(database), $"DELETE FROM tenant_settings WHERE tenant_id = '{TenantB}'");
        }

        await using var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = string.Format(statement, TenantB);

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Equal(RowSecurityOrPermission, error.SqlState);
        Assert.Contains("row-level security", error.MessageText);
    }

    [Fact]
    public async Task Update_cant_reach_another_Tenants_row()
    {
        var database = await SeededDatabaseAsync();
        await using var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"UPDATE tenant_settings SET updated_at = now() WHERE tenant_id = '{TenantB}'";

        Assert.Equal(0, await command.ExecuteNonQueryAsync(Cancellation));
    }

    [Theory]
    [MemberData(nameof(RolesWithSettings))]
    public async Task Unscoped_query_on_a_fresh_connection_raises_an_error(string role)
    {
        var database = await SeededDatabaseAsync();
        await using var connection = new NpgsqlConnection(postgres.RoleConnection(role, database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand("SELECT count(*) FROM tenant_settings", connection);

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync(Cancellation));

        Assert.Equal(UndefinedSetting, error.SqlState);
    }

    [Fact]
    public async Task Unscoped_query_on_a_reused_connection_raises_an_error()
    {
        var database = await SeededDatabaseAsync();
        var pooled = new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Hosted, database))
        {
            Pooling = true,
            MaxPoolSize = 1,
            // The pool's reset would hide a session-level setting.
            NoResetOnClose = true,
        };
        await using var dataSource = NpgsqlDataSource.Create(pooled.ConnectionString);

        int scopedBackend;
        await using (var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation))
        {
            await using var backend = scope.CreateCommandContext().CreateCommand();
            backend.CommandText = "SELECT pg_backend_pid()";
            scopedBackend = (int)(await backend.ExecuteScalarAsync(Cancellation))!;
            await scope.CommitAsync(Cancellation);
        }

        await using var connection = await dataSource.OpenConnectionAsync(Cancellation);
        Assert.Equal(scopedBackend, connection.ProcessID);

        await using var command = new NpgsqlCommand("SELECT count(*) FROM tenant_settings", connection);
        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync(Cancellation));

        Assert.Equal(InvalidUuidText, error.SqlState);
    }

    [Theory]
    [InlineData("Acme.example", "subdomain")]
    [InlineData("", "subdomain")]
    [InlineData("acme.example", "custom")]
    public async Task Tenant_host_refuses_values_exact_matching_cant_rely_on(string host, string kind)
    {
        var database = await SeededDatabaseAsync();

        var error = await Assert.ThrowsAsync<PostgresException>(() => InsertHostAsync(database, host, kind));

        Assert.Equal(CheckViolation, error.SqlState);
    }

    [Fact]
    public async Task Tenant_host_accepts_a_lower_case_subdomain()
    {
        var database = await SeededDatabaseAsync();

        await InsertHostAsync(database, "acme.example", "subdomain");
    }

    [Fact]
    public async Task Known_limit_an_unscoped_query_the_planner_proves_empty_returns_nothing()
    {
        var database = await SeededDatabaseAsync();

        // The policy expression never runs, so the failing cast can't fire, though rows exist.
        var count = await PostgresFixture.ScalarAsync<long>(
            postgres.RoleConnection(TableRegistry.Hosted, database),
            "SELECT count(*) FROM tenant_settings WHERE false");

        Assert.Equal(0, count);
    }

    [Fact]
    public async Task Unscoped_query_on_an_empty_table_raises_while_planning_on_this_engine()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        // The planner evaluates the setting to estimate selectivity, so no row is needed.
        // That's engine behaviour, not a guarantee: this pins it on the tested version.
        var error = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ScalarAsync<long>(
            postgres.RoleConnection(TableRegistry.Hosted, database), "SELECT count(*) FROM tenant_settings"));

        Assert.Equal(UndefinedSetting, error.SqlState);
    }

    [Theory]
    [InlineData(TableRegistry.Hosted, "INSERT INTO tenant_settings (tenant_id) VALUES ('{0}')")]
    [InlineData(TableRegistry.Hosted, "UPDATE tenant_settings SET updated_at = now()")]
    [InlineData(TableRegistry.Admin, "DELETE FROM tenant_settings")]
    [InlineData(TableRegistry.Cli, "SELECT * FROM tenant_settings")]
    [InlineData(TableRegistry.Dispatch, "SELECT * FROM tenant_settings")]
    [InlineData(TableRegistry.Sealer, "SELECT * FROM tenant")]
    [InlineData(TableRegistry.Retention, "SELECT * FROM tenant_host")]
    public async Task Grants_limit_a_role_that_sets_any_Tenant(string role, string statement)
    {
        var database = await SeededDatabaseAsync();
        await using var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = string.Format(statement, TenantA);

        var error = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));

        Assert.Equal(RowSecurityOrPermission, error.SqlState);
        Assert.Contains("permission denied", error.MessageText);
    }

    private Task InsertHostAsync(string database, string host, string kind) =>
        PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Admin, database),
            $"INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('{host}', '{TenantA}', '{kind}')");

    private async Task<string> SeededDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO tenant (id) VALUES ('{TenantA}'), ('{TenantB}');
            INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}'), ('{TenantB}');
            """);

        return database;
    }
}
