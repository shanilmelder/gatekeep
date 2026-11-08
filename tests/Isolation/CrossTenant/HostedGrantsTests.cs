using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>
/// Story 1.31 (AD-2, FR-8, FR-42): the public host's database role, read from the migrated
/// database's own privilege functions, never from the registry alone. <c>gk_hosted</c> has no
/// <c>SELECT</c> on any <c>admin*</c>, <c>tenant_role</c> or <c>deployment_*</c> table, and no
/// <c>INSERT</c>, <c>UPDATE</c>, <c>DELETE</c> or <c>TRUNCATE</c>, at table or column level, on any
/// table the registry marks <see cref="TableUse.Configuration"/>. The registry itself grants it no
/// write there either.
/// </summary>
public sealed class HostedGrantsTests(PostgresFixture postgres)
{
    private static readonly string[] Writes = ["INSERT", "UPDATE", "DELETE", "TRUNCATE"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Hosted_role_reads_no_Admin_tenant_role_or_Deployment_table()
    {
        await using var connection = await OpenAsync(await postgres.NewMigratedDatabaseAsync());

        // The rule covers today's tables of each kind, so an empty match can't pass it.
        var covered = await AdminTablesAsync(connection, null);
        Assert.Contains("admin", covered);
        Assert.Contains("tenant_role", covered);
        Assert.Contains("deployment_audit_event", covered);

        Assert.Empty(await ReadableAdminTablesAsync(connection, null));
    }

    [Fact]
    public async Task Hosted_role_writes_no_configuration_table()
    {
        await using var connection = await OpenAsync(await postgres.NewMigratedDatabaseAsync());

        Assert.Empty(await WritableConfigurationTablesAsync(connection, null));
    }

    [Theory]
    [InlineData("GRANT SELECT ON admin_session TO gk_hosted", "admin_session")]
    [InlineData("GRANT SELECT (role) ON tenant_role TO gk_hosted", "tenant_role")]
    [InlineData("GRANT SELECT ON deployment_audit_detail TO gk_hosted", "deployment_audit_detail")]
    public async Task A_read_grant_on_an_Admin_table_is_reported_by_name(string grant, string table)
    {
        await using var connection = await OpenAsync(await postgres.NewMigratedDatabaseAsync());
        await using var transaction = await connection.BeginTransactionAsync(Cancellation);
        await ExecuteAsync(connection, transaction, grant);

        Assert.Equal([$"gk_hosted can SELECT {table}: AD-2 allows it no read of admin*, tenant_role or deployment_* tables."], await ReadableAdminTablesAsync(connection, transaction));
    }

    [Theory]
    [InlineData("GRANT UPDATE (label) ON tenant TO gk_hosted", "tenant UPDATE")]
    [InlineData("GRANT INSERT ON signing_key TO gk_hosted", "signing_key INSERT")]
    [InlineData("GRANT DELETE ON tenant_settings TO gk_hosted", "tenant_settings DELETE")]
    [InlineData("GRANT TRUNCATE ON protection_key_wrap TO gk_hosted", "protection_key_wrap TRUNCATE")]
    public async Task A_write_grant_on_a_configuration_table_is_reported_by_name(string grant, string expected)
    {
        await using var connection = await OpenAsync(await postgres.NewMigratedDatabaseAsync());
        await using var transaction = await connection.BeginTransactionAsync(Cancellation);
        await ExecuteAsync(connection, transaction, grant);

        var parts = expected.Split(' ');
        Assert.Equal([$"gk_hosted can {parts[1]} {parts[0]}: it is a configuration table, which AD-2 keeps the public host from changing."], await WritableConfigurationTablesAsync(connection, transaction));
    }

    [Fact]
    public void Registry_grants_the_Hosted_role_no_write_on_a_configuration_table()
    {
        var problems = TableRegistry.Tables
            .Where(t => t.Use == TableUse.Configuration)
            .SelectMany(t => HostedPrivileges(t).Where(p => Writes.Contains(p)).Select(p => $"{t.Name} grants gk_hosted {p}."))
            .ToList();

        Assert.Empty(problems);
    }

    [Fact]
    public void Configuration_tables_are_AD_2_s_list()
    {
        // The spec's classification (Story 1.31): every other table is runtime state.
        Assert.Equal(
            [
                "admin", "admin_credential", "admin_enrolment", "admin_recovery_code", "application", "bootstrap_state", "client_secret",
                "migration_history", "protection_key_wrap", "signing_key", "tenant", "tenant_host", "tenant_role", "tenant_settings",
            ],
            TableRegistry.Tables.Where(t => t.Use == TableUse.Configuration).Select(t => t.Name).Order(StringComparer.Ordinal));
    }

    private static IEnumerable<string> HostedPrivileges(TableEntry table) =>
        table.Grants.GetValueOrDefault(TableRegistry.Hosted, [])
            .Concat((table.ColumnGrants?.GetValueOrDefault(TableRegistry.Hosted) ?? []).Select(g => g.Privilege));

    private const string AdminTablesSql =
        """
        SELECT c.relname
        FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND (c.relname LIKE 'admin%' OR c.relname = 'tenant_role' OR c.relname LIKE 'deployment\_%')
        """;

    private static Task<List<string>> AdminTablesAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction) =>
        StringsAsync(connection, transaction, AdminTablesSql + " ORDER BY c.relname COLLATE \"C\"");

    /// <summary>Every such table <c>gk_hosted</c> can read, on the table or any column.</summary>
    private static async Task<List<string>> ReadableAdminTablesAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction) =>
        [
            .. (await StringsAsync(
                connection,
                transaction,
                $"""
                SELECT c.relname FROM ({AdminTablesSql}) AS t JOIN pg_class AS c ON c.relname = t.relname
                JOIN pg_namespace AS n ON n.oid = c.relnamespace AND n.nspname = 'public'
                WHERE has_any_column_privilege('{TableRegistry.Hosted}', c.oid, 'SELECT')
                ORDER BY c.relname COLLATE "C"
                """))
                .Select(t => $"gk_hosted can SELECT {t}: AD-2 allows it no read of admin*, tenant_role or deployment_* tables."),
        ];

    /// <summary>Every write <c>gk_hosted</c> holds on a configuration table: on the table, or on any column.</summary>
    private static async Task<List<string>> WritableConfigurationTablesAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction)
    {
        var problems = new List<string>();
        foreach (var table in TableRegistry.Tables.Where(t => t.Use == TableUse.Configuration).Select(t => t.Name).Order(StringComparer.Ordinal))
        {
            foreach (var privilege in Writes)
            {
                // INSERT and UPDATE can be granted per column; DELETE and TRUNCATE only on the table.
                var check = privilege is "INSERT" or "UPDATE"
                    ? $"has_any_column_privilege('{TableRegistry.Hosted}', 'public.{table}', '{privilege}')"
                    : $"has_table_privilege('{TableRegistry.Hosted}', 'public.{table}', '{privilege}')";
                if ((await StringsAsync(connection, transaction, $"SELECT {check}::text")).Single() == "true")
                {
                    problems.Add($"gk_hosted can {privilege} {table}: it is a configuration table, which AD-2 keeps the public host from changing.");
                }
            }
        }

        return problems;
    }

    private static async Task<List<string>> StringsAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        var values = new List<string>();
        while (await reader.ReadAsync(Cancellation))
        {
            values.Add(reader.GetString(0));
        }

        return values;
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    private async Task<NpgsqlConnection> OpenAsync(string database)
    {
        var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        return connection;
    }
}
