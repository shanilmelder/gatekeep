using Gatekeep.Adapters.Postgres;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 1.27 (AD-6, AD-27): <c>tenant</c>'s new columns, its guard trigger, <c>tenant_host</c>'s
/// guard against every update, delete and truncate for every role and the migrator, and the grants:
/// gk_worker may only set a Tenant's status and insert its settings, gk_admin may insert the
/// creator's role, and gk_hosted only reads.
/// </summary>
public sealed class TenantTablesTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";
    private const string NotNullViolation = "23502";
    private const string CheckViolation = "23514";
    private const string UniqueViolation = "23505";
    private const string RaisedException = "P0001";
    private const string HostRefused = "GK002";
    private const string TenantInsertRefused = "GK003";
    private const string ActivationRefused = "GK005";

    private const string PreviousMigration = "20261104010000_ConfirmSensitiveActions";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000127aa");

    private static readonly string[] RuntimeRolesWithHostAccess = [TableRegistry.Admin, TableRegistry.Worker, TableRegistry.Hosted];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Tenant_has_its_new_columns_all_required()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var columns = await ReadAsync(
            database,
            """
            SELECT column_name || ' ' || data_type || ' ' || is_nullable || ' ' || coalesce(column_default, '-')
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'tenant'
            ORDER BY column_name
            """);

        Assert.Equal(
            [
                "created_at timestamp with time zone NO clock_timestamp()",
                "email_link_base text NO -",
                "id uuid NO -",
                "issuer text NO -",
                "label text NO -",
                "name text NO -",
                "rp_id text NO -",
                "status text NO -",
            ],
            columns);
    }

    [Fact]
    public async Task Migration_fails_loudly_on_a_Tenant_that_existed_before_it()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();
        await using (var context = Context(database))
        {
            await context.GetService<IMigrator>().MigrateAsync(PreviousMigration, Cancellation);
        }

        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"INSERT INTO tenant (id) VALUES ('{TenantA}')");

        await using (var context = Context(database))
        {
            var failure = await Assert.ThrowsAsync<PostgresException>(() => context.Database.MigrateAsync(Cancellation));
            Assert.Equal(NotNullViolation, failure.SqlState);
        }

        // Nothing of the migration stayed: the Tenant keeps its two columns, and it isn't recorded.
        Assert.Equal(0L, await ScalarAsync<long>(database, $"SELECT count(*) FROM {GatekeepMigrator.HistoryTable} WHERE \"MigrationId\" LIKE '%CreateTenants'"));
        Assert.Equal(2L, await ScalarAsync<long>(database, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'tenant'"));
    }

    [Theory]
    [InlineData("''", "'dev'", "'creating'", CheckViolation)]
    [InlineData("repeat('n', 101)", "'dev'", "'creating'", CheckViolation)]
    [InlineData("'n'", "'production'", "'creating'", CheckViolation)]
    [InlineData("NULL", "'dev'", "'creating'", NotNullViolation)]
    [InlineData("'n'", "NULL", "'creating'", NotNullViolation)]
    [InlineData("'n'", "'dev'", "'active'", TenantInsertRefused)]
    [InlineData("'n'", "'dev'", "'deleted'", TenantInsertRefused)]
    [InlineData("'n'", "'dev'", "NULL", TenantInsertRefused)]
    public async Task Columns_hold_only_their_values(string name, string label, string status, string state)
    {
        var database = await SeededAsync();

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base) " +
            $"VALUES ('{Guid.CreateVersion7()}', {name}, {label}, {status}, 'https://x.test/', 'x.test', 'https://x.test/')"));

        Assert.Equal(state, failure.SqlState);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("rp_id")]
    public async Task Issuer_and_RP_ID_are_unique(string column)
    {
        var database = await SeededAsync();
        var stored = await ScalarAsync<string>(database, $"SELECT {column} FROM tenant WHERE id = '{TenantA}'");
        var other = Guid.CreateVersion7();

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base) VALUES " +
            $"('{other}', 'n', 'dev', 'creating', " +
            $"'{(column == "issuer" ? stored : "https://other.test/")}', '{(column == "rp_id" ? stored : "other.test")}', 'https://other.test/')"));

        Assert.Equal(UniqueViolation, failure.SqlState);
    }

    [Theory]
    [MemberData(nameof(HostRoles))]
    public async Task No_role_updates_deletes_or_truncates_a_host(string role)
    {
        var database = await SeededAsync();

        foreach (var sql in new[]
        {
            "UPDATE tenant_host SET host = 'moved.tenants.gatekeep.test'",
            "UPDATE tenant_host SET kind = 'subdomain'",
            "DELETE FROM tenant_host",
            "TRUNCATE tenant_host",
        })
        {
            var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql));
            Assert.Equal(PermissionDenied, failure.SqlState);
        }

        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_host"));
    }

    public static TheoryData<string> HostRoles() => [.. RuntimeRolesWithHostAccess];

    [Theory]
    [InlineData("UPDATE tenant_host SET host = 'moved.tenants.gatekeep.test'")]
    [InlineData("UPDATE tenant_host SET tenant_id = tenant_id")]
    [InlineData("DELETE FROM tenant_host")]
    [InlineData("TRUNCATE tenant_host")]
    public async Task Trigger_refuses_any_role_the_migrator_included(string sql)
    {
        var database = await SeededAsync();

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql));

        Assert.Equal(RaisedException, failure.SqlState);
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_host"));
    }

    [Theory]
    [InlineData(TableRegistry.Worker, "UPDATE tenant SET issuer = 'https://evil.test/'")]
    [InlineData(TableRegistry.Worker, "UPDATE tenant SET rp_id = 'evil.test'")]
    [InlineData(TableRegistry.Worker, "UPDATE tenant SET name = 'Renamed'")]
    [InlineData(TableRegistry.Worker, "DELETE FROM tenant")]
    [InlineData(TableRegistry.Admin, "UPDATE tenant SET status = 'active'")]
    [InlineData(TableRegistry.Admin, "UPDATE tenant SET issuer = 'https://evil.test/'")]
    [InlineData(TableRegistry.Hosted, "UPDATE tenant SET status = 'active'")]
    [InlineData(TableRegistry.Hosted, "INSERT INTO tenant_host (host, tenant_id, kind) SELECT 'new.tenants.gatekeep.test', id, 'subdomain' FROM tenant")]
    [InlineData(TableRegistry.Hosted, "INSERT INTO tenant_role (tenant_id, admin_id, role) SELECT id, gen_random_uuid(), 'owner' FROM tenant")]
    [InlineData(TableRegistry.Cli, "UPDATE tenant SET status = 'active'")]
    public async Task Roles_cant_change_what_they_werent_granted(string role, string sql)
    {
        var database = await SeededAsync(status: "creating");

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql));

        Assert.Equal(PermissionDenied, failure.SqlState);
    }

    [Theory]
    [InlineData("UPDATE tenant SET issuer = 'https://evil.test/'")]
    [InlineData("UPDATE tenant SET rp_id = 'evil.test'")]
    [InlineData("UPDATE tenant SET email_link_base = 'https://evil.test/'")]
    [InlineData("UPDATE tenant SET created_at = created_at - interval '1 day'")]
    [InlineData("UPDATE tenant SET id = gen_random_uuid()")]
    [InlineData("UPDATE tenant SET status = 'creating'")]
    public async Task Trigger_keeps_the_derived_values_and_status_for_any_role(string sql)
    {
        var database = await SeededAsync();

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql));

        Assert.Equal(RaisedException, failure.SqlState);
    }

    [Fact]
    public async Task Worker_activates_a_creating_Tenant_once_and_inserts_its_settings()
    {
        var database = await SeededAsync(status: "creating");
        var worker = postgres.RoleConnection(TableRegistry.Worker, database);
        string Scoped(string sql) => $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); {sql}; COMMIT;";

        // Without its settings it can't become active, whoever asks.
        foreach (var connection in new[] { worker, postgres.RoleConnection(TableRegistry.Migrator, database) })
        {
            var early = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
                connection,
                Scoped($"UPDATE tenant SET status = 'active' WHERE id = '{TenantA}'")));
            Assert.Equal(ActivationRefused, early.SqlState);
        }

        // In the Tenant's own scope (RLS), as the creation Operation's completion does: settings, then active.
        await PostgresFixture.ExecuteAsync(
            worker,
            Scoped($"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}'); UPDATE tenant SET status = 'active' WHERE id = '{TenantA}'"));
        Assert.Equal("active", await ScalarAsync<string>(database, $"SELECT status FROM tenant WHERE id = '{TenantA}'"));
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_settings"));

        // Back to creating is refused for the Worker too, by the trigger.
        var back = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(worker, $"UPDATE tenant SET status = 'creating' WHERE id = '{TenantA}'"));
        Assert.Equal(RaisedException, back.SqlState);
    }

    [Fact]
    public async Task A_host_is_added_only_to_a_creating_Tenant_with_none_of_its_kind()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);
        var creating = Guid.CreateVersion7();
        var active = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            admin,
            $"INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base) VALUES ('{creating}', 'n', 'dev', 'creating', 'https://c.test/', 'c.test', 'https://c.test/')");
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), active);

        await PostgresFixture.ExecuteAsync(admin, $"INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('c.test', '{creating}', 'subdomain')");

        foreach (var sql in new[]
        {
            // A second host of the same kind, and a host for an active Tenant or none.
            $"INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('c2.test', '{creating}', 'subdomain')",
            $"INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('a.test', '{active}', 'subdomain')",
            $"INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('n.test', '{Guid.CreateVersion7()}', 'subdomain')",
        })
        {
            var refused = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(admin, sql));
            Assert.Equal(HostRefused, refused.SqlState);
        }

        // And the Admin can't insert an active Tenant.
        var tenant = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            admin,
            $"INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base) VALUES ('{Guid.CreateVersion7()}', 'n', 'dev', 'active', 'https://d.test/', 'd.test', 'https://d.test/')"));
        Assert.Equal(TenantInsertRefused, tenant.SqlState);
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_host"));
    }

    [Fact]
    public async Task Tenancy_guard_triggers_exist_and_are_enabled()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var triggers = await ReadAsync(
            database,
            """
            SELECT c.relname || '.' || t.tgname || ' ' || t.tgenabled::text
            FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
            WHERE NOT t.tgisinternal AND c.relname IN ('tenant', 'tenant_host', 'tenant_role')
            ORDER BY 1
            """);

        Assert.Equal(
            [
                "tenant.tenant_guard_insert O",
                "tenant.tenant_guard_update O",
                "tenant_host.tenant_host_guard O",
                "tenant_host.tenant_host_guard_insert O",
                "tenant_host.tenant_host_refuse_truncate O",
                "tenant_role.tenant_role_guard_insert O",
            ],
            triggers);
    }

    [Theory]
    [InlineData("tenant")]
    [InlineData("tenant_host")]
    [InlineData("tenant_settings")]
    public async Task Hosted_only_reads_the_Tenancy_tables(string table)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        foreach (var privilege in new[] { "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE" })
        {
            Assert.Equal(
                privilege == "SELECT",
                await ScalarAsync<bool>(database, $"SELECT has_table_privilege('gk_hosted', 'public.{table}', '{privilege}')"));
        }

        Assert.False(await ScalarAsync<bool>(
            database,
            $"SELECT bool_or(has_column_privilege('gk_hosted', 'public.{table}', attname, 'UPDATE')) FROM pg_attribute " +
            $"WHERE attrelid = 'public.{table}'::regclass AND attnum > 0 AND NOT attisdropped"));
    }

    [Fact]
    public async Task Guard_functions_run_for_nobody_directly()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        foreach (var function in new[] { "tenant_guard_update", "tenant_host_guard" })
        {
            foreach (var role in TableRegistry.RuntimeRoles)
            {
                Assert.False(
                    await ScalarAsync<bool>(database, $"SELECT has_function_privilege('{role}', '{function}()', 'EXECUTE')"),
                    $"{role} may execute {function}.");
            }
        }
    }

    private async Task<string> SeededAsync(string status = "active")
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), TenantA, "acme.tenants.gatekeep.test", status);
        return database;
    }

    private MigrationsContext Context(string database) =>
        new(new DbContextOptionsBuilder<MigrationsContext>()
            .UseNpgsql(postgres.RoleConnection(TableRegistry.Migrator, database), npgsql => npgsql.MigrationsHistoryTable(GatekeepMigrator.HistoryTable))
            .ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.ModelSnapshotNotFound))
            .Options);

    private Task<T> ScalarAsync<T>(string database, string sql) => PostgresFixture.ScalarAsync<T>(postgres.SuperuserConnection(database), sql);

    private async Task<List<string>> ReadAsync(string database, string sql)
    {
        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        var rows = new List<string>();
        while (await reader.ReadAsync(Cancellation))
        {
            rows.Add(reader.GetString(0));
        }

        return rows;
    }
}
