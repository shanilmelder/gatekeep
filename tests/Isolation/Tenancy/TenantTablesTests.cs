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
/// creator's role, and gk_hosted only reads. Story 1.28: gk_admin may update a Tenant's label and
/// nothing else of it, and only while it is active (<c>GK006</c>), whoever runs the update. Story
/// 1.29: a status goes only creating to active, creating or active to deleting, and deleting to
/// deleted, each by its one role (<c>GK007</c>); settings go only while deleting (<c>GK008</c>);
/// gk_admin deletes only a deleting Tenant's roles (<c>GK009</c>); and gk_worker reads only the
/// <c>tenant_id</c> of the tables its purges delete from.
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
    private const string LabelRefused = "GK006";
    private const string StatusRefused = "GK007";
    private const string SettingsDeleteRefused = "GK008";
    private const string RoleDeleteRefused = "GK009";

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
    [InlineData(TableRegistry.Admin, "UPDATE tenant SET issuer = 'https://evil.test/'")]
    [InlineData(TableRegistry.Admin, "UPDATE tenant SET name = 'Renamed'")]
    [InlineData(TableRegistry.Admin, "DELETE FROM tenant")]
    [InlineData(TableRegistry.Worker, "UPDATE tenant SET label = 'prod'")]
    [InlineData(TableRegistry.Hosted, "UPDATE tenant SET label = 'prod'")]
    [InlineData(TableRegistry.Cli, "UPDATE tenant SET label = 'prod'")]
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

        // Without its settings it can't become active; and no role but gk_worker activates (Story 1.29).
        var early = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            worker,
            Scoped($"UPDATE tenant SET status = 'active' WHERE id = '{TenantA}'")));
        Assert.Equal(ActivationRefused, early.SqlState);
        var migrator = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Migrator, database),
            Scoped($"UPDATE tenant SET status = 'active' WHERE id = '{TenantA}'")));
        Assert.Equal(StatusRefused, migrator.SqlState);

        // In the Tenant's own scope (RLS), as the creation Operation's completion does: settings, then active.
        await PostgresFixture.ExecuteAsync(
            worker,
            Scoped($"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}'); UPDATE tenant SET status = 'active' WHERE id = '{TenantA}'"));
        Assert.Equal("active", await ScalarAsync<string>(database, $"SELECT status FROM tenant WHERE id = '{TenantA}'"));
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_settings"));

        // Back to creating is refused for the Worker too, by the trigger.
        var back = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(worker, $"UPDATE tenant SET status = 'creating' WHERE id = '{TenantA}'"));
        Assert.Equal(StatusRefused, back.SqlState);
    }

    /// <summary>Story 1.28: gk_admin may update a Tenant's label, and from Story 1.29 its status, and no other column of it.</summary>
    [Fact]
    public async Task Admin_may_update_only_the_label_and_status()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var columns = await ReadAsync(
            database,
            """
            SELECT attname FROM pg_attribute
            WHERE attrelid = 'public.tenant'::regclass AND attnum > 0 AND NOT attisdropped
              AND has_column_privilege('gk_admin', 'public.tenant', attname, 'UPDATE')
            ORDER BY attname
            """);

        Assert.Equal(["label", "status"], columns);
        Assert.False(await ScalarAsync<bool>(database, "SELECT has_table_privilege('gk_admin', 'public.tenant', 'UPDATE')"));
        Assert.False(await ScalarAsync<bool>(database, "SELECT has_table_privilege('gk_admin', 'public.tenant', 'DELETE')"));
    }

    [Fact]
    public async Task Admin_changes_an_active_Tenants_label_and_the_trigger_keeps_the_rest()
    {
        var database = await SeededAsync();
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);

        await PostgresFixture.ExecuteAsync(admin, $"UPDATE tenant SET label = 'prod' WHERE id = '{TenantA}'");
        Assert.Equal("prod", await ScalarAsync<string>(database, $"SELECT label FROM tenant WHERE id = '{TenantA}'"));

        // A label change can't carry another one with it, for the migrator either.
        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Migrator, database),
            $"UPDATE tenant SET label = 'dev', issuer = 'https://evil.test/' WHERE id = '{TenantA}'"));
        Assert.Equal(RaisedException, failure.SqlState);
        Assert.Equal("prod", await ScalarAsync<string>(database, $"SELECT label FROM tenant WHERE id = '{TenantA}'"));
    }

    [Theory]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Migrator)]
    public async Task A_creating_Tenants_label_never_changes_GK006(string role)
    {
        var database = await SeededAsync(status: "creating");

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(role, database),
            $"UPDATE tenant SET label = 'prod' WHERE id = '{TenantA}'"));

        Assert.Equal(LabelRefused, failure.SqlState);
        Assert.Equal("dev", await ScalarAsync<string>(database, $"SELECT label FROM tenant WHERE id = '{TenantA}'"));
    }

    [Fact]
    public async Task Activation_with_an_unchanged_label_still_passes()
    {
        var database = await SeededAsync(status: "creating");
        var worker = postgres.RoleConnection(TableRegistry.Worker, database);

        await PostgresFixture.ExecuteAsync(
            worker,
            $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}'); " +
            $"UPDATE tenant SET status = 'active' WHERE id = '{TenantA}'; COMMIT;");

        Assert.Equal("active|dev", await ScalarAsync<string>(database, $"SELECT status || '|' || label FROM tenant WHERE id = '{TenantA}'"));
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
            WHERE NOT t.tgisinternal AND c.relname IN ('tenant', 'tenant_host', 'tenant_role', 'tenant_settings')
            ORDER BY 1
            """);

        Assert.Equal(
            [
                "tenant.tenant_guard_insert O",
                "tenant.tenant_guard_update O",
                "tenant_host.tenant_host_guard O",
                "tenant_host.tenant_host_guard_insert O",
                "tenant_host.tenant_host_refuse_truncate O",
                "tenant_role.tenant_role_guard_delete O",
                "tenant_role.tenant_role_guard_insert O",
                "tenant_settings.tenant_row_guard O",
                "tenant_settings.tenant_settings_guard_delete O",
                "tenant_settings.tenant_settings_guard_update O",
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

        foreach (var function in new[] { "tenant_guard_update", "tenant_host_guard", "tenant_settings_guard_delete", "tenant_role_guard_delete", "tenant_row_guard" })
        {
            foreach (var role in TableRegistry.RuntimeRoles)
            {
                Assert.False(
                    await ScalarAsync<bool>(database, $"SELECT has_function_privilege('{role}', '{function}()', 'EXECUTE')"),
                    $"{role} may execute {function}.");
            }
        }
    }

    // Story 1.29: the lifecycle guard, the settings and role delete guards, and the purge grants.

    [Theory]
    [InlineData(TableRegistry.Admin, "creating", "active")]
    [InlineData(TableRegistry.Worker, "active", "deleting")]
    [InlineData(TableRegistry.Worker, "creating", "deleting")]
    [InlineData(TableRegistry.Admin, "deleting", "deleted")]
    [InlineData(TableRegistry.Migrator, "deleted", "active")]
    [InlineData(TableRegistry.Migrator, "deleted", "deleting")]
    [InlineData(TableRegistry.Migrator, "deleting", "active")]
    [InlineData(TableRegistry.Migrator, "deleting", "creating")]
    [InlineData(TableRegistry.Migrator, "active", "creating")]
    [InlineData(TableRegistry.Migrator, "active", "deleted")]
    [InlineData(TableRegistry.Migrator, "creating", "deleted")]
    // An allow-list: a step of the lifecycle, by any role but the one that takes it, the migrator included.
    [InlineData(TableRegistry.Migrator, "active", "deleting")]
    [InlineData(TableRegistry.Migrator, "deleting", "deleted")]
    [InlineData(TableRegistry.Migrator, "creating", "deleting")]
    public async Task Status_follows_only_the_lifecycle_by_its_own_role_GK007(string role, string from, string to)
    {
        var database = await SeededAsync(status: from);

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(role, database),
            $"UPDATE tenant SET status = '{to}' WHERE id = '{TenantA}'"));

        Assert.Equal(StatusRefused, failure.SqlState);
        Assert.Equal(from, await ScalarAsync<string>(database, $"SELECT status FROM tenant WHERE id = '{TenantA}'"));
    }

    [Fact]
    public async Task Deleting_to_deleted_with_settings_left_is_GK007()
    {
        var database = await SeededAsync(status: "deleting");
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"SET session_replication_role = replica; INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}'); SET session_replication_role = DEFAULT");

        foreach (var role in new[] { TableRegistry.Worker, TableRegistry.Migrator })
        {
            var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
                postgres.RoleConnection(role, database),
                $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); UPDATE tenant SET status = 'deleted' WHERE id = '{TenantA}'; COMMIT;"));
            Assert.Equal(StatusRefused, failure.SqlState);
        }

        Assert.Equal("deleting", await ScalarAsync<string>(database, $"SELECT status FROM tenant WHERE id = '{TenantA}'"));
    }

    [Theory]
    [InlineData("creating")]
    [InlineData("active")]
    public async Task Admin_starts_a_deletion_and_removes_its_roles_and_the_Worker_ends_it(string from)
    {
        var database = await SeededAsync(status: from);
        var admin = postgres.RoleConnection(TableRegistry.Admin, database);
        var worker = postgres.RoleConnection(TableRegistry.Worker, database);
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO admin (id, deployment_owner) VALUES ('{Guid.CreateVersion7()}', false); " +
            $"INSERT INTO tenant_role (tenant_id, admin_id, role) SELECT '{TenantA}', id, 'editor' FROM admin; " +
            (from == "active" ? $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')" : "SELECT 1"));

        await PostgresFixture.ExecuteAsync(admin, $"UPDATE tenant SET status = 'deleting' WHERE id = '{TenantA}'; DELETE FROM tenant_role WHERE tenant_id = '{TenantA}'");
        Assert.Equal(0L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_role"));

        await PostgresFixture.ExecuteAsync(
            worker,
            $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); DELETE FROM tenant_settings WHERE tenant_id = '{TenantA}'; " +
            $"UPDATE tenant SET status = 'deleted' WHERE id = '{TenantA}'; COMMIT;");

        Assert.Equal("deleted", await ScalarAsync<string>(database, $"SELECT status FROM tenant WHERE id = '{TenantA}'"));
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_host"));
    }

    [Theory]
    [InlineData(TableRegistry.Worker, "active")]
    [InlineData(TableRegistry.Worker, "creating")]
    [InlineData(TableRegistry.Migrator, "active")]
    public async Task Settings_go_only_while_the_Tenant_is_deleting_GK008(string role, string status)
    {
        var database = await SeededAsync(status: status);
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')");

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(role, database),
            $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); DELETE FROM tenant_settings WHERE tenant_id = '{TenantA}'; COMMIT;"));

        Assert.Equal(SettingsDeleteRefused, failure.SqlState);
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_settings"));
    }

    /// <summary>Story 1.29, after Story 2.3: a Tenant's key rows go only with its deletion, so rotation can never delete one (GK008).</summary>
    [Theory]
    [InlineData("signing_key", "active")]
    [InlineData("signing_key", "creating")]
    [InlineData("protection_key_wrap", "active")]
    [InlineData("protection_key_wrap", "creating")]
    public async Task Key_rows_go_only_while_the_Tenant_is_deleting_GK008(string table, string status)
    {
        var database = await SeededAsync(status: status);
        var seed = TenantSeeds.Seeds.Single(s => s.Table == table).Sql(TenantA, Guid.CreateVersion7());
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), $"SET session_replication_role = replica; {seed}; SET session_replication_role = DEFAULT");

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Worker, database),
            $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); DELETE FROM {table} WHERE tenant_id = '{TenantA}'; COMMIT;"));

        Assert.Equal(SettingsDeleteRefused, failure.SqlState);
        Assert.Equal(1L, await ScalarAsync<long>(database, $"SELECT count(*) FROM {table}"));
    }

    [Theory]
    [InlineData("active")]
    [InlineData("creating")]
    [InlineData("deleted")]
    public async Task Admin_deletes_only_a_deleting_Tenants_roles_GK009(string status)
    {
        var database = await SeededAsync(status: status);
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO admin (id, deployment_owner) VALUES ('{Guid.CreateVersion7()}', false); INSERT INTO tenant_role (tenant_id, admin_id, role) SELECT '{TenantA}', id, 'owner' FROM admin");

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Admin, database),
            $"DELETE FROM tenant_role WHERE tenant_id = '{TenantA}'"));

        Assert.Equal(RoleDeleteRefused, failure.SqlState);
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_role"));
    }

    [Theory]
    [MemberData(nameof(AllRuntimeRoles))]
    public async Task No_runtime_role_deletes_a_Tenant(string role)
    {
        var database = await SeededAsync(status: "deleted");

        foreach (var sql in new[] { "DELETE FROM tenant", "TRUNCATE tenant", "DELETE FROM tenant_host" })
        {
            var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql));
            Assert.Equal(PermissionDenied, failure.SqlState);
        }

        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant"));
        Assert.Equal(1L, await ScalarAsync<long>(database, "SELECT count(*) FROM tenant_host"));
    }

    public static TheoryData<string> AllRuntimeRoles() => [.. TableRegistry.RuntimeRoles];

    /// <summary>Story 1.29: every purged tenant table refuses a row for a Tenant being deleted, or deleted (GK010).</summary>
    [Theory]
    [InlineData("deleting")]
    [InlineData("deleted")]
    public async Task No_purged_table_takes_a_row_of_a_deleting_or_deleted_Tenant_GK010(string status)
    {
        var database = await SeededAsync(status: status);
        var value = Guid.CreateVersion7();
        var seeds = TenantSeeds.Seeds.Select(s => (s.Table, Sql: s.Sql(TenantA, value))).ToList();

        // A job payload needs its job, which the job guard writes only in a scope: checked on its own below.
        foreach (var (table, sql) in seeds.Where(s => s.Table != "job_payload"))
        {
            // The parent rows a child needs, written with triggers off; then the child itself, with them on.
            var parents = string.Join("; ", seeds.TakeWhile(s => s.Table != table).Select(s => s.Sql));
            var setup = parents.Length == 0 ? "SELECT 1" : $"SET session_replication_role = replica; {parents}; SET session_replication_role = DEFAULT";
            var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
                postgres.SuperuserConnection(database),
                $"BEGIN; {setup}; {sql}; COMMIT;"));

            Assert.True(failure.SqlState == "GK010", $"{table}: {failure.SqlState}");
        }

        // A job payload is still written while the Tenant is deleting, for its own deletion's step
        // jobs; once it is deleted, never.
        if (status == "deleted")
        {
            var job = Guid.CreateVersion7();
            var payload = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
                postgres.SuperuserConnection(database),
                $"SET session_replication_role = replica; INSERT INTO job (id, type, tenant_id, deployment_wide) VALUES ('{job}', 'operations.operation.step', '{TenantA}', false); " +
                $"SET session_replication_role = DEFAULT; INSERT INTO job_payload (tenant_id, job_id, ids) VALUES ('{TenantA}', '{job}', '{{}}')"));
            Assert.Equal("GK010", payload.SqlState);
        }

        Assert.Empty(await TenantSeeds.RowsLeftAsync(postgres.SuperuserConnection(database), TenantA));
    }

    [Fact]
    public async Task A_deleting_Tenants_own_step_jobs_still_get_their_payload()
    {
        var database = await SeededAsync(status: "deleting");
        var job = Guid.CreateVersion7();

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"SET session_replication_role = replica; INSERT INTO job (id, type, tenant_id, deployment_wide) VALUES ('{job}', 'operations.operation.step', '{TenantA}', false); " +
            $"SET session_replication_role = DEFAULT; INSERT INTO job_payload (tenant_id, job_id, ids) VALUES ('{TenantA}', '{job}', '{{}}')");

        Assert.Equal(1L, await ScalarAsync<long>(database, $"SELECT count(*) FROM job_payload WHERE tenant_id = '{TenantA}'"));
    }

    [Theory]
    [InlineData("deleting", "INSERT INTO tenant_settings (tenant_id) VALUES ('{0}')")]
    [InlineData("deleted", "INSERT INTO tenant_settings (tenant_id) VALUES ('{0}')")]
    [InlineData("creating", "UPDATE tenant_settings SET updated_at = now() WHERE tenant_id = '{0}'")]
    [InlineData("deleting", "UPDATE tenant_settings SET updated_at = now() WHERE tenant_id = '{0}'")]
    public async Task Settings_are_inserted_only_while_creating_or_active_and_updated_only_while_active_GK010(string status, string sql)
    {
        var database = await SeededAsync(status: status);
        if (sql.StartsWith("UPDATE", StringComparison.Ordinal))
        {
            await PostgresFixture.ExecuteAsync(
                postgres.SuperuserConnection(database),
                $"SET session_replication_role = replica; INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}'); SET session_replication_role = DEFAULT");
        }

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            string.Format(System.Globalization.CultureInfo.InvariantCulture, sql, TenantA)));

        Assert.Equal("GK010", failure.SqlState);
    }

    [Fact]
    public async Task An_active_Tenants_settings_update()
    {
        var database = await SeededAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')");

        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"UPDATE tenant_settings SET updated_at = now() WHERE tenant_id = '{TenantA}'");
    }

    [Theory]
    [InlineData("deleting")]
    [InlineData("deleted")]
    public async Task No_role_is_granted_in_a_deleting_or_deleted_Tenant_GK004(string status)
    {
        var database = await SeededAsync(status: status);
        var admin = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"INSERT INTO admin (id, deployment_owner) VALUES ('{admin}', true)");

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Admin, database),
            $"INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{TenantA}', '{admin}', 'owner')"));

        Assert.Equal("GK004", failure.SqlState);
    }

    /// <summary>
    /// Story 1.29: a purge reads only the Tenant ID its <c>WHERE</c> names. Story 3.5: a deleted Application's
    /// purge also reads the Application and family references it deletes by, and never any content.
    /// </summary>
    [Theory]
    [InlineData("user", "tenant_id")]
    [InlineData("user_session", "tenant_id")]
    [InlineData("authorization", "application_id,id,tenant_id")]
    [InlineData("token", "application_id,authorization_id,tenant_id")]
    [InlineData("signin_transaction", "application_id,tenant_id")]
    public async Task Worker_may_delete_and_read_only_the_references_of_a_purged_table(string table, string columns)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        Assert.True(await ScalarAsync<bool>(database, $"SELECT has_table_privilege('gk_worker', 'public.\"{table}\"', 'DELETE')"));
        foreach (var privilege in new[] { "SELECT", "INSERT", "UPDATE", "TRUNCATE" })
        {
            Assert.False(await ScalarAsync<bool>(database, $"SELECT has_table_privilege('gk_worker', 'public.\"{table}\"', '{privilege}')"), $"{table} {privilege}");
        }

        var readable = await ReadAsync(
            database,
            $"""
            SELECT attname FROM pg_attribute
            WHERE attrelid = 'public."{table}"'::regclass AND attnum > 0 AND NOT attisdropped
              AND has_column_privilege('gk_worker', 'public."{table}"', attname, 'SELECT')
            ORDER BY attname
            """);
        Assert.Equal(columns.Split(','), readable);
    }

    [Fact]
    public async Task Worker_reads_no_purged_tables_content()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), TenantA);

        var failure = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
            postgres.RoleConnection(TableRegistry.Worker, database),
            $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); SELECT id FROM \"user\"; COMMIT;"));

        Assert.Equal(PermissionDenied, failure.SqlState);
    }

    /// <summary>
    /// Story 9.1: gk_admin reads <c>signing_key</c> for the Signing keys page. Story 9.2: it inserts the
    /// replacement next row and updates <c>state</c>, <c>promoted_at</c> and <c>rotated_at</c> for an
    /// on-demand rotation, and nothing more: no DELETE, TRUNCATE or table-wide UPDATE, no other column,
    /// and row-level security still holds it to the scope's own Tenant.
    /// </summary>
    [Fact]
    public async Task Admin_reads_inserts_and_rotates_signing_keys_only_in_its_scopes_Tenant()
    {
        var database = await SeededAsync();
        var tenantB = Guid.CreateVersion7();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), tenantB, "beta.tenants.gatekeep.test");
        var seed = TenantSeeds.Seeds.Single(s => s.Table == "signing_key").Sql;
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"{seed(TenantA, Guid.CreateVersion7())}; {seed(tenantB, Guid.CreateVersion7())}");

        foreach (var privilege in new[] { "SELECT", "INSERT" })
        {
            Assert.True(await ScalarAsync<bool>(database, $"SELECT has_table_privilege('gk_admin', 'public.signing_key', '{privilege}')"), privilege);
        }

        foreach (var privilege in new[] { "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER" })
        {
            Assert.False(await ScalarAsync<bool>(database, $"SELECT has_table_privilege('gk_admin', 'public.signing_key', '{privilege}')"), privilege);
        }

        var updatable = await ReadAsync(
            database,
            """
            SELECT attname FROM pg_attribute
            WHERE attrelid = 'public.signing_key'::regclass AND attnum > 0 AND NOT attisdropped
              AND has_column_privilege('gk_admin', 'public.signing_key', attname, 'UPDATE')
            ORDER BY attname
            """);
        Assert.Equal(["promoted_at", "rotated_at", "state"], updatable);

        Assert.Equal([TenantA.ToString()], await AdminReadsAsync(database, TenantA));
        Assert.Equal([tenantB.ToString()], await AdminReadsAsync(database, tenantB));

        foreach (var sql in new[] { "UPDATE signing_key SET retired_at = now()", "UPDATE signing_key SET destroyed_at = now()", "DELETE FROM signing_key" })
        {
            var refused = await Assert.ThrowsAsync<PostgresException>(() => PostgresFixture.ExecuteAsync(
                postgres.RoleConnection(TableRegistry.Admin, database),
                $"BEGIN; SELECT set_config('gatekeep.tenant_id', '{TenantA}', true); {sql}; COMMIT;"));
            Assert.Equal(PermissionDenied, refused.SqlState);
        }
    }

    /// <summary>The <c>tenant_id</c> of each <c>signing_key</c> row gk_admin sees in <paramref name="tenant"/>'s scope.</summary>
    private async Task<List<string>> AdminReadsAsync(string database, Guid tenant)
    {
        await using var connection = new NpgsqlConnection(postgres.RoleConnection(TableRegistry.Admin, database));
        await connection.OpenAsync(Cancellation);
        await using var transaction = await connection.BeginTransactionAsync(Cancellation);
        await using (var scope = new NpgsqlCommand($"SELECT set_config('gatekeep.tenant_id', '{tenant}', true)", connection, transaction))
        {
            await scope.ExecuteScalarAsync(Cancellation);
        }

        await using var command = new NpgsqlCommand("SELECT tenant_id::text FROM signing_key", connection, transaction);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        var rows = new List<string>();
        while (await reader.ReadAsync(Cancellation))
        {
            rows.Add(reader.GetString(0));
        }

        return rows;
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
