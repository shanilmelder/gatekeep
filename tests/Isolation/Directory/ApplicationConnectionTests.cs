using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Connections;

/// <summary>
/// Story 4.12 (FR-14): which Connections each Application allows. The migration's backfill turns every Connection on for
/// every existing non-system Application, and a new Application starts with every Connection its Tenant enables on. The one
/// effective rule: a Connection is enabled for an Application when its Tenant enables it and the Application is the system
/// one or has an enabled row; a missing row means off, and a deleted Application enables nothing. The table holds every
/// role to its grants and every Tenant to its own rows.
/// </summary>
public sealed class ApplicationConnectionTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000412a1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000412a2");
    private static readonly Guid TenantC = Guid.Parse("01900000-0000-7000-8000-0000000412a3");

    private static readonly Guid System = Guid.Parse("01900000-0000-7000-8000-0000000412f1");
    private static readonly Guid AppOn = Guid.Parse("01900000-0000-7000-8000-0000000412b1");
    private static readonly Guid AppOff = Guid.Parse("01900000-0000-7000-8000-0000000412b2");
    private static readonly Guid AppMissing = Guid.Parse("01900000-0000-7000-8000-0000000412b3");
    private static readonly Guid AppDeleted = Guid.Parse("01900000-0000-7000-8000-0000000412b4");
    private static readonly Guid AppOfB = Guid.Parse("01900000-0000-7000-8000-0000000412c1");

    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <summary>
    /// The migration's backfill, rendered through the same <c>ForEachTenant</c> the migration calls and run twice as the
    /// migrator: an enabled row per non-system Application and Connection of each creating or active Tenant, none for the
    /// system Application or a deleting Tenant, and nothing more on a rerun.
    /// </summary>
    [Fact]
    public async Task Backfill_enables_every_Connection_for_every_non_system_Application_once()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(superuser, TestTenants.InsertSql(TenantA, TenantC));
        await PostgresFixture.ExecuteAsync(
            superuser,
            SystemSql(TenantA) + "; " + ApplicationSql(TenantA, AppOn, "Shop") + "; " + ApplicationSql(TenantA, AppDeleted, "Gone", deleted: true) + "; "
            + ApplicationSql(TenantC, AppOfB, "Leaving") + "; "
            + $"INSERT INTO connection (tenant_id, id, kind) VALUES ('{TenantA}', gen_random_uuid(), 'database'), ('{TenantC}', gen_random_uuid(), 'database')");
        await PostgresFixture.ExecuteAsync(
            superuser, $"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{TenantC}'; SET session_replication_role = DEFAULT");

        var builder = new MigrationBuilder("Npgsql.EntityFrameworkCore.PostgreSQL");
        builder.ForEachTenant(Migration20261201000000ApplicationConnections.Backfill);
        var sql = Assert.IsType<SqlOperation>(Assert.Single(builder.Operations)).Sql;

        // The migration's Up() runs exactly that statement, last.
        var migration = new Migration20261201000000ApplicationConnections { ActiveProvider = "Npgsql.EntityFrameworkCore.PostgreSQL" };
        Assert.Equal(sql, Assert.IsType<SqlOperation>(migration.UpOperations[^1]).Sql);

        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);
        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM application_connection WHERE tenant_id = '{TenantA}' AND application_id = '{AppOn}' AND enabled"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM application_connection WHERE tenant_id = '{TenantA}' AND application_id = '{AppDeleted}' AND enabled"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM application_connection WHERE application_id = '{System}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application_connection WHERE tenant_id = '{TenantC}'"));
        Assert.Equal(2L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM application_connection"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event"));
    }

    /// <summary>
    /// The effective rule, as Host.Hosted reads it: an enabled row is on, a disabled or missing row off, the system
    /// Application and no Application (the Tenant's own view) follow the Tenant, and a deleted Application enables nothing.
    /// With the Connection disabled in the Tenant, nothing is on, the system Application included.
    /// </summary>
    [Fact]
    public async Task The_effective_rule_decides_every_Application_and_follows_the_Tenant()
    {
        var (database, connection) = await SeededAsync();

        foreach (var (application, expected) in new (Guid?, bool)[]
            { (AppOn, true), (AppOff, false), (AppMissing, false), (AppDeleted, false), (System, true), (null, true), (Guid.CreateVersion7(), false) })
        {
            var read = await InTenantAsync(
                database, TableRegistry.Hosted, TenantA, c => _directory.FindDatabaseConnectionForApplicationAsync(c, application, Cancellation));
            Assert.NotNull(read);
            Assert.True(expected == read.Enabled, $"{application} reads Enabled {read.Enabled}.");
            if (application is { } id)
            {
                Assert.Equal(expected, await InTenantAsync(
                    database, TableRegistry.Hosted, TenantA, c => _directory.IsConnectionEnabledForApplicationAsync(c, id, connection, Cancellation)));
            }
        }

        // An unknown Connection is never enabled.
        Assert.False(await InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => _directory.IsConnectionEnabledForApplicationAsync(c, AppOn, Guid.CreateVersion7(), Cancellation)));

        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"UPDATE connection SET enabled = false WHERE tenant_id = '{TenantA}'");
        foreach (var application in new Guid?[] { AppOn, System, null })
        {
            var read = await InTenantAsync(
                database, TableRegistry.Hosted, TenantA, c => _directory.FindDatabaseConnectionForApplicationAsync(c, application, Cancellation));
            Assert.False(read!.Enabled, $"{application} reads a Tenant-disabled Connection as enabled.");
        }

        Assert.False(await InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => _directory.IsConnectionEnabledForApplicationAsync(c, System, connection, Cancellation)));

        // A Tenant with no Connection reads none, whatever the Application.
        Assert.Null(await InTenantAsync(
            database, TableRegistry.Hosted, TenantB, c => _directory.FindDatabaseConnectionForApplicationAsync(c, AppOfB, Cancellation)));
    }

    /// <summary>A new Application, an Admin's or a client the System creates, starts with every Connection of its Tenant on.</summary>
    [Fact]
    public async Task A_new_Application_starts_with_every_enabled_Connection_on()
    {
        var (database, connection) = await SeededAsync();
        var superuser = postgres.SuperuserConnection(database);
        var actor = Actor.Admin(Guid.CreateVersion7());

        var created = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, actor, "New app", DirectoryContract.SpaKind, Cancellation));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser,
            $"SELECT count(*) FROM application_connection WHERE tenant_id = '{TenantA}' AND application_id = '{created.Id}' AND connection_id = '{connection}' AND enabled"));
        Assert.True((await InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => _directory.FindDatabaseConnectionForApplicationAsync(c, created.Id, Cancellation)))!.Enabled);

        var web = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.CreateWebClientAsync(c, "Web", ["https://web.example/cb"], Cancellation));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM application_connection WHERE tenant_id = '{TenantA}' AND application_id = '{web.ApplicationId}' AND enabled"));

        // A Tenant with no Connection gets no row.
        var none = await InTenantAsync(
            database, TableRegistry.Admin, TenantB, c => _directory.CreateApplicationAsync(c, actor, "No Connection", DirectoryContract.WebKind, Cancellation));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application_connection WHERE application_id = '{none.Id}'"));

        // One created while the Tenant disables its Connection still gets its row on: it counts once the Tenant enables it again.
        await PostgresFixture.ExecuteAsync(superuser, $"UPDATE connection SET enabled = false WHERE tenant_id = '{TenantA}'");
        var disabled = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.CreateApplicationAsync(c, actor, "Disabled", DirectoryContract.MachineKind, Cancellation));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM application_connection WHERE application_id = '{disabled.Id}' AND enabled"));
        Assert.False((await InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => _directory.FindDatabaseConnectionForApplicationAsync(c, disabled.Id, Cancellation)))!.Enabled);
        await PostgresFixture.ExecuteAsync(superuser, $"UPDATE connection SET enabled = true WHERE tenant_id = '{TenantA}'");
        Assert.True((await InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => _directory.FindDatabaseConnectionForApplicationAsync(c, disabled.Id, Cancellation)))!.Enabled);
    }

    /// <summary>
    /// The hourly backfill's ensure, as gk_worker, for a Tenant that already has Applications and no Connection: the
    /// Connection it inserts is on for each visible one, in the same command, never for the system or a deleted one.
    /// </summary>
    [Fact]
    public async Task Ensuring_a_missing_Connection_turns_it_on_for_the_Tenants_existing_Applications()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(superuser, TestTenants.InsertSql(TenantA));
        await PostgresFixture.ExecuteAsync(
            superuser,
            SystemSql(TenantA) + "; " + ApplicationSql(TenantA, AppOn, "Shop") + "; " + ApplicationSql(TenantA, AppDeleted, "Gone", deleted: true));

        Assert.True(await InTenantAsync(database, TableRegistry.Worker, TenantA, c => _directory.EnsureDatabaseConnectionAsync(c, Cancellation)));
        Assert.False(await InTenantAsync(database, TableRegistry.Worker, TenantA, c => _directory.EnsureDatabaseConnectionAsync(c, Cancellation)));

        Assert.Equal($"{AppOn}", await PostgresFixture.ScalarAsync<string>(
            superuser, $"SELECT string_agg(application_id::text, ',') FROM application_connection WHERE tenant_id = '{TenantA}' AND enabled"));
        Assert.True((await InTenantAsync(
            database, TableRegistry.Hosted, TenantA, c => _directory.FindDatabaseConnectionForApplicationAsync(c, AppOn, Cancellation)))!.Enabled);
    }

    /// <summary>With the Connection disabled in the Tenant, it lists no Application, and each Application sees it as not Tenant-enabled.</summary>
    [Fact]
    public async Task A_Connection_the_Tenant_disables_lists_no_Application_and_reads_as_not_Tenant_enabled()
    {
        var (database, _) = await SeededAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), $"UPDATE connection SET enabled = false WHERE tenant_id = '{TenantA}'");

        var applications = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.ListConnectionApplicationsAsync(c, DirectoryContract.DatabaseConnectionKind, Cancellation));
        Assert.NotNull(applications);
        Assert.Empty(applications);

        var connection = Assert.Single((await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationConnectionsAsync(c, AppOn, Cancellation)))!);
        Assert.True(connection.Enabled);
        Assert.False(connection.TenantEnabled);
        Assert.False(connection.Usable);
    }

    [Fact]
    public async Task A_toggle_writes_its_row_and_one_event_and_an_unchanged_one_nothing()
    {
        var (database, _) = await SeededAsync();
        var superuser = postgres.SuperuserConnection(database);
        var actor = Actor.Admin(Guid.CreateVersion7());

        var off = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.SetApplicationConnectionAsync(c, actor, AppOn, DirectoryContract.DatabaseConnectionKind, false, Cancellation));
        Assert.Equal(ApplicationConnectionWriteStatus.Saved, off.Status);
        Assert.False(off.Connection!.Enabled);
        Assert.True(off.Connection.TenantEnabled);

        var again = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.SetApplicationConnectionAsync(c, actor, AppOn, DirectoryContract.DatabaseConnectionKind, false, Cancellation));
        Assert.Equal(ApplicationConnectionWriteStatus.Unchanged, again.Status);

        // A missing row is off: turning it off changes nothing, and turning it on inserts it.
        var missing = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.SetApplicationConnectionAsync(c, actor, AppMissing, DirectoryContract.DatabaseConnectionKind, false, Cancellation));
        Assert.Equal(ApplicationConnectionWriteStatus.Unchanged, missing.Status);
        var on = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.SetApplicationConnectionAsync(c, actor, AppMissing, DirectoryContract.DatabaseConnectionKind, true, Cancellation));
        Assert.Equal(ApplicationConnectionWriteStatus.Saved, on.Status);
        Assert.True(on.Connection!.Enabled);

        // The system Application, a deleted one, another Tenant's, and an unknown Connection kind are never found.
        foreach (var (tenant, application, kind) in new[]
            {
                (TenantA, System, DirectoryContract.DatabaseConnectionKind),
                (TenantA, AppDeleted, DirectoryContract.DatabaseConnectionKind),
                (TenantA, AppOfB, DirectoryContract.DatabaseConnectionKind),
                (TenantA, AppOff, "social"),
            })
        {
            var refused = await InTenantAsync(
                database, TableRegistry.Admin, tenant, c => _directory.SetApplicationConnectionAsync(c, actor, application, kind, true, Cancellation));
            Assert.Equal(ApplicationConnectionWriteStatus.NotFound, refused.Status);
        }

        Assert.False(await PostgresFixture.ScalarAsync<bool>(
            superuser, $"SELECT enabled FROM application_connection WHERE tenant_id = '{TenantA}' AND application_id = '{AppOn}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM application_connection WHERE application_id = '{System}'"));
        Assert.Equal(2L, await PostgresFixture.ScalarAsync<long>(
            superuser,
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = 'directory.application_connection.updated' AND target_kind = 'client'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM audit_event WHERE type_code = 'directory.application_connection.updated' AND target_id = '{AppOn}'"));
    }

    [Fact]
    public async Task A_Connections_Applications_are_the_visible_ones_it_is_enabled_for_by_name()
    {
        var (database, _) = await SeededAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), ApplicationSql(TenantA, Guid.CreateVersion7(), "Admin console", enabled: true));

        var applications = await InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.ListConnectionApplicationsAsync(c, DirectoryContract.DatabaseConnectionKind, Cancellation));
        Assert.Equal(["Admin console", "Shop"], applications!.Select(a => a.Name));
        Assert.All(applications!, a => Assert.StartsWith("app_", a.ClientId, StringComparison.Ordinal));

        var lists = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationConnectionsAsync(c, AppOff, Cancellation));
        var only = Assert.Single(lists!);
        Assert.Equal((DirectoryContract.DatabaseConnectionKind, false, true), (only.Kind, only.Enabled, only.TenantEnabled));
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationConnectionsAsync(c, System, Cancellation)));
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListApplicationConnectionsAsync(c, AppDeleted, Cancellation)));

        // Tenant B has no Connection; an unknown kind names none.
        Assert.Null(await InTenantAsync(
            database, TableRegistry.Admin, TenantB, c => _directory.ListConnectionApplicationsAsync(c, DirectoryContract.DatabaseConnectionKind, Cancellation)));
        Assert.Null(await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.ListConnectionApplicationsAsync(c, "social", Cancellation)));
    }

    /// <summary>What no role may do to <c>application_connection</c>, by role.</summary>
    public static TheoryData<string, string> Refusals => new()
    {
        { TableRegistry.Admin, "DELETE FROM application_connection" },
        { TableRegistry.Admin, "UPDATE application_connection SET connection_id = gen_random_uuid()" },
        { TableRegistry.Admin, "UPDATE application_connection SET application_id = gen_random_uuid()" },
        { TableRegistry.Hosted, $"INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled) VALUES ('{TenantA}', '{AppMissing}', gen_random_uuid(), true)" },
        { TableRegistry.Hosted, "UPDATE application_connection SET enabled = true" },
        { TableRegistry.Hosted, "DELETE FROM application_connection" },
        { TableRegistry.Worker, "UPDATE application_connection SET enabled = true" },
        // The purges read only the columns their WHEREs name.
        { TableRegistry.Worker, "SELECT enabled FROM application_connection" },
        { TableRegistry.Worker, "SELECT connection_id FROM application_connection" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task Each_role_is_held_to_its_grants(string role, string sql)
    {
        var (database, _) = await SeededAsync();

        await using var connection = new NpgsqlConnection(postgres.RoleConnection(role, database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand($"SELECT set_config('gatekeep.tenant_id', '{TenantA}', false); {sql}", connection);
        var refused = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
        Assert.Equal(PermissionDenied, refused.SqlState);
    }

    [Fact]
    public async Task Each_Tenant_reads_and_writes_only_its_own_rows()
    {
        var (database, _) = await SeededAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"INSERT INTO connection (tenant_id, id, kind) VALUES ('{TenantB}', gen_random_uuid(), 'database'); " + TestTenants.EnableConnectionsSql(TenantB));

        foreach (var (tenant, count) in new[] { (TenantA, 3L), (TenantB, 1L) })
        {
            foreach (var role in new[] { TableRegistry.Admin, TableRegistry.Hosted })
            {
                Assert.Equal(count, await InTenantAsync(database, role, tenant, async c =>
                {
                    await using var command = c.CreateCommand();
                    command.CommandText = "SELECT count(*) FROM application_connection";
                    return (long)(await command.ExecuteScalarAsync(Cancellation))!;
                }));
            }
        }

        // A row naming another Tenant is refused by the restrictive policy.
        var refused = await Assert.ThrowsAsync<PostgresException>(() => InTenantAsync(database, TableRegistry.Admin, TenantB, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText =
                "INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled) "
                + $"VALUES ('{TenantA}', '{AppMissing}', gen_random_uuid(), true)";
            return await command.ExecuteNonQueryAsync(Cancellation);
        }));
        Assert.Equal(PermissionDenied, refused.SqlState);
    }

    /// <summary>
    /// Tenants A and B. A has its system Application, one Application with the database Connection on, one with it off,
    /// one with no row and a deleted one with it on; B has one Application and no Connection.
    /// </summary>
    private async Task<(string Database, Guid Connection)> SeededAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        var connection = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(superuser, TestTenants.InsertSql(TenantA, TenantB));
        await PostgresFixture.ExecuteAsync(
            superuser,
            $"INSERT INTO connection (tenant_id, id, kind) VALUES ('{TenantA}', '{connection}', 'database'); "
            + SystemSql(TenantA) + "; "
            + ApplicationSql(TenantA, AppOn, "Shop", enabled: true) + "; "
            + ApplicationSql(TenantA, AppOff, "Back office", enabled: false) + "; "
            + ApplicationSql(TenantA, AppMissing, "Kiosk") + "; "
            + ApplicationSql(TenantA, AppDeleted, "Gone", deleted: true, enabled: true) + "; "
            + ApplicationSql(TenantB, AppOfB, "B app"));
        return (database, connection);
    }

    private static string SystemSql(Guid tenant) =>
        $"INSERT INTO application (tenant_id, id, name, kind, created_at) VALUES ('{tenant}', '{System}', 'Account Portal', 'system', now())";

    /// <summary>A web Application, and with <paramref name="enabled"/> its row for each of the Tenant's Connections.</summary>
    private static string ApplicationSql(Guid tenant, Guid id, string name, bool deleted = false, bool? enabled = null) =>
        "INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at, deleted_at) "
        + $"VALUES ('{tenant}', '{id}', '{name}', 'web', ARRAY['authorization_code'], now(), {(deleted ? "now()" : "NULL")})"
        + (enabled is { } on
            ? "; INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled) "
              + $"SELECT tenant_id, '{id}', id, {(on ? "true" : "false")} FROM connection WHERE tenant_id = '{tenant}'"
            : string.Empty);

    private async Task<T> InTenantAsync<T>(string database, string role, Guid tenantId, Func<CommandContext, Task<T>> body)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        var result = await body(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }
}
