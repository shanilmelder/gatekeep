using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Connections;

/// <summary>
/// Story 4.6 (FR-17, FR-18): each Tenant's one database Connection. The migration's backfill and Directory's ensure each
/// give a creating or active Tenant exactly one, with the column defaults, which are Directory's defaults; a rerun adds
/// nothing, and a deleting Tenant gets none. The table holds every role to its grants: Host.Admin changes only the sign-up
/// switch and the password policy, Host.Hosted only reads it, and password history is Host.Hosted's to keep.
/// </summary>
public sealed class DatabaseConnectionTests(PostgresFixture postgres)
{
    private const string PermissionDenied = "42501";

    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-0000000046a1");
    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-0000000046a2");
    private static readonly Guid TenantC = Guid.Parse("01900000-0000-7000-8000-0000000046a3");
    private static readonly Guid TenantD = Guid.Parse("01900000-0000-7000-8000-0000000046a4");

    private readonly IDirectory _directory = DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_column_defaults_are_Directorys_defaults()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);

        async Task<string> DefaultOf(string column) => await PostgresFixture.ScalarAsync<string>(
            superuser,
            $"SELECT column_default FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'connection' AND column_name = '{column}'");

        var policy = DirectoryContract.DefaultPasswordPolicy;
        Assert.Equal($"'{DirectoryContract.DatabaseConnectionName}'::text", await DefaultOf("name"));
        Assert.Equal("true", await DefaultOf("enabled"));
        Assert.Equal(DirectoryContract.DefaultSignupEnabled ? "true" : "false", await DefaultOf("signup_enabled"));
        Assert.Equal(policy.MinLength.ToString(System.Globalization.CultureInfo.InvariantCulture), await DefaultOf("password_min_length"));
        Assert.Equal($"'{policy.Strength}'::text", await DefaultOf("password_strength"));
        Assert.Equal(policy.HistoryCount.ToString(System.Globalization.CultureInfo.InvariantCulture), await DefaultOf("password_history_count"));
        Assert.Equal(policy.Dictionary ? "true" : "false", await DefaultOf("password_dictionary"));
        Assert.Equal(policy.PersonalData ? "true" : "false", await DefaultOf("password_personal_data"));

        // The backfill names the same kind and name Directory inserts.
        Assert.Contains($"'{DirectoryContract.DatabaseConnectionKind}', '{DirectoryContract.DatabaseConnectionName}'", Migration20261127000000ConfigureDatabaseConnection.BackfillConnection, StringComparison.Ordinal);
    }

    /// <summary>
    /// The migration's backfill, rendered through the same <c>ForEachTenant</c> the migration calls and run twice as the
    /// migrator over Tenants seeded after migrating.
    /// </summary>
    [Fact]
    public async Task Backfill_gives_each_creating_or_active_Tenant_exactly_one_database_Connection()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        await TestTenants.InsertAsync(superuser, TenantC, status: "deleting");
        await TestTenants.InsertAsync(superuser, TenantD, status: "creating");

        var builder = new MigrationBuilder("Npgsql.EntityFrameworkCore.PostgreSQL");
        builder.ForEachTenant(Migration20261127000000ConfigureDatabaseConnection.BackfillConnection);
        var sql = Assert.IsType<SqlOperation>(Assert.Single(builder.Operations)).Sql;

        // The migration's Up() runs exactly that statement, last.
        var migration = new Migration20261127000000ConfigureDatabaseConnection { ActiveProvider = "Npgsql.EntityFrameworkCore.PostgreSQL" };
        Assert.Equal(sql, Assert.IsType<SqlOperation>(migration.UpOperations[^1]).Sql);

        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);
        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Migrator, database), sql);

        foreach (var tenant in new[] { TenantA, TenantB, TenantD })
        {
            Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
                superuser,
                $"SELECT count(*) FROM connection WHERE tenant_id = '{tenant}' AND kind = 'database' AND name = 'Username-Password' " +
                "AND enabled AND signup_enabled AND password_min_length = 12 AND password_strength = 'good' AND password_history_count = 5 " +
                "AND password_dictionary AND password_personal_data"));
        }

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM connection WHERE tenant_id = '{TenantC}'"));
        Assert.Equal(3L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM connection"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event"));
    }

    /// <summary>
    /// The ensure, as gk_worker, inserts the Connection once; once it exists it attempts no insert, so a Tenant whose
    /// deletion has since started isn't refused by the row guard.
    /// </summary>
    [Fact]
    public async Task Ensuring_inserts_once_and_attempts_nothing_once_it_exists()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);

        Assert.True(await InTenantAsync(database, TableRegistry.Worker, TenantA, c => _directory.EnsureDatabaseConnectionAsync(c, Cancellation)));
        var id = await PostgresFixture.ScalarAsync<Guid>(superuser, $"SELECT id FROM connection WHERE tenant_id = '{TenantA}'");
        Assert.Equal(7, id.Version);

        await PostgresFixture.ExecuteAsync(superuser, $"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{TenantA}'; SET session_replication_role = DEFAULT");
        Assert.False(await InTenantAsync(database, TableRegistry.Worker, TenantA, c => _directory.EnsureDatabaseConnectionAsync(c, Cancellation)));

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM connection"));
        Assert.Equal(id, await PostgresFixture.ScalarAsync<Guid>(superuser, $"SELECT id FROM connection WHERE tenant_id = '{TenantA}'"));

        // Another Tenant's ensure sees only its own.
        Assert.True(await InTenantAsync(database, TableRegistry.Worker, TenantB, c => _directory.EnsureDatabaseConnectionAsync(c, Cancellation)));
        var read = await InTenantAsync(database, TableRegistry.Hosted, TenantB, c => _directory.FindDatabaseConnectionAsync(c, Cancellation));
        Assert.NotNull(read);
        Assert.NotEqual(id, read.Id);
        Assert.Equal(DirectoryContract.DefaultPasswordPolicy, read.Policy);
        Assert.True(read.SignupEnabled);
    }

    /// <summary>What no role may do to the Connection and password history, by role.</summary>
    public static TheoryData<string, string> Refusals => new()
    {
        { TableRegistry.Admin, "UPDATE connection SET name = 'x'" },
        { TableRegistry.Admin, "UPDATE connection SET kind = 'database'" },
        { TableRegistry.Admin, "UPDATE connection SET enabled = false" },
        { TableRegistry.Admin, "DELETE FROM connection" },
        { TableRegistry.Admin, $"INSERT INTO connection (tenant_id, id, kind) VALUES ('{TenantA}', gen_random_uuid(), 'database')" },
        { TableRegistry.Admin, "SELECT count(*) FROM password_history" },
        { TableRegistry.Hosted, "UPDATE connection SET signup_enabled = false" },
        { TableRegistry.Hosted, "DELETE FROM connection" },
        { TableRegistry.Hosted, "UPDATE password_history SET password_hash = 'x'" },
        { TableRegistry.Worker, "UPDATE connection SET signup_enabled = false" },
        // The purge reads only the column its WHERE names: never a hash.
        { TableRegistry.Worker, "SELECT password_hash FROM password_history" },
        { TableRegistry.Worker, "SELECT user_id FROM password_history" },
    };

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task Each_role_is_held_to_its_grants(string role, string sql)
    {
        var database = await DatabaseAsync();

        await using var connection = new NpgsqlConnection(postgres.RoleConnection(role, database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand($"SELECT set_config('gatekeep.tenant_id', '{TenantA}', false); {sql}", connection);
        var refused = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync(Cancellation));
        Assert.Equal(PermissionDenied, refused.SqlState);
    }

    [Fact]
    public async Task Host_Admin_changes_the_sign_up_switch_and_the_policy_and_each_change_writes_one_event()
    {
        var database = await DatabaseAsync();
        await InTenantAsync(database, TableRegistry.Worker, TenantA, c => _directory.EnsureDatabaseConnectionAsync(c, Cancellation));
        var actor = Gatekeep.Kernel.Audit.Actor.Admin(Guid.CreateVersion7());

        var off = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.UpdateDatabaseConnectionSettingsAsync(c, actor, false, Cancellation));
        Assert.Equal(ConnectionWriteStatus.Saved, off.Status);
        Assert.False(off.Connection!.SignupEnabled);

        var again = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.UpdateDatabaseConnectionSettingsAsync(c, actor, false, Cancellation));
        Assert.Equal(ConnectionWriteStatus.Unchanged, again.Status);

        var policy = new PasswordPolicy(20, PasswordStrengths.Excellent, 0, Dictionary: false, PersonalData: true);
        var saved = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.UpdatePasswordPolicyAsync(c, actor, policy, Cancellation));
        Assert.Equal(ConnectionWriteStatus.Saved, saved.Status);
        Assert.Equal(policy, saved.Connection!.Policy);

        var same = await InTenantAsync(database, TableRegistry.Admin, TenantA, c => _directory.UpdatePasswordPolicyAsync(c, actor, policy, Cancellation));
        Assert.Equal(ConnectionWriteStatus.Unchanged, same.Status);

        // Another Tenant has no Connection: nothing found, nothing written.
        var none = await InTenantAsync(database, TableRegistry.Admin, TenantB, c => _directory.UpdatePasswordPolicyAsync(c, actor, policy, Cancellation));
        Assert.Equal(ConnectionWriteStatus.NotFound, none.Status);

        var superuser = postgres.SuperuserConnection(database);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = 'directory.connection.updated' AND target_kind = 'tenant' AND target_id = '{TenantA}'"));
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(
            superuser, $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = 'directory.connection.password_policy_updated' AND target_kind = 'tenant' AND target_id = '{TenantA}'"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantB}'"));

        await Assert.ThrowsAsync<ArgumentException>(() => InTenantAsync(
            database, TableRegistry.Admin, TenantA, c => _directory.UpdatePasswordPolicyAsync(c, actor, policy with { MinLength = 11 }, Cancellation)));
    }

    [Fact]
    public async Task Host_Hosted_keeps_password_history_and_only_its_own_Tenants()
    {
        var database = await DatabaseAsync();
        var superuser = postgres.SuperuserConnection(database);
        var user = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(superuser, $"INSERT INTO \"user\" (tenant_id, id) VALUES ('{TenantA}', '{user}')");

        await InTenantAsync(database, TableRegistry.Hosted, TenantA, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText = $"INSERT INTO password_history (tenant_id, id, user_id, password_hash) VALUES ('{TenantA}', gen_random_uuid(), '{user}', '$argon2id$x')";
            return await command.ExecuteNonQueryAsync(Cancellation);
        });

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(superuser, $"SELECT count(*) FROM password_history WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(0L, await InTenantAsync(database, TableRegistry.Hosted, TenantB, async c =>
        {
            await using var command = c.CreateCommand();
            command.CommandText = "SELECT count(*) FROM password_history";
            return (long)(await command.ExecuteScalarAsync(Cancellation))!;
        }));
    }

    private async Task<T> InTenantAsync<T>(string database, string role, Guid tenantId, Func<CommandContext, Task<T>> body)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, Cancellation);
        var result = await body(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }

    private async Task<string> DatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA, TenantB));
        return database;
    }
}
