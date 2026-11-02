using Gatekeep.Adapters.Postgres;
using Gatekeep.Adapters.Postgres.Migrations;
using Gatekeep.Adapters.Postgres.Schema;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class DataMigrationTests(PostgresFixture postgres)
{
    internal const string FailingTenant = "01900000-0000-7000-8000-00000000000b";

    private const string TenantA = "01900000-0000-7000-8000-00000000000a";
    private const string Epoch = "2026-01-01 00:00:00+00";

    [Fact]
    public async Task ForEachTenant_changes_each_row_once_under_its_own_Tenant()
    {
        var database = await SeededDatabaseAsync();

        await using (var context = NewContext<SucceedingContext>(database))
        {
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
        }

        // One extra day means one pass over each row. Without the scope the statement
        // raises an error, and with a wider one each row gets a day per Tenant.
        Assert.Equal(2, await RowsAtAsync(database, "1 day"));
    }

    [Fact]
    public async Task Failure_in_one_Tenant_rolls_the_migration_back()
    {
        var database = await SeededDatabaseAsync();

        await using (var context = NewContext<FailingContext>(database))
        {
            await Assert.ThrowsAsync<Npgsql.PostgresException>(() => context.Database.MigrateAsync(TestContext.Current.CancellationToken));
        }

        // TenantA ran first and its change went with the rollback.
        Assert.Equal(2, await RowsAtAsync(database, "0 days"));

        var recorded = await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database),
            $"""SELECT count(*) FROM {GatekeepMigrator.HistoryTable} WHERE "MigrationId" LIKE '%Failing%'""");
        Assert.Equal(0, recorded);
    }

    [Fact]
    public async Task ForEachTenant_leaves_no_Tenant_set_for_later_statements()
    {
        var database = await SeededDatabaseAsync();

        await using var context = NewContext<LaterStatementContext>(database);

        var error = await Assert.ThrowsAsync<Npgsql.PostgresException>(
            () => context.Database.MigrateAsync(TestContext.Current.CancellationToken));

        Assert.Equal("22P02", error.SqlState);
    }

    [Theory]
    [InlineData("SELECT $gatekeep_block$x$gatekeep_block$")]
    [InlineData("SELECT $gatekeep_statement$x$gatekeep_statement$")]
    [InlineData("SELECT $gatekeep_other$x$gatekeep_other$")]
    public void ForEachTenant_refuses_its_reserved_quote_tags(string statement)
    {
        var builder = new MigrationBuilder("Npgsql.EntityFrameworkCore.PostgreSQL");

        Assert.Throws<ArgumentException>(() => builder.ForEachTenant(statement));
        Assert.Empty(builder.Operations);
    }

    [Fact]
    public void ForEachTenant_accepts_other_quote_tags()
    {
        var builder = new MigrationBuilder("Npgsql.EntityFrameworkCore.PostgreSQL");

        builder.ForEachTenant("SELECT $tag$x$tag$");

        Assert.Single(builder.Operations);
    }

    [Fact]
    public void Every_migration_is_forward_only()
    {
        var migrations = typeof(MigrationsContext).Assembly.GetTypes()
            .Where(t => t.IsSubclassOf(typeof(Migration)))
            .ToList();

        Assert.NotEmpty(migrations);

        foreach (var type in migrations)
        {
            var migration = (Migration)Activator.CreateInstance(type)!;

            Assert.Throws<NotSupportedException>(() => migration.DownOperations);
        }
    }

    private async Task<string> SeededDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO tenant (id) VALUES ('{TenantA}'), ('{FailingTenant}');
            INSERT INTO tenant_settings (tenant_id, updated_at)
            VALUES ('{TenantA}', '{Epoch}'), ('{FailingTenant}', '{Epoch}');
            """);

        return database;
    }

    private Task<long> RowsAtAsync(string database, string offset) =>
        PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database),
            $"SELECT count(*) FROM tenant_settings WHERE updated_at = timestamptz '{Epoch}' + interval '{offset}'");

    private TContext NewContext<TContext>(string database)
        where TContext : DbContext
    {
        var options = new DbContextOptionsBuilder<TContext>()
            .UseNpgsql(
                postgres.RoleConnection(TableRegistry.Migrator, database),
                npgsql => npgsql
                    .MigrationsHistoryTable(GatekeepMigrator.HistoryTable)
                    .MigrationsAssembly(typeof(DataMigrationTests).Assembly.GetName().Name))
            .ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.ModelSnapshotNotFound))
            .Options;

        return (TContext)Activator.CreateInstance(typeof(TContext), options)!;
    }
}

public sealed class SucceedingContext(DbContextOptions<SucceedingContext> options) : DbContext(options);

public sealed class FailingContext(DbContextOptions<FailingContext> options) : DbContext(options);

public sealed class LaterStatementContext(DbContextOptions<LaterStatementContext> options) : DbContext(options);

[DbContext(typeof(LaterStatementContext))]
[Migration("29990101000002_LaterStatementDataMigration")]
public sealed class LaterStatementDataMigration : Migration
{
    // Without the reset, the second statement would run as the last Tenant.
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.ForEachTenant("UPDATE tenant_settings SET updated_at = updated_at");
        migrationBuilder.Sql("UPDATE tenant_settings SET updated_at = updated_at");
    }
}

[DbContext(typeof(SucceedingContext))]
[Migration("29990101000000_SucceedingDataMigration")]
public sealed class SucceedingDataMigration : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.ForEachTenant("UPDATE tenant_settings SET updated_at = updated_at + interval '1 day'");
}

[DbContext(typeof(FailingContext))]
[Migration("29990101000001_FailingDataMigration")]
public sealed class FailingDataMigration : Migration
{
    // Divides by zero for the second Tenant in id order, after the first has changed.
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.ForEachTenant(
            $"""
            UPDATE tenant_settings
            SET updated_at = updated_at + interval '1 day' * (1 / (tenant_id <> '{DataMigrationTests.FailingTenant}')::int)
            """);
}
