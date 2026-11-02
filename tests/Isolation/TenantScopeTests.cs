using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation;

public sealed class TenantScopeTests(PostgresFixture postgres)
{
    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Empty_Tenant_ID_is_refused_before_opening_a_transaction()
    {
        // Nothing listens here, so reaching the database would raise a different exception.
        await using var dataSource = NpgsqlDataSource.Create("Host=127.0.0.1;Port=1;Timeout=1");

        await Assert.ThrowsAsync<ArgumentException>(
            () => TenantScope.BeginAsync(dataSource, Guid.Empty, Cancellation));
    }

    [Fact]
    public async Task Setting_is_transaction_local_and_read_back_exactly()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await using var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var scope = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        var context = scope.CreateCommandContext();

        await using var command = context.CreateCommand();
        command.CommandText = "SELECT current_setting('gatekeep.tenant_id')";

        Assert.Equal(TenantA.ToString(), await command.ExecuteScalarAsync(Cancellation));
        Assert.Equal(TenantA, context.TenantId);
    }

    [Fact]
    public async Task Commit_keeps_the_write()
    {
        var database = await TenantDatabaseAsync();

        await using (var scope = await AdminScopeAsync(database))
        {
            await InsertSettingsAsync(scope);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(1, await SettingsCountAsync(database));
    }

    [Fact]
    public async Task Disposing_without_commit_rolls_back()
    {
        var database = await TenantDatabaseAsync();

        await using (var scope = await AdminScopeAsync(database))
        {
            await InsertSettingsAsync(scope);
        }

        Assert.Equal(0, await SettingsCountAsync(database));
    }

    [Fact]
    public async Task A_finished_scope_can_no_longer_be_used()
    {
        var database = await TenantDatabaseAsync();
        await using var scope = await AdminScopeAsync(database);
        var context = scope.CreateCommandContext();

        await scope.CommitAsync(Cancellation);

        Assert.Throws<InvalidOperationException>(() => context.CreateCommand());
        Assert.Throws<InvalidOperationException>(() => scope.CreateCommandContext());
        await Assert.ThrowsAsync<InvalidOperationException>(() => scope.CommitAsync(Cancellation));
    }

    [Fact]
    public async Task A_command_made_before_commit_cant_run_after_it()
    {
        var database = await TenantDatabaseAsync();
        await using var scope = await AdminScopeAsync(database);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"INSERT INTO tenant (id) VALUES ('{Guid.NewGuid()}')";

        await scope.CommitAsync(Cancellation);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => command.ExecuteNonQueryAsync(Cancellation));

        var tenants = await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), "SELECT count(*) FROM tenant");
        Assert.Equal(1, tenants);
    }

    [Fact]
    public async Task Disposing_a_committed_scope_leaves_the_next_scope_on_that_connection_alone()
    {
        var database = await TenantDatabaseAsync();
        var builder = new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Admin, database))
        {
            Pooling = true,
            MaxPoolSize = 1,
        };
        await using var dataSource = NpgsqlDataSource.Create(builder.ConnectionString);

        var first = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await first.CommitAsync(Cancellation);

        await using var second = await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
        await InsertSettingsAsync(second);

        await first.DisposeAsync();

        await second.CommitAsync(Cancellation);

        Assert.Equal(1, await SettingsCountAsync(database));
    }

    private async Task<string> TenantDatabaseAsync()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database), $"INSERT INTO tenant (id) VALUES ('{TenantA}')");
        return database;
    }

    private async Task<TenantScope> AdminScopeAsync(string database)
    {
        var dataSource = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        return await TenantScope.BeginAsync(dataSource, TenantA, Cancellation);
    }

    private static async Task InsertSettingsAsync(TenantScope scope)
    {
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = $"INSERT INTO tenant_settings (tenant_id) VALUES ('{TenantA}')";
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    private Task<long> SettingsCountAsync(string database) =>
        PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM tenant_settings");
}
