using Gatekeep.Adapters.Postgres;
using Gatekeep.Adapters.Postgres.Schema;
using Xunit;

namespace Gatekeep.Tests.Isolation;

/// <summary>Runs the real <c>gatekeep migrate</c> command in its own process.</summary>
public sealed class MigrateCommandTests(PostgresFixture postgres) : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-migrate-").FullName;

    [Fact]
    public async Task Running_twice_applies_once_and_both_succeed()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();
        var file = ConnectionFile(postgres.RoleConnection(TableRegistry.Migrator, database));

        var first = await MigrateAsync(file);
        Assert.True(first.ExitCode == 0, first.Output);
        Assert.Contains("Applied 29 migration(s).", first.Output);

        var second = await MigrateAsync(file);
        Assert.True(second.ExitCode == 0, second.Output);
        Assert.Contains("No migrations to apply.", second.Output);

        var applied = await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), $"SELECT count(*) FROM {GatekeepMigrator.HistoryTable}");
        Assert.Equal(29, applied);
    }

    [Fact]
    public async Task Password_file_supplies_the_password_the_connection_file_leaves_out()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();
        var connection = postgres.RoleConnection(TableRegistry.Migrator, database)
            .Replace($"Password={PostgresFixture.Password};", string.Empty);
        Assert.DoesNotContain(PostgresFixture.Password, connection);

        var result = await RunAsync(
            "migrate", "--connection-file", ConnectionFile(connection), "--password-file", ConnectionFile(PostgresFixture.Password + "\n"));

        Assert.True(result.ExitCode == 0, result.Output);
        Assert.Contains("Applied 29 migration(s).", result.Output);
        Assert.DoesNotContain(PostgresFixture.Password, result.Output);
    }

    [Theory]
    [InlineData("changeme")]
    [InlineData("postgres")]
    [InlineData("isolation-test-only")]
    [InlineData("fifteen-chars-x")]
    public async Task Default_or_short_password_file_is_refused_before_connecting(string password)
    {
        var result = await RunAsync(
            "migrate", "--connection-file", ConnectionFile("Host=localhost;Username=gk_migrator"), "--password-file", ConnectionFile(password + "\n"));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("The password file holds a known default or a password under 16 characters.", result.Output);
        Assert.DoesNotContain(password, result.Output);
    }

    [Fact]
    public async Task Bare_migrate_takes_both_files_from_the_environment()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();
        var connection = postgres.RoleConnection(TableRegistry.Migrator, database)
            .Replace($"Password={PostgresFixture.Password};", string.Empty);

        var result = await RunWithEnvironmentAsync(
            new Dictionary<string, string>
            {
                ["GATEKEEP_MIGRATE_CONNECTION_FILE"] = ConnectionFile(connection),
                ["GATEKEEP_MIGRATE_PASSWORD_FILE"] = ConnectionFile(PostgresFixture.Password),
            },
            "migrate");

        Assert.True(result.ExitCode == 0, result.Output);
        Assert.Contains("Applied 29 migration(s).", result.Output);
    }

    [Fact]
    public async Task Empty_password_file_exits_non_zero()
    {
        var result = await RunAsync(
            "migrate", "--connection-file", ConnectionFile("Host=localhost;Username=gk_migrator"), "--password-file", ConnectionFile(""));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Can't read the password file, or it's empty.", result.Output);
    }

    [Theory]
    [InlineData(TableRegistry.Hosted)]
    [InlineData(TableRegistry.Cli)]
    public async Task Runtime_role_is_refused_and_nothing_is_applied(string role)
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();

        await AssertRefusedAsync(postgres.RoleConnection(role, database), role, database, PostgresFixture.Password);
    }

    [Fact]
    public async Task Superuser_is_refused_and_nothing_is_applied()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();

        await AssertRefusedAsync(postgres.SuperuserConnection(database), "postgres", database, "postgres");
    }

    [Fact]
    public async Task Missing_connection_file_exits_non_zero()
    {
        var result = await MigrateAsync(Path.Combine(_directory, "absent"));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Can't read the connection file.", result.Output);
    }

    [Fact]
    public async Task Unreadable_connection_file_exits_non_zero()
    {
        // A directory stands in for an unreadable file on every platform and user.
        var result = await MigrateAsync(_directory);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Can't read the connection file.", result.Output);
    }

    [Fact]
    public async Task Empty_connection_file_exits_non_zero()
    {
        var result = await MigrateAsync(ConnectionFile("  \n"));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("The connection file is empty.", result.Output);
    }

    [Fact]
    public async Task Malformed_connection_file_exits_non_zero_without_echoing_it()
    {
        var result = await MigrateAsync(ConnectionFile("Password=hunter2;NotAKeyword=1"));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("The connection file isn't a valid connection string.", result.Output);
        Assert.DoesNotContain("hunter2", result.Output);
    }

    [Fact]
    public async Task Wrong_password_exits_non_zero_without_echoing_it()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();
        var connection = postgres.RoleConnection(TableRegistry.Migrator, database)
            .Replace(PostgresFixture.Password, "wrong-secret");

        var result = await MigrateAsync(ConnectionFile(connection));

        Assert.NotEqual(0, result.ExitCode);
        Assert.DoesNotContain("wrong-secret", result.Output);
    }

    [Fact]
    public async Task Other_arguments_exit_non_zero()
    {
        var result = await RunAsync("migrate");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Usage:", result.Output);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private async Task AssertRefusedAsync(string connection, string role, string database, string password)
    {
        var result = await MigrateAsync(ConnectionFile(connection));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(role, result.Output);
        Assert.DoesNotContain(password + ";", result.Output);
        Assert.DoesNotContain("Password", result.Output);
        Assert.DoesNotContain(database, result.Output);

        var tables = await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database),
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'");
        Assert.Equal(0, tables);
    }

    private string ConnectionFile(string contents)
    {
        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, contents);
        return path;
    }

    private static Task<(int ExitCode, string Output)> MigrateAsync(string file) =>
        RunAsync("migrate", "--connection-file", file);

    private static Task<(int ExitCode, string Output)> RunAsync(params string[] arguments) =>
        CliProcess.RunAsync(arguments);

    private static Task<(int ExitCode, string Output)> RunWithEnvironmentAsync(
        IReadOnlyDictionary<string, string> environment,
        params string[] arguments) =>
        CliProcess.RunWithEnvironmentAsync(environment, arguments);
}
