using System.Diagnostics;
using Gatekeep.Adapters.Postgres;
using Gatekeep.Adapters.Postgres.Schema;
using Xunit;

namespace Gatekeep.Tests.Isolation;

/// <summary>Runs the real <c>gatekeep migrate</c> command in its own process.</summary>
public sealed class MigrateCommandTests(PostgresFixture postgres) : IDisposable
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(1);

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-migrate-").FullName;

    [Fact]
    public async Task Running_twice_applies_once_and_both_succeed()
    {
        var database = await postgres.NewUnmigratedDatabaseAsync();
        var file = ConnectionFile(postgres.RoleConnection(TableRegistry.Migrator, database));

        var first = await MigrateAsync(file);
        Assert.True(first.ExitCode == 0, first.Output);
        Assert.Contains("Applied 2 migration(s).", first.Output);

        var second = await MigrateAsync(file);
        Assert.True(second.ExitCode == 0, second.Output);
        Assert.Contains("No migrations to apply.", second.Output);

        var applied = await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), $"SELECT count(*) FROM {GatekeepMigrator.HistoryTable}");
        Assert.Equal(2, applied);
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

    private static async Task<(int ExitCode, string Output)> RunAsync(params string[] arguments)
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        var start = new ProcessStartInfo(string.IsNullOrEmpty(host) ? "dotnet" : host)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "gatekeep.dll"));
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        using var timeout = new CancellationTokenSource(CommandTimeout);

        try
        {
            var standardOutput = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var standardError = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);

            return (process.ExitCode, await standardOutput + await standardError);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }
    }
}
