using Gatekeep.Adapters.Postgres;
using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

[assembly: AssemblyFixture(typeof(Gatekeep.Tests.Isolation.PostgresFixture))]

namespace Gatekeep.Tests.Isolation;

/// <summary>
/// One real PostgreSQL for the run. Each test gets its own database, cloned from a
/// template that holds <c>roles.sql</c> output, either before or after migrating.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    public const string Image = "postgres:18.6";
    /// <summary>
    /// Fresh for each run. A fixed test password would be public, and hosts refuse a known
    /// default, so this one is random and only lives as long as the container.
    /// </summary>
    public static readonly string Password = "isolation-" + Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12));

    private const string ClusterDatabase = "gatekeep_cluster";
    private const string Unmigrated = "gatekeep_unmigrated";
    private const string Migrated = "gatekeep_migrated";

    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder(Image)
        .WithDatabase(ClusterDatabase)
        .Build();

    // PostgreSQL refuses to clone a template while another clone holds it.
    private readonly SemaphoreSlim _cloneLock = new(1, 1);

    // CREATE DATABASE doesn't copy a template's database ACL, so each clone runs roles.sql
    // again without its CREATE ROLE lines, which are cluster-wide and already done.
    private string _databaseGrantsSql = string.Empty;

    public async ValueTask InitializeAsync()
    {
        await _container.StartAsync();

        var rolesPath = Path.Combine(FindRepositoryRoot(), "deploy", "postgres", "roles.sql");
        var rolesLines = await File.ReadAllLinesAsync(rolesPath);
        _databaseGrantsSql = string.Join('\n', rolesLines.Where(l => !l.StartsWith("CREATE ROLE", StringComparison.Ordinal)));

        await ExecuteAsync(SuperuserConnection(ClusterDatabase), $"CREATE DATABASE {Unmigrated}");
        await ExecuteAsync(SuperuserConnection(Unmigrated), string.Join('\n', rolesLines));

        foreach (var role in TableRegistry.RuntimeRoles.Append(TableRegistry.Migrator))
        {
            await ExecuteAsync(SuperuserConnection(ClusterDatabase), $"ALTER ROLE {role} PASSWORD '{Password}'");
        }

        await ExecuteAsync(SuperuserConnection(ClusterDatabase), $"CREATE DATABASE {Migrated} TEMPLATE {Unmigrated}");
        await ExecuteAsync(SuperuserConnection(Migrated), _databaseGrantsSql);
        await GatekeepMigrator.MigrateAsync(RoleConnection(TableRegistry.Migrator, Migrated), CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        _cloneLock.Dispose();
        await _container.DisposeAsync();
    }

    public Task<string> NewMigratedDatabaseAsync() => CloneAsync(Migrated);

    public Task<string> NewUnmigratedDatabaseAsync() => CloneAsync(Unmigrated);

    public string SuperuserConnection(string database) =>
        new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
        {
            Database = database,
            Pooling = false,
        }.ConnectionString;

    public string RoleConnection(string role, string database) =>
        new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
        {
            Username = role,
            Password = Password,
            Database = database,
            Pooling = false,
        }.ConnectionString;

    public static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    public static async Task<T> ScalarAsync<T>(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        return (T)(await command.ExecuteScalarAsync())!;
    }

    private async Task<string> CloneAsync(string template)
    {
        var database = "test_" + Guid.NewGuid().ToString("N");

        await _cloneLock.WaitAsync();
        try
        {
            await ExecuteAsync(SuperuserConnection(ClusterDatabase), $"CREATE DATABASE {database} TEMPLATE {template}");
        }
        finally
        {
            _cloneLock.Release();
        }

        await ExecuteAsync(SuperuserConnection(database), _databaseGrantsSql);

        return database;
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Gatekeep.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("No Gatekeep.slnx above the test output.");
    }
}
