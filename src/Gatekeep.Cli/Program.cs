using System.Data.Common;
using Gatekeep.Adapters.Postgres;
using Gatekeep.Kernel.Secrets;

const int Success = 0;
const int Failure = 1;
const int UsageError = 2;

// The cli Compose service sets these, so `docker compose run --rm cli migrate` needs no paths.
const string ConnectionFileVariable = "GATEKEEP_MIGRATE_CONNECTION_FILE";
const string PasswordFileVariable = "GATEKEEP_MIGRATE_PASSWORD_FILE";

const string Usage = """
    Usage: gatekeep migrate --connection-file <path> [--password-file <path>]
           gatekeep migrate    (with GATEKEEP_MIGRATE_CONNECTION_FILE and GATEKEEP_MIGRATE_PASSWORD_FILE set)
    """;

var defaultConnectionFile = Environment.GetEnvironmentVariable(ConnectionFileVariable);
var defaultPasswordFile = Environment.GetEnvironmentVariable(PasswordFileVariable);

return args switch
{
    ["migrate"] when !string.IsNullOrEmpty(defaultConnectionFile) && !string.IsNullOrEmpty(defaultPasswordFile) =>
        await MigrateAsync(defaultConnectionFile, defaultPasswordFile),
    ["migrate", "--connection-file", var path] => await MigrateAsync(path, passwordPath: null),
    ["migrate", "--connection-file", var path, "--password-file", var passwordPath] => await MigrateAsync(path, passwordPath),
    _ => ShowUsage(),
};

static int ShowUsage()
{
    Console.Error.WriteLine(Usage);
    return UsageError;
}

static async Task<string?> ReadFileAsync(string path)
{
    try
    {
        return await File.ReadAllTextAsync(path);
    }
    catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
    {
        return null;
    }
}

static async Task<int> MigrateAsync(string path, string? passwordPath)
{
    var connectionString = (await ReadFileAsync(path))?.Trim();
    if (connectionString is null)
    {
        Console.Error.WriteLine("Can't read the connection file.");
        return Failure;
    }

    if (connectionString.Length == 0)
    {
        Console.Error.WriteLine("The connection file is empty.");
        return Failure;
    }

    if (passwordPath is not null)
    {
        // A Compose secret: the connection file then holds no password.
        var password = (await ReadFileAsync(passwordPath))?.TrimEnd('\r', '\n');
        if (string.IsNullOrEmpty(password))
        {
            Console.Error.WriteLine("Can't read the password file, or it's empty.");
            return Failure;
        }

        // gk_migrator owns the schema, so it gets the same refusal as every host (AD-26).
        if (SecretDefaults.IsUnsafePassword(password))
        {
            Console.Error.WriteLine("The password file holds a known default or a password under 16 characters.");
            return Failure;
        }

        try
        {
            connectionString = new DbConnectionStringBuilder { ConnectionString = connectionString, ["Password"] = password }
                .ConnectionString;
        }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("The connection file isn't a valid connection string.");
            return Failure;
        }
    }

    try
    {
        var applied = await GatekeepMigrator.MigrateAsync(connectionString, CancellationToken.None);

        Console.WriteLine(applied.Count == 0 ? "No migrations to apply." : $"Applied {applied.Count} migration(s).");
        foreach (var migration in applied)
        {
            Console.WriteLine(migration);
        }

        return Success;
    }
    catch (WrongMigrationRoleException e)
    {
        Console.Error.WriteLine(e.Message);
        return Failure;
    }
    catch (ArgumentException)
    {
        // Its message can quote the connection string, which holds the password.
        Console.Error.WriteLine("The connection file isn't a valid connection string.");
        return Failure;
    }
    catch (DbException e)
    {
        Console.Error.WriteLine($"Migration failed: {e.GetType().Name} {e.SqlState}".TrimEnd());
        return Failure;
    }
    catch (Exception e)
    {
        // An unhandled exception would print its message and stack trace.
        Console.Error.WriteLine($"Migration failed: {e.GetType().Name}");
        return Failure;
    }
}
