using System.Data.Common;
using Gatekeep.Adapters.Postgres;

const int Success = 0;
const int Failure = 1;
const int UsageError = 2;

if (args is not ["migrate", "--connection-file", var path])
{
    Console.Error.WriteLine("Usage: gatekeep migrate --connection-file <path>");
    return UsageError;
}

string connectionString;
try
{
    connectionString = (await File.ReadAllTextAsync(path)).Trim();
}
catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
{
    Console.Error.WriteLine("Can't read the connection file.");
    return Failure;
}

if (connectionString.Length == 0)
{
    Console.Error.WriteLine("The connection file is empty.");
    return Failure;
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
