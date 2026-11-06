using System.Data.Common;
using System.Globalization;
using Gatekeep.Adapters.Postgres;
using Gatekeep.Cli;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;

const int Success = 0;
const int Failure = 1;
const int UsageError = 2;

// The cli Compose service sets these, so `docker compose run --rm cli migrate`,
// `docker compose run --rm cli audit verify` and `docker compose run --rm cli init` need no paths.
const string ConnectionFileVariable = "GATEKEEP_MIGRATE_CONNECTION_FILE";
const string PasswordFileVariable = "GATEKEEP_MIGRATE_PASSWORD_FILE";
const string CliConnectionFileVariable = "GATEKEEP_CLI_CONNECTION_FILE";
const string CliPasswordFileVariable = "GATEKEEP_CLI_PASSWORD_FILE";

// Where the cli service bind-mounts bootstrap/ from the host secrets directory.
const string DefaultTokenDirectory = "/gatekeep/bootstrap";

const string Usage = """
    Usage: gatekeep migrate --connection-file <path> [--password-file <path>]
           gatekeep migrate    (with GATEKEEP_MIGRATE_CONNECTION_FILE and GATEKEEP_MIGRATE_PASSWORD_FILE set)
           gatekeep audit verify --connection-file <path> [--password-file <path>]
           gatekeep audit verify    (with GATEKEEP_CLI_CONNECTION_FILE and GATEKEEP_CLI_PASSWORD_FILE set)
           gatekeep init [--token-dir <path>]    (with GATEKEEP_CLI_CONNECTION_FILE, GATEKEEP_CLI_PASSWORD_FILE,
                                                  GATEKEEP_CUSTODY_SOCKET, GATEKEEP_CUSTODY_ROLE_ID_FILE and
                                                  GATEKEEP_CUSTODY_SECRET_ID_FILE set;
                                                  the token directory defaults to /gatekeep/bootstrap)
           gatekeep rotate-transit-keys    (with the same settings as init: the last step of a Master Key rotation)
           gatekeep alerts test    (with GATEKEEP_ALERT_URL, GATEKEEP_ALERT_TOKEN_FILE and GATEKEEP_ALERT_DEPLOYMENT set)
           gatekeep records test    (with GATEKEEP_RECORDS_ENDPOINT, GATEKEEP_RECORDS_REGION, GATEKEEP_RECORDS_BUCKET,
                                     GATEKEEP_RECORDS_ACCESS_KEY_ID_FILE, GATEKEEP_RECORDS_SECRET_ACCESS_KEY_FILE
                                     and the custody settings init uses set)
           gatekeep audit-ship [--once]    (with the GATEKEEP_RECORDS_* settings, GATEKEEP_AUDIT_LOG_FILE and
                                            GATEKEEP_AUDIT_SHIP_STATE_DIR set)
    """;

var defaultConnectionFile = Environment.GetEnvironmentVariable(ConnectionFileVariable);
var defaultPasswordFile = Environment.GetEnvironmentVariable(PasswordFileVariable);
var cliConnectionFile = Environment.GetEnvironmentVariable(CliConnectionFileVariable);
var cliPasswordFile = Environment.GetEnvironmentVariable(CliPasswordFileVariable);
var cliReady = !string.IsNullOrEmpty(cliConnectionFile) && !string.IsNullOrEmpty(cliPasswordFile);

return args switch
{
    ["migrate"] when !string.IsNullOrEmpty(defaultConnectionFile) && !string.IsNullOrEmpty(defaultPasswordFile) =>
        await MigrateAsync(defaultConnectionFile, defaultPasswordFile),
    ["migrate", "--connection-file", var path] => await MigrateAsync(path, passwordPath: null),
    ["migrate", "--connection-file", var path, "--password-file", var passwordPath] => await MigrateAsync(path, passwordPath),
    ["audit", "verify"] when cliReady => await VerifyAsync(cliConnectionFile!, cliPasswordFile),
    ["audit", "verify", "--connection-file", var path] => await VerifyAsync(path, passwordPath: null),
    ["audit", "verify", "--connection-file", var path, "--password-file", var passwordPath] => await VerifyAsync(path, passwordPath),
    ["init"] when cliReady => await InitAsync(cliConnectionFile!, cliPasswordFile!, DefaultTokenDirectory, defaultDirectory: true),
    ["init", "--token-dir", var tokenDirectory] when cliReady && tokenDirectory.Length > 0 =>
        await InitAsync(cliConnectionFile!, cliPasswordFile!, tokenDirectory, defaultDirectory: false),
    ["rotate-transit-keys"] when cliReady => await RotateTransitKeysAsync(cliConnectionFile!, cliPasswordFile!),
    ["alerts", "test"] => await AlertsTestCommand.RunAsync(),
    ["records", "test"] => await RecordsTestCommand.RunAsync(),
    ["audit-ship"] => await AuditShipCommand.RunAsync(once: false),
    ["audit-ship", "--once"] => await AuditShipCommand.RunAsync(once: true),
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

/// <summary>The connection string from its file, with the password file's password in it. Null after saying why not.</summary>
static async Task<string?> ConnectionAsync(string path, string? passwordPath)
{
    var connectionString = (await ReadFileAsync(path))?.Trim();
    if (connectionString is null)
    {
        Console.Error.WriteLine("Can't read the connection file.");
        return null;
    }

    if (connectionString.Length == 0)
    {
        Console.Error.WriteLine("The connection file is empty.");
        return null;
    }

    if (passwordPath is null)
    {
        return connectionString;
    }

    // A Compose secret: the connection file then holds no password.
    var password = (await ReadFileAsync(passwordPath))?.TrimEnd('\r', '\n');
    if (string.IsNullOrEmpty(password))
    {
        Console.Error.WriteLine("Can't read the password file, or it's empty.");
        return null;
    }

    // gk_migrator owns the schema and gk_cli reads every chain, so both get the same refusal as every host (AD-26).
    if (SecretDefaults.IsUnsafePassword(password))
    {
        Console.Error.WriteLine("The password file holds a known default or a password under 16 characters.");
        return null;
    }

    try
    {
        return new DbConnectionStringBuilder { ConnectionString = connectionString, ["Password"] = password }
            .ConnectionString;
    }
    catch (ArgumentException)
    {
        Console.Error.WriteLine("The connection file isn't a valid connection string.");
        return null;
    }
}

static async Task<int> MigrateAsync(string path, string? passwordPath)
{
    var connectionString = await ConnectionAsync(path, passwordPath);
    if (connectionString is null)
    {
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
}

/// <summary>
/// Walks the Deployment chain and every Tenant's chain, each Tenant in its own scope, as
/// <c>gk_cli</c>, which can only read the audit tables. Prints one line per problem, by
/// position only and never row content, and exits 1 on any problem.
/// </summary>
static async Task<int> VerifyAsync(string path, string? passwordPath)
{
    const string CliRole = "gk_cli";

    var connectionString = await ConnectionAsync(path, passwordPath);
    if (connectionString is null)
    {
        return Failure;
    }

    var verifier = AuditContract.CreateVerifier();

    NpgsqlDataSource source;
    try
    {
        source = NpgsqlDataSource.Create(connectionString);
    }
    catch (ArgumentException)
    {
        // Its message can quote the connection string, which holds the password.
        Console.Error.WriteLine("The connection file isn't a valid connection string.");
        return Failure;
    }

    await using var ownedSource = source;

    try
    {

        var chains = new List<(string Name, ChainReport Report)>();
        var tenants = new List<Guid>();

        await using (var scope = await DeploymentScope.BeginAsync(source, CancellationToken.None))
        {
            var context = scope.CreateCommandContext();

            await using (var command = context.CreateCommand())
            {
                command.CommandText = "SELECT current_user::text";
                var role = (string)(await command.ExecuteScalarAsync())!;
                if (role != CliRole)
                {
                    Console.Error.WriteLine($"Audit verify runs only as {CliRole}, not {role}.");
                    return Failure;
                }
            }

            await using (var command = context.CreateCommand())
            {
                command.CommandText = "SELECT id FROM tenant ORDER BY id";
                await using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    tenants.Add(reader.GetGuid(0));
                }
            }

            chains.Add(("deployment", await verifier.VerifyAsync(context, CancellationToken.None)));
            await scope.CommitAsync(CancellationToken.None);
        }

        foreach (var tenantId in tenants)
        {
            await using var scope = await TenantScope.BeginAsync(source, tenantId, CancellationToken.None);
            chains.Add((tenantId.ToString("D"), await verifier.VerifyAsync(scope.CreateCommandContext(), CancellationToken.None)));
            await scope.CommitAsync(CancellationToken.None);
        }

        var problems = 0;
        foreach (var (name, report) in chains)
        {
            foreach (var problem in report.Problems)
            {
                Console.WriteLine($"chain {name}: {problem}");
                problems++;
            }
        }

        var rows = chains.Sum(c => c.Report.SealedRows);
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"verified {chains.Count:N0} chains, {rows:N0} sealed rows, {problems:N0} {(problems == 1 ? "problem" : "problems")}"));

        return problems == 0 ? Success : Failure;
    }
    catch (DbException e)
    {
        Console.Error.WriteLine($"Verification failed: {e.GetType().Name} {e.SqlState}".TrimEnd());
        return Failure;
    }
    catch (Exception e)
    {
        // An unhandled exception would print its message and stack trace.
        Console.Error.WriteLine($"Verification failed: {e.GetType().Name}");
        return Failure;
    }
}

/// <summary>
/// <c>gatekeep init</c> (Story 1.19), as <see cref="InitCommand"/> runs it, with the connection
/// file read here as every command reads it.
/// </summary>
static async Task<int> InitAsync(string path, string passwordPath, string tokenDirectory, bool defaultDirectory)
{
    var connectionString = await ConnectionAsync(path, passwordPath);
    return connectionString is null
        ? Failure
        : await InitCommand.RunAsync(connectionString, tokenDirectory, defaultDirectory);
}

/// <summary><c>gatekeep rotate-transit-keys</c> (Story 12.7), as <see cref="RotateTransitKeysCommand"/> runs it.</summary>
static async Task<int> RotateTransitKeysAsync(string path, string passwordPath)
{
    var connectionString = await ConnectionAsync(path, passwordPath);
    return connectionString is null
        ? Failure
        : await RotateTransitKeysCommand.RunAsync(connectionString);
}
