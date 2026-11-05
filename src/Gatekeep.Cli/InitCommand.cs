using System.Data.Common;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;

namespace Gatekeep.Cli;

/// <summary>
/// <c>gatekeep init</c> (Story 1.19). As <c>gk_cli</c> it refuses a completed bootstrap before
/// anything else; ensures the four Deployment keys; checks the token directory; stages a fresh
/// token; then in one transaction stores only its SHA-256 and the issue event, publishes the
/// file and commits. The previous token file stays valid until the commit. Prints only the
/// file's place and the expiry, never the token. SIGINT and SIGTERM cancel it cleanly.
/// </summary>
internal static class InitCommand
{
    public const string SocketVariable = "GATEKEEP_CUSTODY_SOCKET";
    public const string RoleIdFileVariable = "GATEKEEP_CUSTODY_ROLE_ID_FILE";
    public const string SecretIdFileVariable = "GATEKEEP_CUSTODY_SECRET_ID_FILE";

    private const int Success = 0;
    private const int Failure = 1;
    private const string CliRole = "gk_cli";
    private const string LockNotAvailable = "55P03";
    private const string Setup = "docker compose run --rm bootstrap-dir";

    private enum Phase
    {
        BeforeCommit,
        Committing,
        Committed,
    }

    public static async Task<int> RunAsync(string connectionString, string tokenDirectory, bool defaultDirectory)
    {
        using var cancellation = new CancellationTokenSource();
        using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, Cancel);
        using var terminate = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Cancel);
        var cancellationToken = cancellation.Token;

        void Cancel(PosixSignalContext context)
        {
            context.Cancel = true;
            cancellation.Cancel();
        }

        var shown = defaultDirectory
            ? "bootstrap/" + BootstrapTokenFile.FileName + " in the secrets directory"
            : Path.Combine(Path.GetFullPath(tokenDirectory), BootstrapTokenFile.FileName);

        var custody = CustodyOptions("Nothing was issued.");
        if (custody is null)
        {
            return Failure;
        }

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
        using var file = new BootstrapTokenFile(tokenDirectory);
        var issuer = AdminsContract.CreateBootstrapIssuer(AuditContract.CreateAppender());
        var phase = Phase.BeforeCommit;
        byte[]? token = null;

        try
        {
            // 1. A completed bootstrap is refused before custody or the directory is touched.
            await using (var scope = await DeploymentScope.BeginAsync(source, cancellationToken))
            {
                var context = scope.CreateCommandContext();
                var role = await CurrentRoleAsync(context, cancellationToken);
                if (role != CliRole)
                {
                    Console.Error.WriteLine($"Init runs only as {CliRole}, not {role}.");
                    return Failure;
                }

                if (await issuer.IsCompleteAsync(context, cancellationToken))
                {
                    Console.Error.WriteLine("Bootstrap is already complete, so init issues no token.");
                    return Failure;
                }

                await scope.CommitAsync(cancellationToken);
            }

            // 2. The Deployment keys. Creating one that exists leaves it unchanged.
            if (!await EnsureKeysAsync(custody, cancellationToken))
            {
                return Failure;
            }

            // 3. The directory, before any token exists.
            var check = file.Check(Console.Error);
            if (check != TokenDirectoryCheck.Ready)
            {
                Console.Error.WriteLine(DirectoryMessage(check));
                return Failure;
            }

            // 4. The token, staged where it isn't yet the token file.
            token = BootstrapToken.Generate();
            await file.StageAsync(token, cancellationToken);

            // 5. Its hash and event, the file published under the row lock, then the commit.
            BootstrapIssue? issue;
            await using (var scope = await DeploymentScope.BeginAsync(source, cancellationToken))
            {
                issue = await issuer.IssueAsync(scope.CreateCommandContext(), new Secret<byte[]>(token), cancellationToken);
                if (issue is null)
                {
                    Console.Error.WriteLine("Bootstrap completed while init ran, so init issues no token.");
                    return Failure;
                }

                file.Publish();
                phase = Phase.Committing;
                await scope.CommitAsync(cancellationToken);
                phase = Phase.Committed;
            }

            file.Complete();

            Console.WriteLine($"Wrote the bootstrap token to {shown}{(issue.Reissued ? ", replacing the previous one" : string.Empty)}.");
            Console.WriteLine(string.Create(
                CultureInfo.InvariantCulture,
                $"It expires at {issue.ExpiresAt.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC. Finish bootstrap before then, or run init again."));

            return Success;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(FailureMessage(e, phase, file, cancellationToken.IsCancellationRequested));
            return Failure;
        }
        finally
        {
            if (token is not null)
            {
                CryptographicOperations.ZeroMemory(token);
            }
        }
    }

    /// <summary>
    /// One fixed line naming only the exception's type and SQL state. Before the commit nothing
    /// was stored, and the previous token file is put back if it was replaced; a thrown commit
    /// may or may not have committed; after the commit the token was stored.
    /// </summary>
    private static string FailureMessage(Exception e, Phase phase, BootstrapTokenFile file, bool cancelled)
    {
        if (phase == Phase.Committed)
        {
            return $"Init issued the token to the token file, but failed after the commit ({e.GetType().Name}).";
        }

        var published = file.Published;
        var restored = file.Restore();
        var cause = cancelled
            ? "Init was cancelled"
            : e is PostgresException { SqlState: LockNotAvailable }
                ? "Init timed out after 30 seconds waiting for another init or a bootstrap to release the bootstrap state"
                : e is DbException db
                    ? $"Init failed: {e.GetType().Name} {db.SqlState}".TrimEnd()
                    : $"Init failed: {e.GetType().Name}";

        var previous = restored
            ? "the previous token file was restored"
            : "the previous token file couldn't be restored";

        return phase == Phase.Committing
            ? $"{cause}. The commit's outcome is unknown, so {previous}: run init again."
            : published || !restored
                ? $"{cause}. Nothing was issued, and {previous}."
                : $"{cause}. Nothing was issued.";
    }

    private static string DirectoryMessage(TokenDirectoryCheck check) => check switch
    {
        TokenDirectoryCheck.Missing =>
            $"The token directory is missing or isn't a directory. Make it with: {Setup}. Nothing was issued.",
        TokenDirectoryCheck.SymbolicLink =>
            $"The token directory is a symbolic link. Make bootstrap/ a real directory with: {Setup}. Nothing was issued.",
        TokenDirectoryCheck.NotPrivate =>
            $"The token directory must be owned by this user and writable by no one else. Fix it with: {Setup}. Nothing was issued.",
        TokenDirectoryCheck.NotWritable =>
            $"The token directory isn't writable. Fix it with: {Setup}. Nothing was issued.",
        TokenDirectoryCheck.TokenNotRegular =>
            "The token file is a symbolic link or not a regular file. Remove it, then run init again. Nothing was issued.",
        _ => throw new ArgumentOutOfRangeException(nameof(check)),
    };

    private static async Task<bool> EnsureKeysAsync(OpenBaoOptions options, CancellationToken cancellationToken)
    {
        try
        {
            using var custody = new OpenBaoKeyCustody(options, TimeProvider.System);
            foreach (var keyClass in Enum.GetValues<DeploymentKeyClass>())
            {
                await custody.CreateKeyAsync(KeyName.ForDeployment(keyClass), cancellationToken);
            }

            return true;
        }
        catch (KeyCustodyException e)
        {
            Console.Error.WriteLine($"Key custody failed ({e.Failure}), so the Deployment keys aren't ensured. Nothing was issued.");
            return false;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Console.Error.WriteLine($"Key custody failed ({e.GetType().Name}), so the Deployment keys aren't ensured. Nothing was issued.");
            return false;
        }
    }

    /// <summary>
    /// The socket and the cli AppRole's files from the environment, each file readable and holding
    /// no known default, as every host checks them. Null after naming each refused setting.
    /// </summary>
    internal static OpenBaoOptions? CustodyOptions(string consequence)
    {
        var socket = Environment.GetEnvironmentVariable(SocketVariable);
        var roleIdFile = Environment.GetEnvironmentVariable(RoleIdFileVariable);
        var secretIdFile = Environment.GetEnvironmentVariable(SecretIdFileVariable);

        var refused = new List<string>();
        if (string.IsNullOrWhiteSpace(socket))
        {
            refused.Add(SocketVariable);
        }

        CheckSecretFile(roleIdFile, RoleIdFileVariable, refused);
        CheckSecretFile(secretIdFile, SecretIdFileVariable, refused);

        if (refused.Count > 0)
        {
            Console.Error.WriteLine(
                $"Key custody isn't configured: {string.Join(", ", refused)} must be set, and name a readable file holding no default value. {consequence}");
            return null;
        }

        return new OpenBaoOptions { SocketPath = socket, RoleIdFile = roleIdFile!, SecretIdFile = secretIdFile! };
    }

    /// <summary>The file must be readable and hold a value that isn't a default. Its contents aren't kept.</summary>
    private static void CheckSecretFile(string? path, string name, List<string> refused)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            refused.Add(name);
            return;
        }

        try
        {
            if (SecretDefaults.IsUnsafe(File.ReadAllText(path)))
            {
                refused.Add(name);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            refused.Add(name);
        }
    }

    private static async Task<string> CurrentRoleAsync(CommandContext context, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = "SELECT current_user::text";
        return (string)(await command.ExecuteScalarAsync(cancellationToken))!;
    }
}
