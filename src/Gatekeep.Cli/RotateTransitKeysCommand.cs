using System.Data.Common;
using System.Globalization;
using System.Runtime.InteropServices;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Npgsql;

namespace Gatekeep.Cli;

/// <summary>
/// <c>gatekeep rotate-transit-keys</c> (Story 12.7), the last step of a Master Key rotation. As
/// <c>gk_cli</c> it lists every Tenant, then with the cli AppRole gives a new version to
/// <c>dep-email</c> and <c>dep-payload</c> and to each Tenant's <c>totp</c>, <c>social</c>,
/// <c>email</c>, <c>payload</c> and <c>tpk</c> keys, so values written afterwards are under
/// versions no snapshot taken before the rotation holds.
/// </summary>
/// <remarks>
/// It never touches <c>hmac-*</c> or <c>dep-hmac</c> (T-54: an HMAC under a new version no longer
/// matches the stored one), Signing and Management keys (their lifecycle is Epic 9's) or
/// <c>dep-records</c>. Older versions stay decryptable, since nothing rewraps (G-16). A key that
/// doesn't exist is skipped if it's a Tenant's; any other failure, a rejected Deployment key included,
/// stops it, naming only the key and the failure.
/// Rotating again only adds another version, so a rerun is harmless. Prints counts only.
/// </remarks>
internal static class RotateTransitKeysCommand
{
    private const int Success = 0;
    private const int Failure = 1;
    private const string CliRole = "gk_cli";

    private static readonly DeploymentKeyClass[] DeploymentClasses = [DeploymentKeyClass.Email, DeploymentKeyClass.Payload];

    public static async Task<int> RunAsync(string connectionString)
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

        var options = InitCommand.CustodyOptions("Nothing was rotated.");
        if (options is null)
        {
            return Failure;
        }

        IReadOnlyList<Guid> tenants;
        try
        {
            var listed = await TenantsAsync(connectionString, cancellationToken);
            if (listed is null)
            {
                return Failure;
            }

            tenants = listed;
        }
        catch (DbException e)
        {
            Console.Error.WriteLine($"Listing the Tenants failed: {$"{e.GetType().Name} {e.SqlState}".TrimEnd()}. Nothing was rotated.");
            return Failure;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Listing the Tenants failed: {e.GetType().Name}. Nothing was rotated.");
            return Failure;
        }

        var keys = DeploymentClasses.Select(KeyName.ForDeployment)
            .Concat(tenants.SelectMany(t => KeysContract.SecretClassKeys(t).Where(k => k.Kind != KeyKind.Hmac)))
            .ToList();

        var rotated = 0;
        var skipped = 0;
        try
        {
            using var custody = new OpenBaoKeyCustody(options, TimeProvider.System);
            foreach (var key in keys)
            {
                try
                {
                    await custody.RotateAsync(key, cancellationToken);
                    rotated++;
                }
                catch (KeyCustodyException e) when (e.Failure == KeyCustodyFailure.Rejected && key.TenantId is not null)
                {
                    // No such key: a Tenant whose keys were never made, or were destroyed. A
                    // Deployment key always exists, so a rejected one fails below.
                    skipped++;
                }
                catch (KeyCustodyException e)
                {
                    Console.Error.WriteLine(Counted(rotated, skipped, $"Rotating {key} failed ({e.Failure})."));
                    return Failure;
                }
            }
        }
        catch (Exception e)
        {
            var cause = cancellationToken.IsCancellationRequested ? "Rotation was cancelled." : $"Rotation failed ({e.GetType().Name}).";
            Console.Error.WriteLine(Counted(rotated, skipped, cause));
            return Failure;
        }

        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"Rotated {rotated:N0} Transit keys for the Deployment and {tenants.Count:N0} Tenants, and skipped {skipped:N0} that don't exist."));
        return Success;
    }

    private static string Counted(int rotated, int skipped, string cause) => string.Create(
        CultureInfo.InvariantCulture,
        $"{cause} {rotated:N0} keys were rotated and {skipped:N0} skipped before it. Run rotate-transit-keys again: a rerun is harmless.");

    /// <summary>Every Tenant's ID, read as <c>gk_cli</c>. Null after saying why not.</summary>
    private static async Task<IReadOnlyList<Guid>?> TenantsAsync(string connectionString, CancellationToken cancellationToken)
    {
        NpgsqlDataSource source;
        try
        {
            source = NpgsqlDataSource.Create(connectionString);
        }
        catch (ArgumentException)
        {
            // Its message can quote the connection string, which holds the password.
            Console.Error.WriteLine("The connection file isn't a valid connection string.");
            return null;
        }

        await using var ownedSource = source;
        await using var scope = await DeploymentScope.BeginAsync(source, cancellationToken);
        var context = scope.CreateCommandContext();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = "SELECT current_user::text";
            var role = (string)(await command.ExecuteScalarAsync(cancellationToken))!;
            if (role != CliRole)
            {
                Console.Error.WriteLine($"rotate-transit-keys runs only as {CliRole}, not {role}.");
                return null;
            }
        }

        var tenants = new List<Guid>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = "SELECT id FROM tenant ORDER BY id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                tenants.Add(reader.GetGuid(0));
            }
        }

        await scope.CommitAsync(cancellationToken);
        return tenants;
    }
}
