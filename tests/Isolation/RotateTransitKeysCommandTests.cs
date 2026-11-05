using System.Runtime.Versioning;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Bootstrap;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Hosting;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation;

/// <summary>
/// Story 12.7: <c>gatekeep rotate-transit-keys</c>, the real Cli against a real OpenBao with the cli
/// AppRole, reading Tenants as <c>gk_cli</c>. Its own OpenBao, since it rotates the Deployment keys.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class RotateTransitKeysCommandTests(PostgresFixture postgres, OpenBaoFixture bao)
    : IClassFixture<OpenBaoFixture>, IDisposable
{
    private static readonly byte[] Data = "credential-equivalent value"u8.ToArray();

    private readonly string _scratch = Directory.CreateTempSubdirectory("gatekeep-rotate-transit-").FullName;
    private readonly OpenBaoSocketProxy _socket = new(bao.Address);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Rotates_every_non_HMAC_secret_class_key_skips_missing_ones_and_reruns_harmlessly()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenantA = Guid.CreateVersion7();
        var tenantB = Guid.CreateVersion7();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), tenantA);
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), tenantB);

        // Tenant A has all six secret class keys and a Signing and Management key; Tenant B has
        // no payload key, which is skipped.
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        var signing = KeyName.Signing(tenantA, Guid.CreateVersion7());
        var management = KeyName.Management(tenantA, Guid.CreateVersion7());
        await worker.CreateKeyAsync(signing, Cancellation);
        await worker.CreateKeyAsync(management, Cancellation);
        foreach (var keyClass in Enum.GetValues<TenantKeyClass>())
        {
            await worker.CreateKeyAsync(KeyName.ForTenant(keyClass, tenantA), Cancellation);
            if (keyClass != TenantKeyClass.Payload)
            {
                await worker.CreateKeyAsync(KeyName.ForTenant(keyClass, tenantB), Cancellation);
            }
        }

        using var hosted = bao.Custody(OpenBaoFixture.Hosted);
        var totpA = KeyName.ForTenant(TenantKeyClass.Totp, tenantA);
        var before = await hosted.EncryptAsync(totpA, tenantA, new Secret<byte[]>(Data), Cancellation);

        string[] rotated =
        [
            "dep-email", "dep-payload",
            .. new[] { tenantA, tenantB }.SelectMany(t => new[] { "totp", "social", "email", "tpk" }.Select(p => $"{p}-{t:D}")),
            $"payload-{tenantA:D}",
        ];
        string[] untouched =
        [
            "dep-hmac", "dep-records", $"hmac-{tenantA:D}", $"hmac-{tenantB:D}", signing.Value, management.Value,
        ];

        for (var run = 1; run <= 2; run++)
        {
            var result = await RunAsync(database);

            Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
            Assert.Equal(
                "Rotated 11 Transit keys for the Deployment and 2 Tenants, and skipped 1 that don't exist.",
                result.StandardOutput.Trim());
            Assert.Equal(string.Empty, result.StandardError);
            foreach (var key in rotated)
            {
                Assert.True(await LatestVersionAsync(key) == 1 + run, $"{key} isn't at version {1 + run} after run {run}.");
            }

            foreach (var key in untouched)
            {
                Assert.True(await LatestVersionAsync(key) == 1, $"{key} was rotated.");
            }
        }

        Assert.Null(await InitKeys.TryReadAsync(bao, $"payload-{tenantB:D}", Cancellation));

        // The old ciphertext still decrypts, and new ones use the newest version.
        Assert.Equal(Data, (await hosted.DecryptAsync(totpA, tenantA, before, Cancellation)).Use(b => b.ToArray()));
        Assert.StartsWith("vault:v3:", (await hosted.EncryptAsync(totpA, tenantA, new Secret<byte[]>(Data), Cancellation)).Value, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_custody_failure_stops_it_naming_only_the_key_and_the_failure()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var wrongSecret = WriteFile(Guid.NewGuid().ToString("D"));

        var result = await RunAsync(database, secretIdFile: wrongSecret);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(string.Empty, result.StandardOutput);
        Assert.StartsWith("Rotating dep-email failed (LoginFailed). 0 keys were rotated and 0 skipped before it.", result.StandardError, StringComparison.Ordinal);
        Assert.DoesNotContain(await File.ReadAllTextAsync(wrongSecret, Cancellation), result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rejected_Deployment_key_fails_the_run_naming_it()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        // Custody logs in, then rejects every rotation, as it would a missing dep-email (400 or 404).
        using var socket = new FakeOpenBaoSocket
        {
            Respond = path => path.Contains("/auth/approle/login", StringComparison.Ordinal)
                ? (200, """{"auth":{"client_token":"t","lease_duration":900}}""")
                : (404, "{}"),
        };
        var settings = Settings(database, bao.Options(OpenBaoFixture.Cli).SecretIdFile);
        settings["GATEKEEP_CUSTODY_SOCKET"] = socket.Path;

        var result = await CliProcess.RunCapturedAsync(settings, "rotate-transit-keys");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(string.Empty, result.StandardOutput);
        Assert.StartsWith("Rotating dep-email failed (Rejected). 0 keys were rotated and 0 skipped before it.", result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task As_another_role_it_is_refused_and_rotates_nothing()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var email = await LatestVersionAsync("dep-email");
        var payload = await LatestVersionAsync("dep-payload");
        var settings = Settings(database, bao.Options(OpenBaoFixture.Cli).SecretIdFile);
        settings["GATEKEEP_CLI_CONNECTION_FILE"] = WriteFile(
            new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Admin, database)) { Password = null }.ConnectionString);

        var result = await CliProcess.RunCapturedAsync(settings, "rotate-transit-keys");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("rotate-transit-keys runs only as gk_cli, not gk_admin.\n", result.StandardError.ReplaceLineEndings("\n"));
        Assert.Equal(email, await LatestVersionAsync("dep-email"));
        Assert.Equal(payload, await LatestVersionAsync("dep-payload"));
    }

    [Fact]
    public async Task Without_its_custody_settings_it_rotates_nothing()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var environment = Settings(database, bao.Options(OpenBaoFixture.Cli).SecretIdFile);
        environment.Remove("GATEKEEP_CUSTODY_SOCKET");

        var result = await CliProcess.RunCapturedAsync(environment, "rotate-transit-keys");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("GATEKEEP_CUSTODY_SOCKET must be set", result.StandardError);
        Assert.Contains("Nothing was rotated.", result.StandardError);
    }

    public void Dispose()
    {
        _socket.Dispose();
        Directory.Delete(_scratch, recursive: true);
    }

    private Task<CliResult> RunAsync(string database, string? secretIdFile = null) =>
        CliProcess.RunCapturedAsync(
            Settings(database, secretIdFile ?? bao.Options(OpenBaoFixture.Cli).SecretIdFile),
            "rotate-transit-keys");

    private Dictionary<string, string> Settings(string database, string secretIdFile) => new()
    {
        ["GATEKEEP_CLI_CONNECTION_FILE"] = WriteFile(
            new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Cli, database)) { Password = null }.ConnectionString),
        ["GATEKEEP_CLI_PASSWORD_FILE"] = WriteFile(PostgresFixture.Password + "\n"),
        ["GATEKEEP_CUSTODY_SOCKET"] = _socket.Path,
        ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = bao.Options(OpenBaoFixture.Cli).RoleIdFile,
        ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = secretIdFile,
    };

    private async Task<int> LatestVersionAsync(string key) =>
        (await InitKeys.ReadAsync(bao, key, Cancellation)).GetProperty("latest_version").GetInt32();

    private string WriteFile(string contents)
    {
        var path = Path.Combine(_scratch, Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, contents);
        return path;
    }
}
