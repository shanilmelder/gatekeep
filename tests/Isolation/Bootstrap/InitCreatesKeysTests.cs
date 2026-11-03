using System.Net;
using System.Runtime.Versioning;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Tests.Isolation.Custody;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Bootstrap;

/// <summary>Reads a Transit key as the <c>cli</c> AppRole, whose policy may read <c>dep-*</c>.</summary>
internal static class InitKeys
{
    public static async Task<JsonElement> ReadAsync(OpenBaoFixture bao, string key, CancellationToken cancellationToken) =>
        (await TryReadAsync(bao, key, cancellationToken)) ?? throw new InvalidOperationException($"{key} doesn't exist.");

    public static async Task<JsonElement?> TryReadAsync(OpenBaoFixture bao, string key, CancellationToken cancellationToken)
    {
        var token = await bao.LoginAsync(OpenBaoFixture.Cli);
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);
        using var response = await http.GetAsync($"v1/transit/keys/{key}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return body.RootElement.GetProperty("data").Clone();
    }
}

/// <summary>
/// Story 1.19 with an OpenBao whose setup made no Deployment key: <c>gatekeep init</c> makes all
/// four, each of its AD-10 type, not exportable, at version 1.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class InitCreatesKeysTests(PostgresFixture postgres, NoDeploymentKeysOpenBaoFixture bao)
    : IClassFixture<NoDeploymentKeysOpenBaoFixture>, IDisposable
{
    private readonly string _scratch = Directory.CreateTempSubdirectory("gatekeep-init-keys-").FullName;
    private readonly OpenBaoSocketProxy _socket = new(bao.Address);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Init_creates_the_four_Deployment_keys_with_their_types()
    {
        (string Key, string Type)[] expected =
        [
            ("dep-email", "aes256-gcm96"),
            ("dep-payload", "aes256-gcm96"),
            ("dep-hmac", "hmac"),
            ("dep-records", "rsa-3072"),
        ];
        foreach (var (key, _) in expected)
        {
            Assert.Null(await InitKeys.TryReadAsync(bao, key, Cancellation));
        }

        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = Path.Combine(_scratch, "bootstrap");
        Directory.CreateDirectory(directory);
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var options = bao.Options(OpenBaoFixture.Cli);
        var environment = new Dictionary<string, string>
        {
            ["GATEKEEP_CLI_CONNECTION_FILE"] = WriteFile(
                new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Cli, database)) { Password = null }.ConnectionString),
            ["GATEKEEP_CLI_PASSWORD_FILE"] = WriteFile(PostgresFixture.Password + "\n"),
            ["GATEKEEP_CUSTODY_SOCKET"] = _socket.Path,
            ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = options.RoleIdFile,
            ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = options.SecretIdFile,
        };

        var result = await CliProcess.RunCapturedAsync(environment, "init", "--token-dir", directory);

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
        foreach (var (key, type) in expected)
        {
            var data = await InitKeys.ReadAsync(bao, key, Cancellation);
            Assert.Equal(type, data.GetProperty("type").GetString());
            Assert.False(data.GetProperty("exportable").GetBoolean(), $"{key} is exportable.");
            Assert.False(data.GetProperty("allow_plaintext_backup").GetBoolean(), $"{key} allows a plaintext backup.");
            Assert.Equal(1, data.GetProperty("latest_version").GetInt32());
        }
    }

    public void Dispose()
    {
        _socket.Dispose();
        Directory.Delete(_scratch, recursive: true);
    }

    private string WriteFile(string contents)
    {
        var path = Path.Combine(_scratch, Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, contents);
        return path;
    }
}
