using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Tests.Isolation.Audit;
using Xunit;
using static Gatekeep.Tests.Isolation.Audit.AuditChains;

namespace Gatekeep.Tests.Isolation;

/// <summary>Runs the real <c>gatekeep audit verify</c> command in its own process, as <c>gk_cli</c>.</summary>
public sealed class AuditVerifyCommandTests(PostgresFixture postgres) : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-verify-").FullName;

    [Fact]
    public async Task Intact_chains_exit_0_with_a_count_of_chains_and_rows()
    {
        var chains = await IntactAsync();

        var result = await VerifyAsync(chains);

        Assert.True(result.ExitCode == 0, result.Output);
        Assert.Contains("verified 3 chains, 6 sealed rows, 0 problems", result.Output);
        Assert.DoesNotContain(PostgresFixture.Password, result.Output);
    }

    [Fact]
    public async Task Altered_row_exits_1_naming_its_chain_epoch_and_seq_and_no_content()
    {
        var chains = await IntactAsync();
        await chains.SuperuserAsync(
            $"""
            SET session_replication_role = replica;
            UPDATE audit_event SET type_code = 'tenancy.settings.deleted' WHERE tenant_id = '{TenantA}' AND seq = 2;
            """);

        var result = await VerifyAsync(chains);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains($"chain {TenantA}: epoch 1 seq 2: altered (hash doesn't match)", result.Output);
        Assert.Contains("verified 3 chains, 6 sealed rows, 1 problem", result.Output);
        Assert.DoesNotContain("1 problems", result.Output);
        Assert.DoesNotContain("tenancy.settings", result.Output);
        Assert.DoesNotContain("someone@example.test", result.Output);
        Assert.DoesNotContain("192.0.2.1", result.Output);
    }

    [Fact]
    public async Task Missing_Deployment_start_exits_1_naming_the_range()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(null, 4);
        await chains.SuperuserAsync(
            """
            SET session_replication_role = replica;
            DELETE FROM deployment_audit_detail WHERE event_id IN (SELECT id FROM deployment_audit_event WHERE seq <= 2);
            DELETE FROM deployment_audit_event WHERE seq <= 2;
            """);

        var result = await VerifyAsync(chains);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("chain deployment: seq 1-2: missing (no checkpoint names seq 2)", result.Output);
    }

    [Fact]
    public async Task Chains_cut_by_retention_and_resealed_exit_0()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5, 1, 2, 3);
        await chains.SealedChainAsync(null, 2, 1);
        await chains.ApplyRetentionAsync(TenantA);
        await chains.ApplyRetentionAsync(null);
        await chains.SealAsync(TenantA);
        await chains.SealAsync(null);

        var result = await VerifyAsync(chains);

        Assert.True(result.ExitCode == 0, result.Output);
        Assert.Contains("verified 2 chains, 5 sealed rows, 0 problems", result.Output);
    }

    [Fact]
    public async Task Verify_straight_after_a_cut_before_the_checkpoint_is_sealed_exits_0()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA);
        await chains.SealedChainAsync(TenantA, 5, 1, 2, 3);
        await chains.SealedChainAsync(null, 2, 1);
        await chains.ApplyRetentionAsync(TenantA);
        await chains.ApplyRetentionAsync(null);

        var result = await VerifyAsync(chains);

        Assert.True(result.ExitCode == 0, result.Output);
        Assert.Contains("verified 2 chains, 3 sealed rows, 0 problems", result.Output);
    }

    [Fact]
    public async Task Bare_audit_verify_takes_both_files_from_the_environment()
    {
        var chains = await IntactAsync();

        var result = await CliProcess.RunWithEnvironmentAsync(
            new Dictionary<string, string>
            {
                ["GATEKEEP_CLI_CONNECTION_FILE"] = File(PasswordlessConnection(chains, TableRegistry.Cli)),
                ["GATEKEEP_CLI_PASSWORD_FILE"] = File(PostgresFixture.Password + "\n"),
            },
            "audit",
            "verify");

        Assert.True(result.ExitCode == 0, result.Output);
        Assert.Contains("0 problems", result.Output);
    }

    [Theory]
    [InlineData(TableRegistry.Admin)]
    [InlineData(TableRegistry.Retention)]
    public async Task Other_role_is_refused(string role)
    {
        var chains = await IntactAsync();

        var result = await CliProcess.RunAsync("audit", "verify", "--connection-file", File(chains.Connection(role)));

        Assert.Equal(1, result.ExitCode);
        Assert.Contains($"Audit verify runs only as gk_cli, not {role}.", result.Output);
        Assert.DoesNotContain("verified", result.Output);
    }

    [Fact]
    public async Task Default_password_file_is_refused_before_connecting()
    {
        var result = await CliProcess.RunAsync(
            "audit", "verify", "--connection-file", File("Host=localhost;Username=gk_cli"), "--password-file", File("changeme\n"));

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("The password file holds a known default or a password under 16 characters.", result.Output);
    }

    [Fact]
    public async Task Missing_connection_file_exits_1()
    {
        var result = await CliProcess.RunAsync("audit", "verify", "--connection-file", Path.Combine(_directory, "absent"));

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("Can't read the connection file.", result.Output);
    }

    [Fact]
    public async Task Bare_audit_verify_without_the_environment_shows_usage()
    {
        var result = await CliProcess.RunAsync("audit", "verify");

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("gatekeep audit verify --connection-file <path> [--password-file <path>]", result.Output);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    /// <summary>Tenant A with 3 sealed rows, Tenant B with 2 and the Deployment with 1.</summary>
    private async Task<AuditChains> IntactAsync()
    {
        var chains = await AuditChains.CreateAsync(postgres, TenantA, TenantB);
        await chains.SealedChainAsync(TenantA, 3);
        await chains.SealedChainAsync(TenantB, 2);
        await chains.SealedChainAsync(null, 1);
        return chains;
    }

    private Task<(int ExitCode, string Output)> VerifyAsync(AuditChains chains) =>
        CliProcess.RunAsync(
            "audit",
            "verify",
            "--connection-file",
            File(PasswordlessConnection(chains, TableRegistry.Cli)),
            "--password-file",
            File(PostgresFixture.Password + "\n"));

    private static string PasswordlessConnection(AuditChains chains, string role) =>
        chains.Connection(role).Replace($"Password={PostgresFixture.Password};", string.Empty);

    private string File(string contents)
    {
        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        System.IO.File.WriteAllText(path, contents);
        return path;
    }
}
