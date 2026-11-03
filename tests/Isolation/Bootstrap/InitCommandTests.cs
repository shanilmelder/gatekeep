using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Tests.Isolation.Canary;
using Gatekeep.Tests.Isolation.Custody;
using Npgsql;
using Xunit;
using CanaryValue = Gatekeep.Tests.Isolation.Canary.Canary;

namespace Gatekeep.Tests.Isolation.Bootstrap;

/// <summary>
/// Story 1.19: the real <c>gatekeep init</c> in its own process, as <c>gk_cli</c> against a real
/// PostgreSQL and as the <c>cli</c> AppRole against a real OpenBao, reached on a unix socket.
/// Permission-sensitive runs drop to the cli uid, 10004, as the <c>cli</c> service runs.
/// Linux only, as the tests container is: it checks Unix file modes.
/// </summary>
[SupportedOSPlatform("linux")]
[Collection(OpenBaoCollection.Name)]
public sealed class InitCommandTests(PostgresFixture postgres, OpenBaoFixture bao) : IDisposable
{
    public const int CliUid = 10004;

    private const string PermissionDenied = "42501";
    private const string Raised = "P0001";
    private const string IssuedCode = "bootstrap.token.issued";
    private const string ReissuedCode = "bootstrap.token.reissued";
    private const string TokenFileName = "bootstrap-token";

    private const string Completed = "Bootstrap is already complete, so init issues no token.\n";
    private const string Missing = "The token directory is missing or isn't a directory. Make it with: docker compose run --rm bootstrap-dir. Nothing was issued.\n";
    private const string Linked = "The token directory is a symbolic link. Make bootstrap/ a real directory with: docker compose run --rm bootstrap-dir. Nothing was issued.\n";
    private const string NotPrivate = "The token directory must be owned by this user and writable by no one else. Fix it with: docker compose run --rm bootstrap-dir. Nothing was issued.\n";
    private const string NotWritable = "The token directory isn't writable. Fix it with: docker compose run --rm bootstrap-dir. Nothing was issued.\n";
    private const string TokenNotRegular = "The token file is a symbolic link or not a regular file. Remove it, then run init again. Nothing was issued.\n";

    private const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerReadWrite = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private static readonly string[] DeploymentKeys = ["dep-email", "dep-payload", "dep-hmac", "dep-records"];

    private readonly string _scratch = Scratch();
    private readonly OpenBaoSocketProxy _socket = new(bao.Address);

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task First_init_ensures_the_keys_writes_a_root_only_token_and_stores_only_its_hash()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();

        var result = await InitAsync(database, directory);

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);

        var file = Path.Combine(directory, TokenFileName);
        var content = await File.ReadAllTextAsync(file, Cancellation);
        Assert.Matches("^[0-9a-f]{64}\n$", content);
        Assert.Equal(OwnerReadWrite, File.GetUnixFileMode(file));
        Assert.Equal(Private, File.GetUnixFileMode(directory));
        Assert.Equal([TokenFileName], Entries(directory));

        var state = await StateAsync(database);
        Assert.NotNull(state);
        Assert.Equal(Sha256(content), state.Hash);
        Assert.Equal(BootstrapToken.Hash(content), state.Hash);
        Assert.Equal(TimeSpan.FromMinutes(15), state.ExpiresAt - state.IssuedAt);
        Assert.Null(state.CompletedAt);

        Assert.Equal([(IssuedCode, "system")], await EventsAsync(database));

        foreach (var key in DeploymentKeys)
        {
            Assert.True(await KeyVersionAsync(key) >= 1, $"{key} doesn't exist.");
        }

        var expiry = state.ExpiresAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        Assert.Equal(
            $"Wrote the bootstrap token to {file}.\nIt expires at {expiry} UTC. Finish bootstrap before then, or run init again.\n",
            result.StandardOutput.ReplaceLineEndings("\n"));
        Assert.Empty(result.StandardError);
        AssertNoToken(content, result);
    }

    [Fact]
    public async Task Init_as_the_cli_uid_writes_a_token_it_owns()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory(owner: CliUid);

        var result = await InitAsync(database, directory, uid: CliUid);

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
        var file = Path.Combine(directory, TokenFileName);
        Assert.Equal($"{CliUid} 600", Stat("%u %a", file));
        Assert.Equal(Sha256(await File.ReadAllTextAsync(file, Cancellation)), (await StateAsync(database))!.Hash);
        Assert.Equal([TokenFileName], Entries(directory));
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("")]
    public void Token_hash_trims_surrounding_whitespace(string around)
    {
        var token = Encoding.ASCII.GetString(BootstrapToken.Generate());
        Assert.Matches("^[0-9a-f]{64}$", token);

        var expected = SHA256.HashData(Encoding.ASCII.GetBytes(token));
        Assert.Equal(expected, BootstrapToken.Hash(around + token + around));
        Assert.Equal(expected, BootstrapToken.Hash(Encoding.ASCII.GetBytes(token + around)));
    }

    [Theory]
    [InlineData(63)]
    [InlineData(65)]
    public void Token_hash_refuses_another_length(int length)
    {
        var text = new string('a', length);

        var refused = Assert.Throws<ArgumentException>(() => BootstrapToken.Hash(text));
        Assert.DoesNotContain(text, refused.Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => BootstrapToken.Hash(Encoding.ASCII.GetBytes(text)));
    }

    [Theory]
    [InlineData('A')]
    [InlineData('g')]
    [InlineData(' ')]
    [InlineData('é')]
    public void Token_hash_refuses_anything_but_lower_case_hex(char wrong)
    {
        var text = new string('a', 32) + wrong + new string('a', 31);

        Assert.Throws<ArgumentException>(() => BootstrapToken.Hash(text));
    }

    [Fact]
    public async Task Existing_keys_keep_their_versions()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        Assert.Equal(0, (await InitAsync(database, TokenDirectory())).ExitCode);
        var before = new Dictionary<string, int>();
        foreach (var key in DeploymentKeys)
        {
            before[key] = await KeyVersionAsync(key);
        }

        var result = await InitAsync(database, TokenDirectory());

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
        foreach (var key in DeploymentKeys)
        {
            Assert.Equal(before[key], await KeyVersionAsync(key));
        }
    }

    [Fact]
    public async Task Reissue_replaces_the_token_its_hash_and_expiry_and_marks_the_event()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        Assert.Equal(0, (await InitAsync(database, directory)).ExitCode);
        var first = await File.ReadAllTextAsync(Path.Combine(directory, TokenFileName), Cancellation);
        var firstState = (await StateAsync(database))!;

        var result = await InitAsync(database, directory);

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
        var second = await File.ReadAllTextAsync(Path.Combine(directory, TokenFileName), Cancellation);
        Assert.Matches("^[0-9a-f]{64}\n$", second);
        Assert.NotEqual(first, second);

        var state = (await StateAsync(database))!;
        Assert.Equal(Sha256(second), state.Hash);
        Assert.NotEqual(Sha256(first), state.Hash);
        Assert.True(state.IssuedAt > firstState.IssuedAt);
        Assert.Equal(TimeSpan.FromMinutes(15), state.ExpiresAt - state.IssuedAt);
        Assert.Null(state.CompletedAt);

        Assert.Equal([(IssuedCode, "system"), (ReissuedCode, "system")], await EventsAsync(database));
        Assert.Contains("replacing the previous one", result.StandardOutput);
        Assert.Equal([TokenFileName], Entries(directory));
        AssertNoToken(first, result);
        AssertNoToken(second, result);
    }

    [Fact]
    public async Task Completed_bootstrap_is_refused_first_and_nothing_changes()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        Assert.Equal(0, (await InitAsync(database, directory)).ExitCode);
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), "UPDATE bootstrap_state SET completed_at = now()");
        var token = await File.ReadAllTextAsync(Path.Combine(directory, TokenFileName), Cancellation);
        var state = await StateAsync(database);

        // Custody unreachable and the directory a link: the refusal comes before either is touched.
        var link = Path.Combine(_scratch, "link-" + Guid.NewGuid().ToString("N"));
        Directory.CreateSymbolicLink(link, directory);
        var result = await InitAsync(database, link, socket: Path.Combine(_scratch, "absent.sock"));

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(Completed, Error(result));
        Assert.Empty(result.StandardOutput);
        Assert.Equal(token, await File.ReadAllTextAsync(Path.Combine(directory, TokenFileName), Cancellation));
        Assert.Equal([TokenFileName], Entries(directory));
        Assert.Equal(state, await StateAsync(database));
        Assert.Equal([(IssuedCode, "system")], await EventsAsync(database));
    }

    [Fact]
    public async Task Unreachable_OpenBao_exits_1_with_no_file_and_no_row()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();

        var result = await InitAsync(database, directory, socket: Path.Combine(_scratch, "absent.sock"));

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("Key custody failed (Unavailable), so the Deployment keys aren't ensured. Nothing was issued.\n", Error(result));
        await AssertNothingIssuedAsync(database, directory);
    }

    [Fact]
    public async Task Refused_login_exits_1_with_no_file_and_no_row()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();

        var result = await InitAsync(database, directory, secretIdFile: WriteFile("not-the-cli-secret-id\n"));

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("Key custody failed (LoginFailed), so the Deployment keys aren't ensured. Nothing was issued.\n", Error(result));
        await AssertNothingIssuedAsync(database, directory);
    }

    [Theory]
    [InlineData("GATEKEEP_CUSTODY_SOCKET", null)]
    [InlineData("GATEKEEP_CUSTODY_ROLE_ID_FILE", null)]
    [InlineData("GATEKEEP_CUSTODY_SECRET_ID_FILE", null)]
    [InlineData("GATEKEEP_CUSTODY_SECRET_ID_FILE", "changeme\n")]
    [InlineData("GATEKEEP_CUSTODY_ROLE_ID_FILE", "")]
    public async Task Missing_or_default_custody_setting_exits_1_naming_it(string variable, string? fileContents)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var environment = Environment(database);
        if (fileContents is null)
        {
            environment.Remove(variable);
        }
        else
        {
            environment[variable] = WriteFile(fileContents);
        }

        var result = await CliProcess.Start(environment, uid: null, "init", "--token-dir", directory).CompletedAsync();

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(
            $"Key custody isn't configured: {variable} must be set, and name a readable file holding no default value. Nothing was issued.\n",
            Error(result));
        await AssertNothingIssuedAsync(database, directory);
    }

    [Fact]
    public async Task Unreachable_database_exits_1_and_leaves_no_token_file()
    {
        var directory = TokenDirectory();
        var closed = new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1",
            Port = Hosting.HostProcess.FreePort(),
            Database = "gatekeep",
            Username = TableRegistry.Cli,
            Timeout = 5,
        }.ConnectionString;

        var result = await InitAsync(closed, directory, rawConnection: true);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("Init failed: NpgsqlException. Nothing was issued.\n", Error(result));
        Assert.Empty(Entries(directory));
    }

    [Fact]
    public async Task Missing_token_directory_exits_1_with_no_row()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = Path.Combine(_scratch, "absent");

        var result = await InitAsync(database, directory);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(Missing, Error(result));
        Assert.False(Directory.Exists(directory));
        Assert.Null(await StateAsync(database));
        Assert.Empty(await EventsAsync(database));
    }

    [Fact]
    public async Task Token_directory_that_isnt_a_directory_exits_1_with_no_row()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var notADirectory = WriteFile("a file, not a directory");

        var result = await InitAsync(database, notADirectory);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(Missing, Error(result));
        Assert.Equal("a file, not a directory", await File.ReadAllTextAsync(notADirectory, Cancellation));
        Assert.Null(await StateAsync(database));
        Assert.Empty(await EventsAsync(database));
    }

    [Theory]
    [InlineData("0500", CliUid, NotWritable)]
    [InlineData("0700", 0, NotPrivate)]
    [InlineData("0770", CliUid, NotPrivate)]
    [InlineData("0702", CliUid, NotPrivate)]
    [InlineData("0777", CliUid, NotPrivate)]
    public async Task Token_directory_the_cli_uid_cant_keep_private_is_refused(string mode, int owner, string message)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory(owner: owner, mode: (UnixFileMode)Convert.ToInt32(mode, 8));

        var result = await InitAsync(database, directory, uid: CliUid);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(message, Error(result));
        Assert.Empty(Entries(directory));
        Assert.Equal(mode[1..], Stat("%a", directory));
        Assert.Null(await StateAsync(database));
        Assert.Empty(await EventsAsync(database));
    }

    [Fact]
    public async Task Symbolic_link_token_directory_is_refused()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var target = TokenDirectory();
        var link = Path.Combine(_scratch, "link-" + Guid.NewGuid().ToString("N"));
        Directory.CreateSymbolicLink(link, target);

        var result = await InitAsync(database, link);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(Linked, Error(result));
        Assert.Empty(Entries(target));
        Assert.Null(await StateAsync(database));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Token_file_that_is_a_link_or_not_a_file_is_refused(bool link)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var elsewhere = WriteFile("elsewhere\n");
        if (link)
        {
            File.CreateSymbolicLink(Path.Combine(directory, TokenFileName), elsewhere);
        }
        else
        {
            Directory.CreateDirectory(Path.Combine(directory, TokenFileName));
        }

        var result = await InitAsync(database, directory);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(TokenNotRegular, Error(result));
        Assert.Equal("elsewhere\n", await File.ReadAllTextAsync(elsewhere, Cancellation));
        Assert.Equal([TokenFileName], Entries(directory));
        Assert.Null(await StateAsync(database));
    }

    [Fact]
    public async Task Existing_0644_token_file_is_replaced_by_a_new_0600_file()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var file = Path.Combine(directory, TokenFileName);
        await File.WriteAllTextAsync(file, "old\n", Cancellation);
        File.SetUnixFileMode(file, (UnixFileMode)Convert.ToInt32("0644", 8));
        var inode = Stat("%i", file);

        var result = await InitAsync(database, directory);

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
        Assert.Equal(OwnerReadWrite, File.GetUnixFileMode(file));
        Assert.NotEqual(inode, Stat("%i", file));
        Assert.Equal([TokenFileName], Entries(directory));
    }

    [Fact]
    public async Task Stale_leftovers_are_swept_and_fresh_ones_kept()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var stale = new[] { ".bootstrap-token.dead.tmp", ".bootstrap-token.dead.probe" };
        foreach (var name in stale)
        {
            var path = Path.Combine(directory, name);
            await File.WriteAllTextAsync(path, "x", Cancellation);
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddHours(-1));
        }

        var fresh = Path.Combine(directory, ".bootstrap-token.waiting.tmp");
        await File.WriteAllTextAsync(fresh, "x", Cancellation);

        var result = await InitAsync(database, directory);

        Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);
        Assert.Equal([".bootstrap-token.waiting.tmp", TokenFileName], Entries(directory));
    }

    [Fact]
    public async Task Database_failure_after_staging_leaves_the_previous_token_and_no_row()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var file = Path.Combine(directory, TokenFileName);
        var previous = new string('b', 64) + "\n";
        await File.WriteAllTextAsync(file, previous, Cancellation);
        File.SetUnixFileMode(file, OwnerReadWrite);
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            """
            CREATE FUNCTION test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused by the test'; END $$;
            CREATE TRIGGER test_refuse BEFORE INSERT OR UPDATE ON bootstrap_state FOR EACH ROW EXECUTE FUNCTION test_refuse();
            """);

        var result = await InitAsync(database, directory);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("Init failed: PostgresException P0001. Nothing was issued.\n", Error(result));
        Assert.Equal(previous, await File.ReadAllTextAsync(file, Cancellation));
        Assert.Equal([TokenFileName], Entries(directory));
        Assert.Null(await StateAsync(database));
        Assert.Empty(await EventsAsync(database));
    }

    [Fact]
    public async Task Commit_failure_after_the_rename_restores_the_previous_valid_token()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var file = Path.Combine(directory, TokenFileName);
        Assert.Equal(0, (await InitAsync(database, directory)).ExitCode);
        var valid = await File.ReadAllTextAsync(file, Cancellation);
        await RefuseCommitsAsync(database);

        var result = await InitAsync(database, directory);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(
            "Init failed: PostgresException P0001. The commit's outcome is unknown, so the previous token file was restored: run init again.\n",
            Error(result));
        Assert.Equal(valid, await File.ReadAllTextAsync(file, Cancellation));
        Assert.Equal([TokenFileName], Entries(directory));
        Assert.Equal(Sha256(valid), (await StateAsync(database))!.Hash);
        Assert.Equal([(IssuedCode, "system")], await EventsAsync(database));

        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), "DROP TRIGGER test_refuse_commit ON bootstrap_state");
        var rerun = await InitAsync(database, directory);

        Assert.True(rerun.ExitCode == 0, rerun.StandardOutput + rerun.StandardError);
        Assert.Equal(Sha256(await File.ReadAllTextAsync(file, Cancellation)), (await StateAsync(database))!.Hash);
        Assert.Equal([TokenFileName], Entries(directory));
    }

    [Fact]
    public async Task Commit_failure_on_the_first_issue_leaves_no_token_file()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        await RefuseCommitsAsync(database);

        var result = await InitAsync(database, directory);

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("The commit's outcome is unknown", result.StandardError);
        Assert.Empty(Entries(directory));
        Assert.Null(await StateAsync(database));
    }

    [Fact]
    public async Task Row_and_event_commit_in_one_transaction()
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        Assert.Equal(0, (await InitAsync(database, TokenDirectory())).ExitCode);

        var superuser = postgres.SuperuserConnection(database);
        var row = await PostgresFixture.ScalarAsync<string>(superuser, "SELECT xmin::text FROM bootstrap_state");
        var audit = await PostgresFixture.ScalarAsync<string>(superuser, "SELECT xmin::text FROM deployment_audit_event");
        Assert.Equal(row, audit);
    }

    [Fact]
    public async Task Concurrent_inits_wait_on_the_lock_then_serialise_and_the_file_holds_the_committed_token()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();

        RunningCli[] runs;
        await using (var holder = await HoldTableAsync(database))
        {
            runs = [StartInit(database, directory), StartInit(database, directory)];
            await WaitForLockWaitersAsync(database, 2);
        }

        var results = await Task.WhenAll(runs.Select(r => r.CompletedAsync()));

        Assert.All(results, r => Assert.True(r.ExitCode == 0, r.StandardOutput + r.StandardError));
        var content = await File.ReadAllTextAsync(Path.Combine(directory, TokenFileName), Cancellation);
        Assert.Equal(Sha256(content), (await StateAsync(database))!.Hash);
        Assert.Equal([TokenFileName], Entries(directory));
        Assert.Equal([IssuedCode, ReissuedCode], await SealedEventsAsync(database));
    }

    [Fact]
    public async Task Signal_while_waiting_cancels_cleanly()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();

        CliResult result;
        await using (var holder = await HoldTableAsync(database))
        {
            var run = StartInit(database, directory);
            await WaitForLockWaitersAsync(database, 1);
            Run("kill", "-TERM", run.Id.ToString(CultureInfo.InvariantCulture));
            result = await run.CompletedAsync();
        }

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("Init was cancelled. Nothing was issued.\n", Error(result));
        Assert.Empty(Entries(directory));
        Assert.Null(await StateAsync(database));
        Assert.Empty(await EventsAsync(database));
    }

    [Fact]
    public async Task Lock_held_past_the_timeout_exits_1_with_its_own_message()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();

        CliResult result;
        await using (var holder = await HoldTableAsync(database))
        {
            result = await InitAsync(database, directory);
        }

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(
            "Init timed out after 30 seconds waiting for another init or a bootstrap to release the bootstrap state. Nothing was issued.\n",
            Error(result));
        Assert.Empty(Entries(directory));
        Assert.Null(await StateAsync(database));
    }

    [Fact]
    public async Task Token_and_its_hash_are_in_no_output_and_no_column_after_issue_and_reissue()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var outputs = new List<CanarySource>();
        var tokens = new List<CanaryValue>();
        var hashes = new List<CanaryValue>();

        foreach (var run in new[] { "first", "reissue" })
        {
            var result = await InitAsync(database, directory);
            Assert.True(result.ExitCode == 0, result.StandardOutput + result.StandardError);

            var token = (await File.ReadAllTextAsync(Path.Combine(directory, TokenFileName), Cancellation)).TrimEnd('\n');
            var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
            tokens.Add(new CanaryValue($"bootstrap-token ({run})", token, token));
            hashes.Add(new CanaryValue($"bootstrap-token hash ({run})", hash, hash));
            outputs.Add(new CanarySource($"init {run} stdout", result.StandardOutput));
            outputs.Add(new CanarySource($"init {run} stderr", result.StandardError));
        }

        // Every table and column. A raw-bytes copy would show as its hex, which is the token itself.
        var tables = await CanaryScanner.DatabaseSourcesAsync(postgres.SuperuserConnection(database), Cancellation);
        Assert.Contains(tables, t => t.Name.StartsWith("bootstrap_state.token_sha256", StringComparison.Ordinal));
        Assert.Contains(tables, t => t.Name.StartsWith("deployment_audit_event.", StringComparison.Ordinal));
        var elsewhere = tables.Where(t => !t.Name.StartsWith("bootstrap_state.token_sha256", StringComparison.Ordinal)).ToList();

        CanaryScanner.ThrowIfFound(CanaryScanner.Scan(tokens, [.. outputs, .. tables]));
        CanaryScanner.ThrowIfFound(CanaryScanner.Scan(hashes, [.. outputs, .. elsewhere]));

        // The scan would find the latest hash where it belongs.
        Assert.Single(CanaryScanner.Scan([hashes[^1]], tables));
    }

    [Theory]
    [InlineData("init|extra-arg")]
    [InlineData("init|--token-dir")]
    [InlineData("init|--token-dir|")]
    [InlineData("init|--token-dir|/tmp|extra-arg")]
    public async Task Malformed_init_shows_usage_and_exits_2(string arguments)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var result = await CliProcess.Start(Environment(database), uid: null, arguments.Split('|')).CompletedAsync();

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("gatekeep init [--token-dir <path>]", result.StandardError);
        Assert.Contains("GATEKEEP_CUSTODY_SOCKET, GATEKEEP_CUSTODY_ROLE_ID_FILE and", result.StandardError);
        Assert.Contains("GATEKEEP_CUSTODY_SECRET_ID_FILE set;", result.StandardError);
        Assert.Null(await StateAsync(database));
    }

    [Fact]
    public async Task Bare_init_without_the_cli_environment_shows_usage()
    {
        var result = await CliProcess.RunCapturedAsync(new Dictionary<string, string>(), "init");

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("gatekeep init [--token-dir <path>]", result.StandardError);
    }

    [Fact]
    public async Task Init_as_another_role_is_refused()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var directory = TokenDirectory();
        var admin = new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Admin, database)) { Password = null }.ConnectionString;

        var result = await InitAsync(admin, directory, rawConnection: true);

        Assert.Equal(1, result.ExitCode);
        Assert.Equal("Init runs only as gk_cli, not gk_admin.\n", Error(result));
        Assert.Empty(Entries(directory));
        Assert.Null(await StateAsync(database));
    }

    [Theory]
    [InlineData(TableRegistry.Hosted, "SELECT * FROM bootstrap_state")]
    [InlineData(TableRegistry.Worker, "SELECT * FROM bootstrap_state")]
    [InlineData(TableRegistry.Dispatch, "SELECT * FROM bootstrap_state")]
    [InlineData(TableRegistry.Sealer, "SELECT * FROM bootstrap_state")]
    [InlineData(TableRegistry.Retention, "SELECT * FROM bootstrap_state")]
    [InlineData(TableRegistry.Hosted, "UPDATE bootstrap_state SET completed_at = now()")]
    [InlineData(TableRegistry.Worker, "UPDATE bootstrap_state SET completed_at = now()")]
    [InlineData(TableRegistry.Cli, "UPDATE bootstrap_state SET completed_at = now()")]
    [InlineData(TableRegistry.Cli, "INSERT INTO bootstrap_state VALUES (1, sha256('x'::bytea), now(), now() + interval '15 minutes', now())")]
    [InlineData(TableRegistry.Admin, "UPDATE bootstrap_state SET token_sha256 = sha256('y'::bytea)")]
    [InlineData(TableRegistry.Admin, "UPDATE bootstrap_state SET expires_at = now() + interval '1 hour'")]
    [InlineData(TableRegistry.Admin, "UPDATE bootstrap_state SET issued_at = now()")]
    [InlineData(TableRegistry.Admin, "INSERT INTO bootstrap_state VALUES (1, sha256('x'::bytea), now(), now() + interval '15 minutes')")]
    [InlineData(TableRegistry.Cli, "DELETE FROM bootstrap_state")]
    [InlineData(TableRegistry.Admin, "DELETE FROM bootstrap_state")]
    [InlineData(TableRegistry.Cli, "TRUNCATE bootstrap_state")]
    [InlineData(TableRegistry.Admin, "TRUNCATE bootstrap_state")]
    public async Task Roles_without_a_grant_cant_touch_bootstrap_state(string role, string sql)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await SeedStateAsync(database);

        var denied = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql));

        Assert.Equal(PermissionDenied, denied.SqlState);
        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM bootstrap_state"));
    }

    [Theory]
    [InlineData(TableRegistry.Cli, "UPDATE bootstrap_state SET token_sha256 = sha256('y'::bytea), issued_at = now(), expires_at = now() + interval '15 minutes'")]
    [InlineData(TableRegistry.Admin, "UPDATE bootstrap_state SET completed_at = now()")]
    public async Task Cli_reissues_and_Admin_completes(string role, string sql)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await SeedStateAsync(database);

        await PostgresFixture.ExecuteAsync(postgres.RoleConnection(role, database), sql);

        Assert.Equal(1L, await PostgresFixture.ScalarAsync<long>(postgres.RoleConnection(role, database), "SELECT count(*) FROM bootstrap_state"));
    }

    [Theory]
    [InlineData(null, "UPDATE bootstrap_state SET completed_at = NULL")]
    [InlineData(null, "UPDATE bootstrap_state SET completed_at = now() + interval '1 minute'")]
    [InlineData(null, "UPDATE bootstrap_state SET token_sha256 = sha256('y'::bytea)")]
    [InlineData(null, "UPDATE bootstrap_state SET expires_at = expires_at + interval '1 hour'")]
    [InlineData(TableRegistry.Admin, "UPDATE bootstrap_state SET completed_at = NULL")]
    [InlineData(TableRegistry.Admin, "UPDATE bootstrap_state SET completed_at = now() + interval '1 minute'")]
    public async Task Completed_row_is_final_even_for_the_superuser(string? role, string sql)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await SeedStateAsync(database);
        var superuser = postgres.SuperuserConnection(database);
        await PostgresFixture.ExecuteAsync(superuser, "UPDATE bootstrap_state SET completed_at = now()");
        var before = await StateAsync(database);

        var raised = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(role is null ? superuser : postgres.RoleConnection(role, database), sql));

        Assert.Equal(Raised, raised.SqlState);
        Assert.Equal(before, await StateAsync(database));
    }

    [Theory]
    [InlineData("INSERT INTO bootstrap_state VALUES (2, sha256('x'::bytea), now(), now() + interval '15 minutes')")]
    [InlineData("INSERT INTO bootstrap_state VALUES (1, 'short'::bytea, now(), now() + interval '15 minutes')")]
    [InlineData("INSERT INTO bootstrap_state VALUES (1, sha256('x'::bytea), now(), now() - interval '1 minute')")]
    public async Task Schema_refuses_a_row_off_its_shape(string sql)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(
            () => PostgresFixture.ExecuteAsync(postgres.RoleConnection(TableRegistry.Cli, database), sql));

        Assert.Equal("23514", refused.SqlState);
    }

    public void Dispose()
    {
        _socket.Dispose();
        Directory.Delete(_scratch, recursive: true);
    }

    internal sealed record BootstrapState(byte[] Hash, DateTime IssuedAt, DateTime ExpiresAt, DateTime? CompletedAt)
    {
        public bool Equals(BootstrapState? other) =>
            other is not null && Hash.SequenceEqual(other.Hash) && IssuedAt == other.IssuedAt
            && ExpiresAt == other.ExpiresAt && CompletedAt == other.CompletedAt;

        public override int GetHashCode() => HashCode.Combine(IssuedAt, ExpiresAt, CompletedAt);
    }

    /// <summary>The scratch folder, which the cli uid can traverse, as it reads its files there.</summary>
    private static string Scratch()
    {
        var scratch = Directory.CreateTempSubdirectory("gatekeep-init-").FullName;
        File.SetUnixFileMode(scratch, (UnixFileMode)Convert.ToInt32("0755", 8));
        return scratch;
    }

    private static string Error(CliResult result) => result.StandardError.ReplaceLineEndings("\n");

    private static List<string> Entries(string directory) =>
        [.. Directory.EnumerateFileSystemEntries(directory).Select(e => Path.GetFileName(e)!).Order(StringComparer.Ordinal)];

    private static void AssertNoToken(string token, CliResult result)
    {
        var value = token.TrimEnd('\n');
        Assert.DoesNotContain(value, result.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain(value, result.StandardError, StringComparison.Ordinal);
    }

    private static byte[] Sha256(string fileContent) =>
        SHA256.HashData(Encoding.ASCII.GetBytes(fileContent.TrimEnd('\n')));

    /// <summary>One <c>stat -c</c> field set of <paramref name="path"/>, without following a link.</summary>
    private static string Stat(string format, string path) => Run("stat", "-c", format, path);

    private static string Run(string program, params string[] arguments)
    {
        var start = new ProcessStartInfo(program) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        Assert.True(process.ExitCode == 0, $"{program} failed: {process.StandardError.ReadToEnd()}");
        return output.Trim();
    }

    private Task SeedStateAsync(string database) =>
        PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            "INSERT INTO bootstrap_state VALUES (1, sha256('seed'::bytea), now(), now() + interval '15 minutes')");

    /// <summary>A constraint trigger that raises at commit, after init has renamed its file into place.</summary>
    private Task RefuseCommitsAsync(string database) =>
        PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            """
            CREATE FUNCTION test_refuse_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused at commit by the test'; END $$;
            CREATE CONSTRAINT TRIGGER test_refuse_commit AFTER INSERT OR UPDATE ON bootstrap_state
              DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION test_refuse_commit();
            """);

    /// <summary>A superuser transaction holding a lock every write to <c>bootstrap_state</c> waits on.</summary>
    private async Task<HeldLock> HoldTableAsync(string database)
    {
        var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        var transaction = await connection.BeginTransactionAsync(Cancellation);
        await using var command = new NpgsqlCommand("LOCK TABLE bootstrap_state IN SHARE MODE", connection, transaction);
        await command.ExecuteNonQueryAsync(Cancellation);
        return new HeldLock(connection, transaction);
    }

    private async Task WaitForLockWaitersAsync(string database, int count)
    {
        var deadline = DateTime.UtcNow.AddSeconds(25);
        while (true)
        {
            var waiting = await PostgresFixture.ScalarAsync<long>(
                postgres.SuperuserConnection(database),
                $"SELECT count(*) FROM pg_stat_activity WHERE datname = '{database}' AND usename = 'gk_cli' AND wait_event_type = 'Lock'");
            if (waiting >= count)
            {
                return;
            }

            Assert.True(DateTime.UtcNow < deadline, $"Only {waiting} of {count} inits came to wait on the lock.");
            await Task.Delay(100, Cancellation);
        }
    }

    private async Task AssertNothingIssuedAsync(string database, string directory)
    {
        Assert.Empty(Entries(directory));
        Assert.Null(await StateAsync(database));
        Assert.Empty(await EventsAsync(database));
    }

    /// <summary>A fresh token directory, as bootstrap-dir leaves it unless a test says otherwise.</summary>
    private string TokenDirectory(int? owner = null, UnixFileMode mode = Private)
    {
        var directory = Path.Combine(_scratch, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        if (owner is { } uid)
        {
            Run("chown", $"{uid}:{uid}", directory);
        }

        File.SetUnixFileMode(directory, mode);
        return directory;
    }

    private RunningCli StartInit(string database, string directory) =>
        CliProcess.Start(Environment(database), uid: null, "init", "--token-dir", directory);

    private Task<CliResult> InitAsync(
        string database,
        string directory,
        int? uid = null,
        string? socket = null,
        string? secretIdFile = null,
        bool rawConnection = false) =>
        CliProcess.Start(Environment(database, socket, secretIdFile, rawConnection), uid, "init", "--token-dir", directory).CompletedAsync();

    /// <summary>What the <c>cli</c> service sets, pointed at this test's database, socket and AppRole files.</summary>
    private Dictionary<string, string> Environment(
        string database,
        string? socket = null,
        string? secretIdFile = null,
        bool rawConnection = false)
    {
        var options = bao.Options(OpenBaoFixture.Cli);
        var connection = rawConnection
            ? database
            : new NpgsqlConnectionStringBuilder(postgres.RoleConnection(TableRegistry.Cli, database)) { Password = null }.ConnectionString;

        return new Dictionary<string, string>
        {
            ["GATEKEEP_CLI_CONNECTION_FILE"] = WriteFile(connection),
            ["GATEKEEP_CLI_PASSWORD_FILE"] = WriteFile(PostgresFixture.Password + "\n"),
            ["GATEKEEP_CUSTODY_SOCKET"] = socket ?? _socket.Path,
            ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = options.RoleIdFile,
            ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = secretIdFile ?? options.SecretIdFile,
        };
    }

    private async Task<BootstrapState?> StateAsync(string database)
    {
        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT token_sha256, issued_at, expires_at, completed_at FROM bootstrap_state WHERE id = 1", connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);
        if (!await reader.ReadAsync(Cancellation))
        {
            return null;
        }

        return new BootstrapState(
            reader.GetFieldValue<byte[]>(0),
            reader.GetDateTime(1),
            reader.GetDateTime(2),
            reader.IsDBNull(3) ? null : reader.GetDateTime(3));
    }

    /// <summary>The Deployment chain's events, oldest first: each code and Actor kind.</summary>
    private async Task<List<(string Code, string Actor)>> EventsAsync(string database)
    {
        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand(
            "SELECT type_code, actor_kind, actor_id IS NULL AND target_kind IS NULL AND target_id IS NULL FROM deployment_audit_event ORDER BY occurred_at, id",
            connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);

        var events = new List<(string, string)>();
        while (await reader.ReadAsync(Cancellation))
        {
            Assert.True(reader.GetBoolean(2), "A bootstrap event names an Actor ID or a target.");
            events.Add((reader.GetString(0), reader.GetString(1)));
        }

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database), "SELECT count(*) FROM deployment_audit_detail"));
        return events;
    }

    /// <summary>Seals the Deployment chain as <c>gk_sealer</c>, then lists its codes in chain order.</summary>
    private async Task<List<string>> SealedEventsAsync(string database)
    {
        await using (var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Sealer, database)))
        await using (var scope = await DeploymentScope.BeginAsync(source, Cancellation))
        {
            await AuditContract.CreateSealer().SealAsync(scope.CreateCommandContext(), 100, Cancellation);
            await scope.CommitAsync(Cancellation);
        }

        await using var connection = new NpgsqlConnection(postgres.SuperuserConnection(database));
        await connection.OpenAsync(Cancellation);
        await using var command = new NpgsqlCommand("SELECT type_code, seq FROM deployment_audit_event ORDER BY seq", connection);
        await using var reader = await command.ExecuteReaderAsync(Cancellation);

        var codes = new List<string>();
        while (await reader.ReadAsync(Cancellation))
        {
            Assert.False(reader.IsDBNull(1), "An event wasn't sealed.");
            codes.Add(reader.GetString(0));
        }

        return codes;
    }

    private async Task<int> KeyVersionAsync(string key) =>
        (await InitKeys.ReadAsync(bao, key, Cancellation)).GetProperty("latest_version").GetInt32();

    private string WriteFile(string contents)
    {
        var path = Path.Combine(_scratch, Guid.NewGuid().ToString("N"));
        File.WriteAllText(path, contents);
        return path;
    }

    /// <summary>The held transaction and its connection, released together: rolled back, then closed.</summary>
    private sealed class HeldLock(NpgsqlConnection connection, NpgsqlTransaction transaction) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await transaction.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
