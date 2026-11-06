using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Cli;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Canary;
using Gatekeep.Tests.Isolation.Custody;
using Xunit;
using CanaryValue = Gatekeep.Tests.Isolation.Canary.Canary;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30: the audit shipper copies what OpenBao appends to its audit file into the bucket, in
/// whole lines, within 30 seconds; it resumes at its offset after a restart with no gap and no
/// repeated key; it starts over under a new file ID when the file shrinks; and the chunks hold no
/// plaintext, token or secret ID, because the audit device HMACs every value.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class AuditShipTests(OpenBaoFixture bao, ObjectLockFixture bucket) : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-ship-").FullName;

    // A chunk shipped near midnight lands under either day, so both are searched.
    private readonly DateTime _started = DateTime.UtcNow;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task Audit_log_is_readable_by_the_openbao_audit_group_alone()
    {
        var modes = await bao.ExecAsync("stat", "-c", "%a %U %G", "/var/log/openbao", OpenBaoFixture.AuditLog);

        Assert.Equal(0, modes.ExitCode);
        Assert.Equal(["2750 openbao openbao-audit", "640 openbao openbao-audit"], modes.Stdout.Trim().Split('\n'));
    }

    [Fact]
    public async Task Transit_requests_reach_the_bucket_within_30_seconds_with_no_plaintext_or_token()
    {
        var plaintext = "cnry-transit-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));
        var social = KeyName.ForTenant(TenantKeyClass.Social, bao.TenantA);
        using (var cli = bao.Custody(OpenBaoFixture.Cli))
        {
            await cli.EncryptAsync(social, bao.TenantA, new Secret<byte[]>(Encoding.UTF8.GetBytes(plaintext)), Cancellation);
            await cli.SignAsync(OffServerRecords.SigningKey, "record"u8.ToArray(), Cancellation);
        }

        // A raw encrypt with a token this test holds, so the token itself is a canary.
        var token = await bao.LoginAsync(OpenBaoFixture.Cli);
        using (var http = new HttpClient { BaseAddress = bao.Address })
        {
            http.DefaultRequestHeaders.Add("X-Vault-Token", token);
            using var raw = await http.PostAsJsonAsync(
                $"v1/transit/encrypt/{social}",
                new { plaintext = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext)), associated_data = Convert.ToBase64String(Encoding.UTF8.GetBytes(bao.TenantA.ToString("D"))) },
                Cancellation);
        }

        // The shipper reads a copy of the audit file, as the shipper service reads the volume.
        var auditFile = Path.Combine(_directory, "audit.log");
        await File.WriteAllTextAsync(auditFile, string.Empty, Cancellation);
        var state = State();
        var output = new StringWriter();
        var error = new StringWriter();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
        var shipping = AuditShipCommand.ShipAsync(
            bucket.Options(), auditFile, state, ObjectLockFixture.Permitted(), TimeProvider.System, output, error,
            once: false, AuditShipCommand.Interval, stop.Token);

        var audit = await bao.ReadTextAsync(OpenBaoFixture.AuditLog);
        // Whole lines only, in case OpenBao was part way through one when it was read.
        audit = audit[..(audit.LastIndexOf('\n') + 1)];
        await File.WriteAllTextAsync(auditFile, audit, Cancellation);
        var written = Stopwatch.StartNew();
        IReadOnlyList<ObjectVersion> shipped = [];
        while (shipped.Count == 0 && written.Elapsed < TimeSpan.FromSeconds(30))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);
            if (File.Exists(Path.Combine(state, "state")))
            {
                shipped = await ShippedAsync(FileId(state));
            }
        }

        Assert.NotEmpty(shipped);
        Assert.True(written.Elapsed < TimeSpan.FromSeconds(30), $"Shipped after {written.Elapsed}.");

        // A long audit file goes up in several chunks: wait until the offset reaches its end.
        var length = Encoding.UTF8.GetByteCount(audit);
        while (Offset(state) < length && written.Elapsed < TimeSpan.FromSeconds(90))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);
        }

        Assert.Equal(length, Offset(state));
        await stop.CancelAsync();
        Assert.Equal(0, await shipping);

        List<(string Name, string Text)> dumped = [];
        foreach (var prefix in Prefixes(FileId(state)))
        {
            dumped.AddRange(await bucket.DumpAsync(prefix));
        }

        var chunks = string.Concat(dumped.Where(d => d.Name.StartsWith("bucket object", StringComparison.Ordinal)).Select(d => d.Text));
        Assert.Contains($"\"path\":\"transit/encrypt/{social}\"", chunks, StringComparison.Ordinal);
        Assert.Contains("\"path\":\"transit/sign/dep-records\"", chunks, StringComparison.Ordinal);
        Assert.All(dumped.Where(d => d.Name.StartsWith("bucket metadata", StringComparison.Ordinal)), d => Assert.StartsWith("COMPLIANCE ", d.Text, StringComparison.Ordinal));

        List<CanaryValue> canaries =
        [
            new("transit-plaintext", plaintext, plaintext),
            new("transit-plaintext-base64", Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext)), string.Empty),
            new("openbao-token", token, token),
            new("bucket-secret-key", bucket.SecretAccessKey, string.Empty),
        ];
        var secretId = (await File.ReadAllTextAsync(bao.Options(OpenBaoFixture.Cli).SecretIdFile, Cancellation)).Trim();
        canaries.Add(new CanaryValue("secret-id", secretId, string.Empty));

        CanarySource[] sources =
        [
            .. dumped.Select(d => new CanarySource(d.Name, d.Text)),
            new("shipper stdout", output.ToString()),
            new("shipper stderr", error.ToString()),
        ];
        CanaryScanner.ThrowIfFound(CanaryScanner.Scan(canaries, sources));
    }

    [Fact]
    public async Task Restarted_shipper_resumes_at_its_offset_with_no_gap_and_no_repeated_key()
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        var state = State();
        await File.WriteAllTextAsync(auditFile, Lines(0, 3) + "{\"partial\":", Cancellation);

        // The last line isn't finished, so it waits.
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));
        var fileId = FileId(state);
        var first = Assert.Single(await ShippedAsync(fileId));
        Assert.EndsWith($"{fileId}-{0:D20}.jsonl", first.Key, StringComparison.Ordinal);
        Assert.Equal(Lines(0, 3), await bucket.ReadAsync(first));

        // A new process, as a restart is, with the same state directory.
        await File.AppendAllTextAsync(auditFile, "1}\n" + Lines(3, 2), Cancellation);
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));

        var versions = (await ShippedAsync(fileId)).OrderBy(v => v.Key, StringComparer.Ordinal).ToList();
        Assert.Equal(2, versions.Count);
        Assert.Equal(versions.Count, versions.Select(v => v.Key).Distinct().Count());
        Assert.EndsWith($"{fileId}-{Encoding.UTF8.GetByteCount(Lines(0, 3)):D20}.jsonl", versions[1].Key, StringComparison.Ordinal);
        Assert.Equal(await File.ReadAllTextAsync(auditFile, Cancellation), await bucket.ReadAsync(versions[0]) + await bucket.ReadAsync(versions[1]));
    }

    [Fact]
    public async Task File_shorter_than_the_saved_offset_starts_over_from_0_under_a_new_file_ID()
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        var state = State();
        await File.WriteAllTextAsync(auditFile, Lines(0, 4), Cancellation);
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));
        var before = FileId(state);

        await File.WriteAllTextAsync(auditFile, Lines(10, 1), Cancellation);
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));

        var after = FileId(state);
        Assert.NotEqual(before, after);
        var restarted = Assert.Single(await ShippedAsync(after));
        Assert.EndsWith($"{after}-{0:D20}.jsonl", restarted.Key, StringComparison.Ordinal);
        Assert.Equal(Lines(10, 1), await bucket.ReadAsync(restarted));
    }

    [Fact]
    public async Task File_replaced_and_regrown_past_the_saved_offset_ships_everything_from_0_under_a_new_file_ID()
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        var state = State();
        await File.WriteAllTextAsync(auditFile, Lines(0, 2), Cancellation);
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));
        var before = FileId(state);

        // A new file, already longer than the old offset before the next pass sees it.
        File.Delete(auditFile);
        await File.WriteAllTextAsync(auditFile, Lines(100, 6), Cancellation);
        Assert.True(new FileInfo(auditFile).Length > Offset(state));
        var output = new StringWriter();
        Assert.Equal(0, await AuditShipCommand.ShipAsync(
            bucket.Options(), auditFile, state, ObjectLockFixture.Permitted(), TimeProvider.System,
            output, new StringWriter(), once: true, AuditShipCommand.Interval, Cancellation));

        var after = FileId(state);
        Assert.NotEqual(before, after);
        Assert.Contains(AuditShipper.Replaced, output.ToString(), StringComparison.Ordinal);
        var restarted = Assert.Single(await ShippedAsync(after));
        Assert.EndsWith($"{after}-{0:D20}.jsonl", restarted.Key, StringComparison.Ordinal);
        Assert.Equal(Lines(100, 6), await bucket.ReadAsync(restarted));
        Assert.Equal(Encoding.UTF8.GetByteCount(Lines(100, 6)), Offset(state));
    }

    [Fact]
    public async Task Unreadable_state_says_so_and_ships_everything_again_under_a_new_file_ID()
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        var state = State();
        await File.WriteAllTextAsync(auditFile, Lines(0, 2), Cancellation);
        await File.WriteAllTextAsync(Path.Combine(state, "state"), "not a state\n", Cancellation);
        var output = new StringWriter();

        Assert.Equal(0, await AuditShipCommand.ShipAsync(
            bucket.Options(), auditFile, state, ObjectLockFixture.Permitted(), TimeProvider.System,
            output, new StringWriter(), once: true, AuditShipCommand.Interval, Cancellation));

        Assert.Contains(AuditShipper.StateUnreadable, output.ToString(), StringComparison.Ordinal);
        Assert.Equal(Lines(0, 2), await bucket.ReadAsync(Assert.Single(await ShippedAsync(FileId(state)))));
    }

    [Fact]
    public async Task No_audit_file_yet_ships_nothing_and_says_so()
    {
        var output = new StringWriter();

        var exit = await AuditShipCommand.ShipAsync(
            bucket.Options(), Path.Combine(_directory, "missing.log"), State(), ObjectLockFixture.Permitted(), TimeProvider.System,
            output, new StringWriter(), once: true, AuditShipCommand.Interval, Cancellation);

        Assert.Equal(0, exit);
        Assert.Contains("There is no audit file yet", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Bucket_failure_is_one_fixed_line_and_the_offset_stays()
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        var state = State();
        await File.WriteAllTextAsync(auditFile, Lines(0, 2), Cancellation);
        var wrong = Path.Combine(_directory, "wrong-secret");
        await File.WriteAllTextAsync(wrong, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(20)), Cancellation);
        var error = new StringWriter();

        var exit = await AuditShipCommand.ShipAsync(
            bucket.Options(secretAccessKeyFile: wrong), auditFile, state, ObjectLockFixture.Permitted(), TimeProvider.System,
            new StringWriter(), error, once: true, AuditShipCommand.Interval, Cancellation);

        Assert.Equal(1, exit);
        Assert.Equal(AuditShipCommand.Rejected, error.ToString().Trim());
        Assert.Equal(0, await ShipOnceAsync(auditFile, state));
        Assert.Equal(Lines(0, 2), await bucket.ReadAsync(Assert.Single(await ShippedAsync(FileId(state)))));
    }

    /// <summary>The prefixes chunks of <paramref name="fileId"/> shipped since this test started can be under: that day's, and today's.</summary>
    private IEnumerable<string> Prefixes(Guid fileId) =>
        new[] { _started, DateTime.UtcNow }.Select(d => $"openbao-audit/{d:yyyy'/'MM'/'dd}/{fileId}-").Distinct(StringComparer.Ordinal);

    private async Task<IReadOnlyList<ObjectVersion>> ShippedAsync(Guid fileId)
    {
        List<ObjectVersion> shipped = [];
        foreach (var prefix in Prefixes(fileId))
        {
            shipped.AddRange(await bucket.VersionsAsync(prefix));
        }

        return shipped;
    }

    private Task<int> ShipOnceAsync(string auditFile, string state) =>
        AuditShipCommand.ShipAsync(
            bucket.Options(), auditFile, state, ObjectLockFixture.Permitted(), TimeProvider.System,
            new StringWriter(), new StringWriter(), once: true, AuditShipCommand.Interval, Cancellation);

    private string State() => Directory.CreateDirectory(Path.Combine(_directory, "state-" + Guid.NewGuid().ToString("N"))).FullName;

    private static Guid FileId(string state) => Guid.ParseExact(File.ReadAllLines(Path.Combine(state, "state"))[0], "D");

    private static long Offset(string state) => long.Parse(File.ReadAllLines(Path.Combine(state, "state"))[1], System.Globalization.CultureInfo.InvariantCulture);

    private static string Lines(int first, int count) =>
        string.Concat(Enumerable.Range(first, count).Select(i => JsonSerializer.Serialize(new { type = "request", n = i }) + "\n"));
}
