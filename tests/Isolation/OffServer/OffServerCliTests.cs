using System.Text;
using System.Text.Json.Nodes;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Cli;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Retention;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Hosting;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30: <c>gatekeep alerts test</c>, <c>records test</c> and <c>audit-ship</c>. As a real
/// process each refuses a missing or unsafe setting by name before doing anything and never prints
/// a value, and refuses a private address with its fixed line. In process, with EgressHttp's test
/// permit, the test alert reaches the sink and the test record lands in the locked bucket, signed
/// with <c>dep-records</c> by the cli AppRole.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class OffServerCliTests(OpenBaoFixture bao, ObjectLockFixture bucket) : IDisposable
{
    private const string Canary = "cnry-cli-setting-7c41";

    private static readonly string[] AlertVariables =
        [OffServerSettings.AlertUrlVariable, OffServerSettings.AlertTokenFileVariable, OffServerSettings.AlertDeploymentVariable];

    private static readonly string[] RecordsVariables =
    [
        OffServerSettings.RecordsEndpointVariable,
        OffServerSettings.RecordsRegionVariable,
        OffServerSettings.RecordsBucketVariable,
        OffServerSettings.RecordsAccessKeyIdFileVariable,
        OffServerSettings.RecordsSecretAccessKeyFileVariable,
    ];

    private static readonly string[] CustodyVariables =
        ["GATEKEEP_CUSTODY_SOCKET", "GATEKEEP_CUSTODY_ROLE_ID_FILE", "GATEKEEP_CUSTODY_SECRET_ID_FILE"];

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-offserver-cli-").FullName;
    private readonly List<FakeOpenBaoSocket> _sockets = [];

    // Every request any stand-in OpenBao socket got: a refusal must come before custody is reached.
    private int _custodyRequests;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        foreach (var socket in _sockets)
        {
            socket.Dispose();
        }

        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task Alerts_test_with_no_settings_refuses_naming_each_and_sends_nothing()
    {
        var result = await CliProcess.RunCapturedAsync(new Dictionary<string, string>(), "alerts", "test");

        Assert.Equal(1, result.ExitCode);
        Assert.All(AlertVariables, v => Assert.Contains(v, result.StandardError, StringComparison.Ordinal));
        Assert.Contains("Nothing was sent.", result.StandardError, StringComparison.Ordinal);
        Assert.Empty(result.StandardOutput);
    }

    public static TheoryData<string, string> UnsafeAlertSettings => new()
    {
        { OffServerSettings.AlertUrlVariable, $"http://alerts.example.com/{Canary}" },
        { OffServerSettings.AlertUrlVariable, $"https://{Canary}:x@alerts.example.com/hook" },
        { OffServerSettings.AlertUrlVariable, $"alerts.example.com/{Canary}" },
        { OffServerSettings.AlertTokenFileVariable, "file:" },
        { OffServerSettings.AlertTokenFileVariable, "file:changeme" },
        { OffServerSettings.AlertTokenFileVariable, "missing" },
        { OffServerSettings.AlertTokenFileVariable, "file:alert token" },
        { OffServerSettings.AlertTokenFileVariable, "file:alert\ttoken" },
        { OffServerSettings.AlertTokenFileVariable, "file:alert\u00e9token" },
        { OffServerSettings.AlertDeploymentVariable, $"https://{Canary}.example.com" },
        { OffServerSettings.AlertDeploymentVariable, "localhost" },
    };

    [Theory]
    [MemberData(nameof(UnsafeAlertSettings))]
    public async Task Alerts_test_with_one_unsafe_setting_refuses_naming_only_it_and_never_its_value(string variable, string value)
    {
        var environment = AlertEnvironment("https://alerts.invalid/hook");
        environment[variable] = Resolve(value);

        var result = await CliProcess.RunCapturedAsync(environment, "alerts", "test");

        Assert.Equal(1, result.ExitCode);
        Assert.Contains(variable, result.StandardError, StringComparison.Ordinal);
        Assert.All(AlertVariables.Where(v => v != variable), v => Assert.DoesNotContain(v, result.StandardError, StringComparison.Ordinal));
        Assert.DoesNotContain(Canary, result.StandardOutput + result.StandardError, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://10.0.0.1/hook")]
    [InlineData("https://127.0.0.1/hook")]
    [InlineData("https://[::ffff:192.168.1.1]/hook")]
    [InlineData("https://[fd00::1]/hook")]
    [InlineData("https://host.docker.internal/hook")]
    public async Task Alerts_test_to_a_private_address_prints_the_fixed_refusal(string url)
    {
        var result = await CliProcess.RunCapturedAsync(AlertEnvironment(url), "alerts", "test");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(AlertsTestCommand.RefusedPrivate, result.StandardError.Trim());
        Assert.Empty(result.StandardOutput);
    }

    [Fact]
    public async Task Alerts_test_to_a_name_that_never_resolves_is_unavailable()
    {
        var result = await CliProcess.RunCapturedAsync(AlertEnvironment("https://alerts.invalid/hook"), "alerts", "test");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(AlertsTestCommand.Unavailable, result.StandardError.Trim());
        Assert.DoesNotContain("alerts.invalid", result.StandardOutput + result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Alerts_test_delivers_one_test_alert_and_prints_its_ID()
    {
        await using var sink = await AlertSinkFixture.StartAsync();
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await AlertsTestCommand.SendAsync(
            Webhook(sink), new AlertDeployment("admin.gatekeep-admin.test"), ObjectLockFixture.Permitted(), TimeProvider.System, output, error, Cancellation);

        Assert.Equal(0, exit);
        Assert.Empty(error.ToString());
        var request = Assert.Single(sink.Requests);
        var body = JsonNode.Parse(request.Body)!.AsObject();
        Assert.Equal("operations.alert.test", (string?)body["code"]);
        Assert.Equal($"{AlertsTestCommand.Delivered} Alert ID: {(string?)body["alertId"]}", output.ToString().Trim());
        Assert.StartsWith("Bearer ", request.Headers["Authorization"], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(404)]
    [InlineData(500)]
    [InlineData(302)]
    public async Task Alerts_test_answered_other_than_2xx_prints_only_the_fixed_line(int status)
    {
        await using var sink = await AlertSinkFixture.StartAsync();
        sink.Status = status;
        sink.Location = status == 302 ? "https://example.com/" : null;
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await AlertsTestCommand.SendAsync(
            Webhook(sink), new AlertDeployment("admin.gatekeep-admin.test"), ObjectLockFixture.Permitted(), TimeProvider.System, output, error, Cancellation);

        Assert.Equal(1, exit);
        Assert.Empty(output.ToString());
        Assert.Equal(AlertsTestCommand.Rejected, error.ToString().Trim());
        Assert.Single(sink.Requests);
    }

    [Fact]
    public async Task Records_test_with_no_settings_refuses_naming_each_and_signs_nothing()
    {
        var result = await CliProcess.RunCapturedAsync(new Dictionary<string, string>(), "records", "test");

        Assert.Equal(1, result.ExitCode);
        Assert.All(RecordsVariables.Concat(CustodyVariables), v => Assert.Contains(v, result.StandardError, StringComparison.Ordinal));
        Assert.Contains("Nothing was signed or written.", result.StandardError, StringComparison.Ordinal);
        Assert.Empty(result.StandardOutput);
    }

    public static TheoryData<string, string> UnsafeRecordsSettings => new()
    {
        { OffServerSettings.RecordsEndpointVariable, $"http://{Canary}.example.com" },
        { OffServerSettings.RecordsEndpointVariable, $"https://{Canary}:x@s3.example.com" },
        { OffServerSettings.RecordsEndpointVariable, $"https://s3.example.com/{Canary}" },
        { OffServerSettings.RecordsBucketVariable, $"Bad_{Canary}" },
        { OffServerSettings.RecordsBucketVariable, "192.168.1.1" },
        { OffServerSettings.RecordsRegionVariable, $"US_{Canary}" },
        { OffServerSettings.RecordsAccessKeyIdFileVariable, "file:" },
        { OffServerSettings.RecordsSecretAccessKeyFileVariable, "file:password" },
        { OffServerSettings.RecordsSecretAccessKeyFileVariable, "missing" },
        { OffServerSettings.RecordsAccessKeyIdFileVariable, "file:ak 123" },
        { OffServerSettings.RecordsSecretAccessKeyFileVariable, "file:sk\u0001123" },
        { OffServerSettings.RecordsSecretAccessKeyFileVariable, "file:sk\u00e9123" },
    };

    [Theory]
    [MemberData(nameof(UnsafeRecordsSettings))]
    public async Task Records_test_and_audit_ship_with_one_unsafe_setting_refuse_naming_only_it(string variable, string value)
    {
        foreach (var command in new[] { new[] { "records", "test" }, ["audit-ship", "--once"], ["audit-ship"] })
        {
            var environment = RecordsEnvironment("https://objects.invalid");
            environment[variable] = Resolve(value);

            var result = await CliProcess.RunCapturedAsync(environment, command);

            Assert.Equal(1, result.ExitCode);
            Assert.Contains(variable, result.StandardError, StringComparison.Ordinal);
            Assert.All(RecordsVariables.Where(v => v != variable), v => Assert.DoesNotContain(v, result.StandardError, StringComparison.Ordinal));
            Assert.DoesNotContain(Canary, result.StandardOutput + result.StandardError, StringComparison.Ordinal);
        }

        Assert.Equal(0, _custodyRequests);
    }

    [Theory]
    [InlineData("https://127.0.0.1")]
    [InlineData("https://10.0.0.1:9000")]
    [InlineData("https://[::1]")]
    public async Task Records_test_to_a_private_address_prints_the_fixed_refusal(string endpoint)
    {
        var result = await CliProcess.RunCapturedAsync(RecordsEnvironment(endpoint), "records", "test");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(RecordsTestCommand.RefusedPrivate, result.StandardError.Trim());
    }

    [Fact]
    public async Task Audit_ship_with_no_settings_refuses_naming_each_and_ships_nothing()
    {
        var result = await CliProcess.RunCapturedAsync(new Dictionary<string, string>(), "audit-ship", "--once");

        Assert.Equal(1, result.ExitCode);
        Assert.All(
            RecordsVariables.Append(OffServerSettings.AuditLogFileVariable).Append(OffServerSettings.AuditShipStateVariable),
            v => Assert.Contains(v, result.StandardError, StringComparison.Ordinal));
        Assert.Contains("Nothing was shipped.", result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Audit_ship_to_a_private_address_prints_the_fixed_refusal()
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        await File.WriteAllTextAsync(auditFile, "{\"type\":\"request\"}\n", Cancellation);
        var environment = RecordsEnvironment("https://127.0.0.1");
        environment[OffServerSettings.AuditLogFileVariable] = auditFile;
        environment[OffServerSettings.AuditShipStateVariable] = Directory.CreateDirectory(Path.Combine(_directory, "state")).FullName;

        var result = await CliProcess.RunCapturedAsync(environment, "audit-ship", "--once");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(AuditShipCommand.RefusedPrivate, result.StandardError.Trim());
    }

    [Fact]
    public async Task Records_test_writes_a_signed_record_in_compliance_mode_for_90_days_that_verifies_with_dep_records()
    {
        var before = DateTimeOffset.UtcNow;
        var output = new StringWriter();
        var error = new StringWriter();
        using var cli = bao.Custody(OpenBaoFixture.Cli);

        var exit = await RecordsTestCommand.WriteAsync(
            bucket.Options(), cli, ObjectLockFixture.Permitted(), TimeProvider.System, output, error, Cancellation);

        Assert.Equal(0, exit);
        Assert.Empty(error.ToString());
        var printed = output.ToString().Trim();
        Assert.StartsWith(RecordsTestCommand.Written + " ", printed, StringComparison.Ordinal);
        var key = printed[(RecordsTestCommand.Written.Length + 1)..];
        Assert.Matches(@"^records/test/\d{4}/\d{2}/\d{2}/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\.json$", key);

        var version = Assert.Single(await bucket.VersionsAsync(key));
        var locked = await bucket.LockAsync(version);
        Assert.Equal("COMPLIANCE", locked.Mode);
        Assert.True(locked.RetainUntil >= before.AddDays(RetentionPeriods.LogDays));
        Assert.True(RetentionPeriods.LogDays >= 90);

        var content = Encoding.UTF8.GetBytes(await bucket.ReadAsync(version));
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        Assert.True(await OffServerRecords.VerifyAsync(worker, content, Cancellation));
        var record = JsonNode.Parse(content)!.AsObject();
        Assert.Equal("dep-records", (string?)record["signature"]!["key"]);
        Assert.Equal("test", (string?)record["kind"]);

        // A changed payload no longer verifies.
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(content).Replace("gatekeep records test", "gatekeep records tess", StringComparison.Ordinal));
        Assert.False(await OffServerRecords.VerifyAsync(worker, tampered, Cancellation));
    }

    [Fact]
    public async Task Records_test_whose_signing_is_refused_writes_nothing()
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var before = (await bucket.VersionsAsync("records/test/")).Count;
        // Host.Hosted's policy may not sign with dep-records.
        using var hosted = bao.Custody(OpenBaoFixture.Hosted);

        var exit = await RecordsTestCommand.WriteAsync(
            bucket.Options(), hosted, ObjectLockFixture.Permitted(), TimeProvider.System, output, error, Cancellation);

        Assert.Equal(1, exit);
        Assert.Equal("Key custody failed (Refused), so the test record wasn't signed. Nothing was written.", error.ToString().Trim());
        Assert.Equal(before, (await bucket.VersionsAsync("records/test/")).Count);
    }

    public static TheoryData<string, string, string> BlankedSettings
    {
        get
        {
            var rows = new TheoryData<string, string, string>();
            foreach (var variable in AlertVariables)
            {
                rows.Add("alerts test", variable, "Nothing was sent.");
            }

            foreach (var variable in RecordsVariables)
            {
                rows.Add("records test", variable, "Nothing was signed or written.");
                rows.Add("audit-ship --once", variable, "Nothing was shipped.");
            }

            rows.Add("audit-ship --once", OffServerSettings.AuditLogFileVariable, "Nothing was shipped.");
            rows.Add("audit-ship --once", OffServerSettings.AuditShipStateVariable, "Nothing was shipped.");
            return rows;
        }
    }

    [Theory]
    [MemberData(nameof(BlankedSettings))]
    public async Task Command_with_one_setting_blank_prints_exactly_the_refusal_naming_it(string command, string variable, string consequence)
    {
        var environment = command == "alerts test" ? AlertEnvironment("https://alerts.invalid/hook") : RecordsEnvironment("https://objects.invalid");
        environment[variable] = string.Empty;

        var result = await CliProcess.RunCapturedAsync(environment, command.Split(' '));

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(OffServerSettings.Refusal([variable], consequence), result.StandardError.Trim());
        Assert.Empty(result.StandardOutput);
        Assert.Equal(0, _custodyRequests);
    }

    [Theory]
    [InlineData("/proc")]
    [InlineData("missing")]
    public async Task Audit_ship_refuses_a_state_directory_it_cant_write_before_shipping_anything(string directory)
    {
        var auditFile = Path.Combine(_directory, "audit.log");
        await File.WriteAllTextAsync(auditFile, "{\"type\":\"request\"}\n", Cancellation);
        var environment = RecordsEnvironment("https://objects.invalid");
        environment[OffServerSettings.AuditLogFileVariable] = auditFile;
        environment[OffServerSettings.AuditShipStateVariable] = Resolve(directory);

        var result = await CliProcess.RunCapturedAsync(environment, "audit-ship", "--once");

        Assert.Equal(1, result.ExitCode);
        Assert.Equal(OffServerSettings.Refusal([OffServerSettings.AuditShipStateVariable], "Nothing was shipped."), result.StandardError.Trim());
    }

    [Fact]
    public async Task Alerts_test_whose_token_file_turns_unusable_after_the_check_prints_the_token_line_not_the_address_line()
    {
        await using var sink = await AlertSinkFixture.StartAsync();
        var error = new StringWriter();

        var exit = await AlertsTestCommand.SendAsync(
            new WebhookAlertOptions { Url = sink.Url, TokenFile = TempFile("changeme") },
            new AlertDeployment("admin.gatekeep-admin.test"), ObjectLockFixture.Permitted(), TimeProvider.System, new StringWriter(), error, Cancellation);

        Assert.Equal(1, exit);
        Assert.Equal(AlertsTestCommand.RefusedToken, error.ToString().Trim());
        Assert.Empty(sink.Requests);
    }

    [Fact]
    public async Task Records_test_and_audit_ship_whose_credential_turns_unusable_print_the_credential_line()
    {
        var options = bucket.Options(secretAccessKeyFile: TempFile("sk with a space"));
        var recordsError = new StringWriter();
        var auditFile = TempFile("{\"type\":\"request\"}\n");
        var shipError = new StringWriter();

        var records = await RecordsTestCommand.WriteAsync(
            options, new SigningCustody(), ObjectLockFixture.Permitted(), TimeProvider.System, new StringWriter(), recordsError, Cancellation);
        var shipped = await AuditShipCommand.ShipAsync(
            options, auditFile, Directory.CreateDirectory(Path.Combine(_directory, "state-" + Guid.NewGuid().ToString("N"))).FullName,
            ObjectLockFixture.Permitted(), TimeProvider.System, new StringWriter(), shipError, once: true, AuditShipCommand.Interval, Cancellation);

        Assert.Equal(1, records);
        Assert.Equal(RecordsTestCommand.RefusedCredential, recordsError.ToString().Trim());
        Assert.Equal(1, shipped);
        Assert.Equal(AuditShipCommand.RefusedCredential, shipError.ToString().Trim());
    }

    private WebhookAlertOptions Webhook(AlertSinkFixture sink) =>
        new() { Url = sink.Url, TokenFile = TempFile("token-" + Guid.NewGuid().ToString("N")) };

    private Dictionary<string, string> AlertEnvironment(string url) => new()
    {
        [OffServerSettings.AlertUrlVariable] = url,
        [OffServerSettings.AlertTokenFileVariable] = TempFile("token-" + Guid.NewGuid().ToString("N") + "\n"),
        [OffServerSettings.AlertDeploymentVariable] = "admin.gatekeep-admin.test",
    };

    /// <summary>Valid bucket settings and, for records test, custody on a stand-in socket that signs anything.</summary>
    private Dictionary<string, string> RecordsEnvironment(string endpoint)
    {
        var socket = new FakeOpenBaoSocket
        {
            Respond = _ =>
            {
                Interlocked.Increment(ref _custodyRequests);
                return (200, """{"auth":{"client_token":"fake-token","lease_duration":900},"data":{"signature":"vault:v1:c2lnbmF0dXJl"}}""");
            },
        };
        _sockets.Add(socket);

        return new()
        {
            [OffServerSettings.RecordsEndpointVariable] = endpoint,
            [OffServerSettings.RecordsRegionVariable] = "us-east-1",
            [OffServerSettings.RecordsBucketVariable] = "gatekeep-records",
            [OffServerSettings.RecordsAccessKeyIdFileVariable] = TempFile("ak" + Guid.NewGuid().ToString("N")),
            [OffServerSettings.RecordsSecretAccessKeyFileVariable] = TempFile("sk" + Guid.NewGuid().ToString("N")),
            ["GATEKEEP_CUSTODY_SOCKET"] = socket.Path,
            ["GATEKEEP_CUSTODY_ROLE_ID_FILE"] = TempFile(Guid.NewGuid().ToString()),
            ["GATEKEEP_CUSTODY_SECRET_ID_FILE"] = TempFile(Guid.NewGuid().ToString()),
            [OffServerSettings.AuditLogFileVariable] = Path.Combine(_directory, "audit.log"),
            [OffServerSettings.AuditShipStateVariable] = _directory,
        };
    }

    /// <summary><c>file:x</c> is a file holding x, <c>missing</c> a file that doesn't exist, anything else the value itself.</summary>
    private string Resolve(string value) => value switch
    {
        "missing" => Path.Combine(_directory, "missing-" + Guid.NewGuid().ToString("N")),
        _ when value.StartsWith("file:", StringComparison.Ordinal) => TempFile(value["file:".Length..]),
        _ => value,
    };

    private string TempFile(string contents)
    {
        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        System.IO.File.WriteAllText(path, contents);
        return path;
    }
}
