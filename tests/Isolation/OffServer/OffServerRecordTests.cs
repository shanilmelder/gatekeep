using System.Text;
using System.Text.Json.Nodes;
using Gatekeep.Adapters.AlertChannel;
using Gatekeep.Kernel.Alerts;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Retention;
using Gatekeep.Adapters.ObjectLock;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30, with no container: a signed record's canonical bytes, that its signature covers
/// exactly them, its key, and the alert's shape.
/// </summary>
public sealed class OffServerRecordTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 6, 9, 30, 15, TimeSpan.FromHours(2));

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public void Canonical_JSON_sorts_members_by_UTF16_and_uses_minimal_escaping()
    {
        var node = new JsonObject
        {
            ["b"] = 2,
            ["a"] = new JsonArray("x", true, false, null, -9_007_199_254_740_991L),
            ["é"] = "€ \"q\" \\ \n\t\u0001",
            ["A"] = new JsonObject { ["z"] = null, ["y"] = "\U0001F600" },
        };

        Assert.Equal(
            "{\"A\":{\"y\":\"\U0001F600\",\"z\":null},\"a\":[\"x\",true,false,null,-9007199254740991],\"b\":2,\"é\":\"€ \\\"q\\\" \\\\ \\n\\t\\u0001\"}",
            CanonicalJson.Write(node));
    }

    [Theory]
    [InlineData(1.5)]
    [InlineData(9_007_199_254_740_993d)]
    public void Canonical_JSON_refuses_a_fraction_or_an_unsafe_integer(double value)
    {
        Assert.Throws<ArgumentException>(() => CanonicalJson.Write(new JsonObject { ["n"] = value }));
    }

    [Fact]
    public void Canonical_JSON_refuses_a_lone_surrogate()
    {
        Assert.Throws<ArgumentException>(() => CanonicalJson.Write(new JsonObject { ["s"] = "a\ud800b" }));
    }

    [Fact]
    public async Task Record_is_canonical_JSON_of_five_members_and_its_key_is_dated()
    {
        var custody = new SigningCustody();
        var store = new MemoryStore();
        var writer = new OffServerRecordWriter(custody, store, new SetTime(Now.AddTicks(1234567)));

        var record = await writer.WriteAsync("test", new JsonObject { ["purpose"] = "x", ["count"] = 3 }, Cancellation);

        var put = Assert.Single(store.Puts);
        Assert.Equal(record.Key, put.Key);
        Assert.Equal("application/json", put.ContentType);
        Assert.Equal($"records/test/2026/11/06/{record.Id:D}.json", record.Key);
        Assert.Equal(7, record.Id.Version);
        Assert.Equal(record.Content, put.Content);

        var signature = Convert.ToBase64String(record.Signature.Value);
        Assert.Equal(
            $$"""{"id":"{{record.Id:D}}","kind":"test","payload":{"count":3,"purpose":"x"},"signature":{"key":"dep-records","value":"{{signature}}","version":1},"writtenAt":"2026-11-06T07:30:15.123456Z"}""",
            Encoding.UTF8.GetString(put.Content));
    }

    [Fact]
    public async Task Signature_covers_the_canonical_bytes_of_the_other_four_members_with_dep_records()
    {
        var custody = new SigningCustody();
        var store = new MemoryStore();
        var writer = new OffServerRecordWriter(custody, store, new SetTime(Now));

        var record = await writer.WriteAsync("test", new JsonObject { ["purpose"] = "x" }, Cancellation);

        var (key, data) = Assert.Single(custody.Signed);
        Assert.Equal("dep-records", key.Value);
        Assert.Equal(
            $$"""{"id":"{{record.Id:D}}","kind":"test","payload":{"purpose":"x"},"writtenAt":"2026-11-06T07:30:15.000000Z"}""",
            Encoding.UTF8.GetString(data));
        Assert.Equal(OffServerRecords.SignedBytes("test", record.Id, record.WrittenAt, new JsonObject { ["purpose"] = "x" }), data);
        Assert.True(await OffServerRecords.VerifyAsync(custody, record.Content, Cancellation));
    }

    [Theory]
    [InlineData("\"purpose\":\"x\"", "\"purpose\":\"y\"")]
    [InlineData("\"kind\":\"test\"", "\"kind\":\"tess\"")]
    [InlineData("07:30:15.000000Z", "07:30:16.000000Z")]
    [InlineData("\"version\":1", "\"version\":2")]
    [InlineData("\"key\":\"dep-records\"", "\"key\":\"dep-payload\"")]
    [InlineData("{\"id\"", "{ \"id\"")]
    [InlineData("\"payload\":{\"purpose\":\"x\"}", "\"payload\":{\"purpose\":\"x\"},\"extra\":1")]
    public async Task Changed_record_or_second_spelling_fails_to_verify(string original, string replacement)
    {
        var custody = new SigningCustody();
        var store = new MemoryStore();
        var record = await new OffServerRecordWriter(custody, store, new SetTime(Now))
            .WriteAsync("test", new JsonObject { ["purpose"] = "x" }, Cancellation);
        var text = Encoding.UTF8.GetString(record.Content);
        Assert.Contains(original, text, StringComparison.Ordinal);

        var changed = Encoding.UTF8.GetBytes(text.Replace(original, replacement, StringComparison.Ordinal));

        Assert.False(await OffServerRecords.VerifyAsync(custody, changed, Cancellation));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Test")]
    [InlineData("records/test")]
    [InlineData("1test")]
    [InlineData("te-st")]
    public async Task Kind_that_isnt_one_lower_case_word_is_refused_before_anything_is_signed(string kind)
    {
        var custody = new SigningCustody();
        var store = new MemoryStore();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            new OffServerRecordWriter(custody, store, new SetTime(Now)).WriteAsync(kind, [], Cancellation));

        Assert.Empty(custody.Signed);
        Assert.Empty(store.Puts);
    }

    [Fact]
    public async Task Custody_failure_writes_nothing()
    {
        var custody = new SigningCustody { Fails = Gatekeep.Kernel.Secrets.KeyCustodyFailure.Refused };
        var store = new MemoryStore();

        await Assert.ThrowsAsync<Gatekeep.Kernel.Secrets.KeyCustodyException>(() =>
            new OffServerRecordWriter(custody, store, new SetTime(Now)).WriteAsync("test", [], Cancellation));

        Assert.Empty(store.Puts);
    }

    [Theory]
    [InlineData("records/test/2026/11/06/0190abcd.json", true)]
    [InlineData("openbao-audit/2026/11/06/x-00000000000000000000.jsonl", true)]
    [InlineData("/records/x", false)]
    [InlineData("records//x", false)]
    [InlineData("records/../x", false)]
    [InlineData("records/x?y", false)]
    [InlineData("records/x y", false)]
    [InlineData("", false)]
    public void Object_key_shape(string key, bool valid)
    {
        Assert.Equal(valid, OffServerObjectKey.IsValid(key));
    }

    [Fact]
    public void Retention_is_at_least_the_Log_period_rounded_up_to_the_second()
    {
        var at = new DateTimeOffset(2026, 11, 6, 7, 30, 15, TimeSpan.Zero).AddTicks(1);

        var until = S3ObjectLockStore.RetainUntil(at);

        Assert.True(until >= at.AddDays(RetentionPeriods.LogDays));
        Assert.Equal(new DateTimeOffset(2027, 2, 4, 7, 30, 16, TimeSpan.Zero), until);
        Assert.True(RetentionPeriods.LogDays >= 90);
    }

    [Fact]
    public void Alert_body_holds_only_the_listed_fields()
    {
        var alertId = Guid.CreateVersion7(Now);
        var tenantId = Guid.CreateVersion7();
        var eventId = Guid.CreateVersion7();
        var alert = new SecurityAlert(SecurityAlertCode.Test, alertId, Now, new AlertDeployment("admin.example.com"), tenantId, eventId);

        var body = JsonNode.Parse(WebhookAlertChannel.Body(alert))!.AsObject();

        Assert.Equal(["alertId", "code", "deployment", "eventId", "raisedAt", "summary", "tenantId"], body.Select(m => m.Key).Order(StringComparer.Ordinal));
        Assert.Equal(alertId.ToString("D"), (string?)body["alertId"]);
        Assert.Equal("operations.alert.test", (string?)body["code"]);
        Assert.Equal("admin.example.com", (string?)body["deployment"]);
        Assert.Equal("2026-11-06T07:30:15.000000Z", (string?)body["raisedAt"]);
        Assert.Equal(SecurityAlertCode.Test.Summary, (string?)body["summary"]);
        Assert.Equal(tenantId.ToString("D"), (string?)body["tenantId"]);
        Assert.Equal(eventId.ToString("D"), (string?)body["eventId"]);

        var bare = JsonNode.Parse(WebhookAlertChannel.Body(SecurityAlert.Raise(SecurityAlertCode.Test, new AlertDeployment("admin.example.com"), TimeProvider.System)))!.AsObject();
        Assert.Equal(["alertId", "code", "deployment", "raisedAt", "summary"], bare.Select(m => m.Key).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("admin.example.com", true)]
    [InlineData("admin.gatekeep-admin.localhost", true)]
    [InlineData("localhost", false)]
    [InlineData("Admin.example.com", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("https://admin.example.com", false)]
    [InlineData("admin.example.com/x", false)]
    [InlineData("-a.example.com", false)]
    [InlineData("", false)]
    public void Deployment_is_named_by_a_hostname(string name, bool valid)
    {
        Assert.Equal(valid, AlertDeployment.IsValid(name));
    }

    [Theory]
    [InlineData("Line one\nline two")]
    [InlineData("See https://example.com")]
    [InlineData("")]
    public void Alert_summary_is_one_line_of_fixed_text_with_no_address(string summary)
    {
        Assert.Throws<ArgumentException>(() => SecurityAlertCode.Define("operations.alert.test", summary));
    }

    [Fact]
    public void Alert_ID_is_a_UUIDv7()
    {
        Assert.Throws<ArgumentException>(() =>
            new SecurityAlert(SecurityAlertCode.Test, Guid.NewGuid(), Now, new AlertDeployment("admin.example.com")));
    }
}
