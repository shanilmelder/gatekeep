using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.ObjectLock;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Retention;
using Xunit;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// Story 1.30: the Object Lock adapter against a locked, versioned bucket. Every object goes up in
/// compliance mode for at least the Log period, with Content-MD5; the server's credential can't
/// delete it, delete its version, shorten its retention, bypass it or read it; a second write keeps
/// the first version locked; and no failure carries the address, the bucket or the credential.
/// </summary>
public sealed class ObjectLockStoreTests(ObjectLockFixture bucket) : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-objects-").FullName;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public async Task Object_is_written_in_compliance_mode_for_at_least_the_Log_period()
    {
        var key = Key();
        var before = DateTimeOffset.UtcNow;
        using var store = bucket.Store();

        await store.PutAsync(key, "{\"a\":1}"u8.ToArray(), "application/json", Cancellation);

        var version = Assert.Single(await bucket.VersionsAsync(key));
        var locked = await bucket.LockAsync(version);
        Assert.Equal(HttpStatusCode.OK, locked.Status);
        Assert.Equal(S3ObjectLockStore.ComplianceMode, locked.Mode);
        Assert.True(locked.RetainUntil >= before.AddDays(RetentionPeriods.LogDays), $"Retained until {locked.RetainUntil:O}.");
        Assert.Equal("application/json", locked.ContentType);
        Assert.Equal("{\"a\":1}", await bucket.ReadAsync(version));
    }

    [Fact]
    public async Task Signed_record_written_through_the_writer_lands_at_its_key_and_verifies()
    {
        var custody = new SigningCustody();
        using var store = bucket.Store();

        var record = await new OffServerRecordWriter(custody, store, TimeProvider.System)
            .WriteAsync("test", new JsonObject { ["purpose"] = "store test" }, Cancellation);

        var version = Assert.Single(await bucket.VersionsAsync(record.Key));
        Assert.Matches(@"^records/test/\d{4}/\d{2}/\d{2}/[0-9a-f-]{36}\.json$", version.Key);
        var stored = Encoding.UTF8.GetBytes(await bucket.ReadAsync(version));
        Assert.Equal(record.Content, stored);
        Assert.True(await OffServerRecords.VerifyAsync(custody, stored, Cancellation));
    }

    [Fact]
    public async Task Server_credential_cant_delete_shorten_bypass_or_read_and_the_version_stays()
    {
        var key = Key();
        using var store = bucket.Store();
        await store.PutAsync(key, "kept"u8.ToArray(), "text/plain", Cancellation);
        var version = Assert.Single(await bucket.VersionsAsync(key));
        var path = $"/{ObjectLockFixture.Bucket}/{SigV4.UriEncode(key, path: true)}";
        var shorter = Retention("COMPLIANCE", DateTimeOffset.UtcNow.AddDays(1));
        var governance = Retention("GOVERNANCE", DateTimeOffset.UtcNow.AddDays(1));

        var attempts = new (string Name, HttpMethod Method, string PathAndQuery, byte[]? Body, Dictionary<string, string>? Headers)[]
        {
            ("delete", HttpMethod.Delete, path, null, null),
            ("delete version", HttpMethod.Delete, ObjectLockFixture.VersionPath(version), null, null),
            ("shorter retention", HttpMethod.Put, ObjectLockFixture.VersionPath(version) + "&retention", shorter, null),
            ("governance bypass", HttpMethod.Put, ObjectLockFixture.VersionPath(version) + "&retention", governance,
                new Dictionary<string, string> { ["x-amz-bypass-governance-retention"] = "true" }),
            ("delete version with bypass", HttpMethod.Delete, ObjectLockFixture.VersionPath(version), null,
                new Dictionary<string, string> { ["x-amz-bypass-governance-retention"] = "true" }),
            ("read", HttpMethod.Get, path, null, null),
            ("read version", HttpMethod.Get, ObjectLockFixture.VersionPath(version), null, null),
            ("list", HttpMethod.Get, $"/{ObjectLockFixture.Bucket}?versions", null, null),
        };

        // What the policy doesn't grant at all is denied outright; a retention change, which the
        // policy grants for the PUT's sake, is refused by the compliance lock instead.
        string[] denied = ["delete", "delete version", "delete version with bypass", "read", "read version", "list"];
        foreach (var (name, method, pathAndQuery, body, headers) in attempts)
        {
            var (status, answer, response) = await bucket.SendAsync(method, pathAndQuery, asRoot: false, body, headers);
            response.Dispose();
            if (denied.Contains(name))
            {
                Assert.True(status == HttpStatusCode.Forbidden, $"The server credential's {name} was answered {(int)status}.");
                Assert.True(answer.Contains("<Code>AccessDenied</Code>", StringComparison.Ordinal), $"The server credential's {name} was refused with: {answer}");
            }
            else
            {
                Assert.True((int)status >= 400, $"The server credential's {name} was answered {(int)status}.");
            }
        }

        Assert.Equal([version], await bucket.VersionsAsync(key));
        var locked = await bucket.LockAsync(version);
        Assert.Equal(S3ObjectLockStore.ComplianceMode, locked.Mode);
        Assert.True(locked.RetainUntil >= DateTimeOffset.UtcNow.AddDays(RetentionPeriods.LogDays - 1));
        Assert.Equal("kept", await bucket.ReadAsync(version));

        // Not even the root user removes a version in compliance mode.
        var (rootStatus, _, rootResponse) = await bucket.SendAsync(
            HttpMethod.Delete, ObjectLockFixture.VersionPath(version), asRoot: true, headers: new Dictionary<string, string> { ["x-amz-bypass-governance-retention"] = "true" });
        rootResponse.Dispose();
        Assert.True((int)rootStatus >= 400, $"Root deleted a locked version: {(int)rootStatus}.");
    }

    [Fact]
    public async Task Second_write_to_the_same_key_adds_a_version_and_the_first_stays_locked()
    {
        var key = Key();
        using var store = bucket.Store();

        await store.PutAsync(key, "first"u8.ToArray(), "text/plain", Cancellation);
        var first = Assert.Single(await bucket.VersionsAsync(key));
        await store.PutAsync(key, "second"u8.ToArray(), "text/plain", Cancellation);

        var versions = await bucket.VersionsAsync(key);
        Assert.Equal(2, versions.Count);
        Assert.Contains(first, versions);
        Assert.Equal("first", await bucket.ReadAsync(first));
        Assert.Equal(S3ObjectLockStore.ComplianceMode, (await bucket.LockAsync(first)).Mode);
    }

    [Fact]
    public async Task Wrong_credential_is_Rejected_with_nothing_of_the_answer_in_the_failure()
    {
        var wrong = TempFile(Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(20)));
        using var store = new S3ObjectLockStore(ObjectLockFixture.Permitted(), bucket.Options(secretAccessKeyFile: wrong), TimeProvider.System);

        var failure = await Assert.ThrowsAsync<OffServerStoreException>(() =>
            store.PutAsync(Key(), "x"u8.ToArray(), "text/plain", Cancellation));

        Assert.Equal(OffServerStoreFailure.Rejected, failure.Failure);
        Assert.Equal(OffServerOperation.Put, failure.Operation);
        AssertLeaksNothing(failure);
    }

    [Fact]
    public async Task Bucket_nobody_listens_on_is_Unavailable()
    {
        var closed = new Uri($"http://127.0.0.1:{Hosting.HostProcess.FreePort()}/");
        using var store = new S3ObjectLockStore(ObjectLockFixture.Permitted(), bucket.Options(endpoint: closed), TimeProvider.System);

        var failure = await Assert.ThrowsAsync<OffServerStoreException>(() =>
            store.PutAsync(Key(), "x"u8.ToArray(), "text/plain", Cancellation));

        Assert.Equal(OffServerStoreFailure.Unavailable, failure.Failure);
        AssertLeaksNothing(failure);
    }

    [Fact]
    public async Task Bucket_on_a_private_address_is_Refused_through_the_real_EgressHttp()
    {
        var before = await bucket.VersionsAsync("records/");
        // The bucket is up there: only the egress rule stops the write.
        var https = new UriBuilder(bucket.Endpoint) { Scheme = Uri.UriSchemeHttps }.Uri;
        using var store = new S3ObjectLockStore(EgressHttp.Create(), bucket.Options(endpoint: https), TimeProvider.System);

        var failure = await Assert.ThrowsAsync<OffServerStoreException>(() =>
            store.PutAsync("records/refused/x.json", "x"u8.ToArray(), "application/json", Cancellation));

        Assert.Equal(OffServerStoreFailure.Refused, failure.Failure);
        Assert.Equal(OffServerRefusal.Address, failure.Refusal);
        Assert.Empty(await bucket.VersionsAsync("records/refused/"));
        Assert.Equal(before.Count, (await bucket.VersionsAsync("records/")).Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("changeme")]
    [InlineData("gk ab12cd34")]
    [InlineData("gk\u0007ab12cd34")]
    [InlineData("gk\u00e9ab12cd34")]
    public async Task Empty_default_or_non_ASCII_credential_file_is_Refused_and_nothing_is_sent(string value)
    {
        var key = Key();
        using var store = new S3ObjectLockStore(ObjectLockFixture.Permitted(), bucket.Options(accessKeyIdFile: TempFile(value)), TimeProvider.System);

        var failure = await Assert.ThrowsAsync<OffServerStoreException>(() => store.PutAsync(key, "x"u8.ToArray(), "text/plain", Cancellation));

        Assert.Equal(OffServerStoreFailure.Refused, failure.Failure);
        Assert.Equal(OffServerRefusal.CredentialFile, failure.Refusal);
        Assert.Empty(await bucket.VersionsAsync(key));
    }

    [Theory]
    [InlineData("gatekeep-records", true)]
    [InlineData("gatekeep.records.1", true)]
    [InlineData("ab", false)]
    [InlineData("Gatekeep", false)]
    [InlineData("gatekeep_records", false)]
    [InlineData("-gatekeep", false)]
    [InlineData("gatekeep..records", false)]
    [InlineData("gatekeep.-records", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("999.1.1.1", false)]
    [InlineData("123", true)]
    [InlineData("1.2.3", true)]
    [InlineData("1.2.3.4.5", true)]
    [InlineData("10.0.0.1a", true)]
    [InlineData("xn--gatekeep", false)]
    [InlineData("gatekeep-s3alias", false)]
    public void Bucket_name_follows_the_S3_rules(string name, bool valid)
    {
        Assert.Equal(valid, ObjectLockOptions.IsValidBucket(name));
    }

    [Theory]
    [InlineData("https://s3.eu-central-1.example.com", true)]
    [InlineData("https://s3.example.com:9000/", true)]
    [InlineData("http://s3.example.com", false)]
    [InlineData("https://key:secret@s3.example.com", false)]
    [InlineData("https://s3.example.com/bucket", false)]
    [InlineData("https://s3.example.com/?x=1", false)]
    [InlineData("s3.example.com", false)]
    public void Endpoint_must_be_absolute_https_with_nothing_after_the_port(string endpoint, bool accepted)
    {
        Assert.Equal(accepted, ObjectLockOptions.TryParseEndpoint(endpoint) is not null);
    }

    [Fact]
    public async Task Put_carries_the_compliance_mode_a_90_day_retain_until_and_a_correct_Content_MD5()
    {
        var now = new DateTimeOffset(2026, 11, 6, 12, 30, 15, 250, TimeSpan.Zero);
        var handler = new CapturingHandler();
        var body = "{\"a\":1}"u8.ToArray();
        using (var store = new S3ObjectLockStore(handler, bucket.Options(endpoint: new Uri("https://s3.example.com")), new SetTime(now)))
        {
            await store.PutAsync("records/test/x.json", body, "application/json", Cancellation);
        }

        var (request, headers, sent) = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Put, request.Method);
        Assert.Equal($"/{ObjectLockFixture.Bucket}/records/test/x.json", request.RequestUri!.AbsolutePath);
        Assert.Equal(body, sent);
        Assert.Equal("COMPLIANCE", headers["x-amz-object-lock-mode"]);
        var until = DateTimeOffset.Parse(headers["x-amz-object-lock-retain-until-date"], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        Assert.True(until >= now.AddDays(RetentionPeriods.LogDays), $"Retained until {until:O}.");
        Assert.True(until < now.AddDays(RetentionPeriods.LogDays).AddSeconds(2), $"Retained until {until:O}.");
        Assert.Equal(Convert.ToBase64String(System.Security.Cryptography.MD5.HashData(body)), headers["content-md5"]);
        // The lock headers are signed, so nothing on the way can strip them.
        Assert.Matches(@"SignedHeaders=[^,]*\bcontent-md5\b[^,]*\bx-amz-object-lock-mode;x-amz-object-lock-retain-until-date\b", headers["authorization"]);
    }

    [Fact]
    public async Task Bucket_answering_500_is_Rejected_after_exactly_one_request()
    {
        var handler = new CapturingHandler(HttpStatusCode.InternalServerError);
        using var store = new S3ObjectLockStore(handler, bucket.Options(endpoint: new Uri("https://s3.example.com")), TimeProvider.System);

        var failure = await Assert.ThrowsAsync<OffServerStoreException>(() =>
            store.PutAsync(Key(), "x"u8.ToArray(), "text/plain", Cancellation));

        Assert.Equal(OffServerStoreFailure.Rejected, failure.Failure);
        Assert.Null(failure.Refusal);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public void Signing_for_an_IPv6_endpoint_keeps_the_brackets_in_the_Host_header_and_the_canonical_request()
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, new Uri("https://[2001:db8::1]:9000/gatekeep-records/records/x.json"))
        {
            Content = new ByteArrayContent("x"u8.ToArray()),
        };

        var canonical = SigV4.Sign(request, "x"u8, "AKIDEXAMPLE", "secret-example-key", "us-east-1", DateTimeOffset.UtcNow);

        Assert.Equal("[2001:db8::1]:9000", request.Headers.Host);
        Assert.Contains("\nhost:[2001:db8::1]:9000\n", canonical, StringComparison.Ordinal);
        Assert.StartsWith("PUT\n/gatekeep-records/records/x.json\n", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-example-key", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Server_credential_writing_in_governance_mode_still_cant_remove_what_it_wrote()
    {
        // An intruder with the server's credential could PUT with a weaker lock than the adapter's.
        var key = Key();
        var path = $"/{ObjectLockFixture.Bucket}/{SigV4.UriEncode(key, path: true)}";
        var (status, _, put) = await bucket.SendAsync(
            HttpMethod.Put, path, asRoot: false, "weak"u8.ToArray(), new Dictionary<string, string>
            {
                ["x-amz-object-lock-mode"] = "GOVERNANCE",
                ["x-amz-object-lock-retain-until-date"] = DateTimeOffset.UtcNow.AddMinutes(1).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'.000Z'", CultureInfo.InvariantCulture),
            });
        put.Dispose();

        // The bucket takes it, since the policy grants the PUT and its retention...
        Assert.Equal(HttpStatusCode.OK, status);
        var version = Assert.Single(await bucket.VersionsAsync(key));
        Assert.Equal("GOVERNANCE", (await bucket.LockAsync(version)).Mode);

        // ...but the same credential can't take it away again, governance bypass or not.
        foreach (var headers in new Dictionary<string, string>?[] { null, new() { ["x-amz-bypass-governance-retention"] = "true" } })
        {
            var (deleted, _, response) = await bucket.SendAsync(HttpMethod.Delete, ObjectLockFixture.VersionPath(version), asRoot: false, headers: headers);
            response.Dispose();
            Assert.Equal(HttpStatusCode.Forbidden, deleted);
        }

        Assert.Equal([version], await bucket.VersionsAsync(key));
        Assert.Equal("weak", await bucket.ReadAsync(version));
    }

    private static string Key() => $"tests/store/{Guid.CreateVersion7():D}.json";

    private static byte[] Retention(string mode, DateTimeOffset until) => Encoding.UTF8.GetBytes(
        $"<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>{mode}</Mode>"
        + $"<RetainUntilDate>{until.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)}</RetainUntilDate></Retention>");

    private string TempFile(string contents)
    {
        var path = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        System.IO.File.WriteAllText(path, contents);
        return path;
    }

    private void AssertLeaksNothing(Exception failure)
    {
        var text = failure.ToString();
        Assert.Null(failure.InnerException);
        Assert.DoesNotContain(bucket.SecretAccessKey, text, StringComparison.Ordinal);
        Assert.DoesNotContain(bucket.AccessKeyId, text, StringComparison.Ordinal);
        Assert.DoesNotContain(ObjectLockFixture.Bucket, text, StringComparison.Ordinal);
        Assert.DoesNotContain("127.0.0.1", text, StringComparison.Ordinal);
        Assert.DoesNotContain(bucket.Endpoint.Host, text, StringComparison.Ordinal);
    }
}
