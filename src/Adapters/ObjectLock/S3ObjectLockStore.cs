using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Gatekeep.Adapters.Egress;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Retention;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Adapters.ObjectLock;

/// <summary>
/// Where the bucket is and the files its write-only credential is read from, at each write.
/// The bucket is on a separate provider, with versioning and Object Lock (AD-17).
/// </summary>
public sealed record ObjectLockOptions
{
    private const int MinBucketLength = 3;
    private const int MaxBucketLength = 63;
    private const int MaxRegionLength = 32;

    /// <summary>The S3 API endpoint: absolute <c>https</c>, with nothing after the host and port (<see cref="TryParseEndpoint"/>).</summary>
    public required Uri Endpoint { get; init; }

    public required string Region { get; init; }

    public required string Bucket { get; init; }

    public required string AccessKeyIdFile { get; init; }

    public required string SecretAccessKeyFile { get; init; }

    /// <summary>How long one write may take, connecting included.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The endpoint, when <paramref name="text"/> is an absolute <c>https</c> URL with a host and no user info, path, query or fragment.</summary>
    public static Uri? TryParseEndpoint(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)
            || text.Contains('@', StringComparison.Ordinal)
            || !Uri.TryCreate(text.Trim(), UriKind.Absolute, out var endpoint)
            || endpoint.Scheme != Uri.UriSchemeHttps
            || endpoint.UserInfo.Length > 0
            || endpoint.AbsolutePath != "/"
            || endpoint.Query.Length > 0
            || endpoint.Fragment.Length > 0
            || endpoint.Host.Length == 0)
        {
            return null;
        }

        return endpoint;
    }

    /// <summary>A region name such as <c>eu-central-1</c>: lower-case letters, digits and hyphens.</summary>
    public static bool IsValidRegion(string? region) =>
        !string.IsNullOrEmpty(region)
        && region.Length <= MaxRegionLength
        && region[0] != '-'
        && region[^1] != '-'
        && region.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');

    /// <summary>
    /// The S3 bucket naming rules: 3 to 63 lower-case letters, digits, dots and hyphens, starting and
    /// ending with a letter or digit, no two dots together or a dot beside a hyphen, not formatted as
    /// an IPv4 address, and none of the reserved prefixes and suffixes.
    /// </summary>
    public static bool IsValidBucket(string? bucket)
    {
        if (string.IsNullOrEmpty(bucket)
            || bucket.Length is < MinBucketLength or > MaxBucketLength
            || !bucket.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '.' or '-')
            || !char.IsAsciiLetterOrDigit(bucket[0])
            || !char.IsAsciiLetterOrDigit(bucket[^1])
            || bucket.Contains("..", StringComparison.Ordinal)
            || bucket.Contains(".-", StringComparison.Ordinal)
            || bucket.Contains("-.", StringComparison.Ordinal)
            || IsDottedQuad(bucket))
        {
            return false;
        }

        string[] prefixes = ["xn--", "sthree-", "amzn-s3-demo-"];
        string[] suffixes = ["-s3alias", "--ol-s3", "--x-s3", "--table-s3", ".mrap"];
        return !prefixes.Any(p => bucket.StartsWith(p, StringComparison.Ordinal))
            && !suffixes.Any(s => bucket.EndsWith(s, StringComparison.Ordinal));
    }

    /// <summary>
    /// Four dot-separated groups of one to three digits, as S3 refuses: <c>IPAddress.TryParse</c>
    /// would also take a name such as <c>123</c> or <c>1.2.3</c>, which S3 allows.
    /// </summary>
    private static bool IsDottedQuad(string bucket)
    {
        var parts = bucket.Split('.');
        return parts.Length == 4 && parts.All(p => p.Length is >= 1 and <= 3 && p.All(char.IsAsciiDigit));
    }
}

/// <summary>
/// <see cref="IOffServerStore"/> as one SigV4-signed S3 <c>PUT</c>, path-style, over
/// <see cref="EgressHttp"/> (Story 1.30). Every object goes up with
/// <c>x-amz-object-lock-mode: COMPLIANCE</c>, <c>x-amz-object-lock-retain-until-date</c> at least
/// <see cref="RetentionPeriods.LogDays"/> days ahead, and <c>Content-MD5</c>. Only a 2xx answer
/// writes; anything else is <see cref="OffServerStoreFailure.Rejected"/>. The response body is
/// never read and no failure carries the address, the bucket, the credential or the answer.
/// </summary>
public sealed class S3ObjectLockStore : IOffServerStore, IDisposable
{
    public const string ComplianceMode = "COMPLIANCE";

    private readonly HttpClient _http;
    private readonly ObjectLockOptions _options;
    private readonly TimeProvider _time;

    /// <summary>Takes the handler from <see cref="EgressHttp.Create()"/>, and disposes it.</summary>
    public S3ObjectLockStore(HttpMessageHandler handler, ObjectLockOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(options.Endpoint);
        if (!ObjectLockOptions.IsValidBucket(options.Bucket) || !ObjectLockOptions.IsValidRegion(options.Region))
        {
            throw new ArgumentException("The bucket or region breaks the S3 naming rules.", nameof(options));
        }

        _options = options;
        _time = time;
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = options.Timeout };
    }

    /// <summary>The retain-until date for a write at <paramref name="now"/>: <see cref="RetentionPeriods.LogDays"/> days on, rounded up to the second.</summary>
    public static DateTimeOffset RetainUntil(DateTimeOffset now)
    {
        var until = now.ToUniversalTime().AddDays(RetentionPeriods.LogDays);
        var whole = new DateTimeOffset(until.UtcTicks - (until.UtcTicks % TimeSpan.TicksPerSecond), TimeSpan.Zero);
        return whole < until ? whole.AddSeconds(1) : whole;
    }

    public async Task PutAsync(string key, ReadOnlyMemory<byte> content, string contentType, CancellationToken cancellationToken)
    {
        if (!OffServerObjectKey.IsValid(key))
        {
            throw new ArgumentException("An object key is segments of letters, digits, '.', '_' and '-', joined by '/'.", nameof(key));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);

        var (accessKeyId, secretAccessKey) = ReadCredential();
        var body = content.ToArray();
        var now = _time.GetUtcNow();

        using var request = new HttpRequestMessage(HttpMethod.Put, ObjectUri(key))
        {
            Content = new ByteArrayContent(body),
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Content.Headers.ContentMD5 = MD5.HashData(body);
        request.Headers.TryAddWithoutValidation("x-amz-object-lock-mode", ComplianceMode);
        request.Headers.TryAddWithoutValidation(
            "x-amz-object-lock-retain-until-date",
            RetainUntil(now).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'.000Z'", CultureInfo.InvariantCulture));
        SigV4.Sign(request, body, accessKeyId, secretAccessKey, _options.Region, now);

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception e) when (EgressRefusedException.Find(e) is not null)
        {
            throw new OffServerStoreException(OffServerOperation.Put, OffServerStoreFailure.Refused, OffServerRefusal.Address);
        }
        catch (HttpRequestException)
        {
            throw new OffServerStoreException(OffServerOperation.Put, OffServerStoreFailure.Unavailable);
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // HttpClient's own timeout, not the caller's cancellation.
            throw new OffServerStoreException(OffServerOperation.Put, OffServerStoreFailure.Unavailable);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new OffServerStoreException(OffServerOperation.Put, OffServerStoreFailure.Rejected);
            }
        }
    }

    public void Dispose() => _http.Dispose();

    /// <summary>Path-style: <c>{endpoint}/{bucket}/{key}</c>, so the bucket name needs no DNS record of its own.</summary>
    private Uri ObjectUri(string key, string? query = null) =>
        new(_options.Endpoint, $"/{_options.Bucket}/{SigV4.UriEncode(key, path: true)}{(query is null ? string.Empty : "?" + query)}");

    /// <summary>The credential, read at each write so a replaced file takes effect. Its values are never kept or shown.</summary>
    private (string AccessKeyId, string SecretAccessKey) ReadCredential()
    {
        var accessKeyId = Read(_options.AccessKeyIdFile);
        var secretAccessKey = Read(_options.SecretAccessKeyFile);
        return (accessKeyId, secretAccessKey);

        static string Read(string path)
        {
            string value;
            try
            {
                value = File.ReadAllText(path).Trim();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                throw new OffServerStoreException(OffServerOperation.Put, OffServerStoreFailure.Refused, OffServerRefusal.CredentialFile);
            }

            if (SecretDefaults.IsUnsafeCredential(value))
            {
                throw new OffServerStoreException(OffServerOperation.Put, OffServerStoreFailure.Refused, OffServerRefusal.CredentialFile);
            }

            return value;
        }
    }
}
