using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Gatekeep.Adapters.ObjectLock;

/// <summary>
/// AWS Signature Version 4 for one S3 request, header-signed, as the S3 API documents it. It
/// signs <c>host</c>, <c>content-md5</c>, <c>content-type</c> and every <c>x-amz-*</c> header the
/// request carries, over the SHA-256 of the exact body. The secret key is used only to derive the
/// signing key and never leaves this method.
/// </summary>
public static class SigV4
{
    public const string Algorithm = "AWS4-HMAC-SHA256";
    private const string Service = "s3";
    private const string Terminator = "aws4_request";

    /// <summary>
    /// Adds <c>x-amz-date</c>, <c>x-amz-content-sha256</c>, <c>Host</c> and <c>Authorization</c> to
    /// <paramref name="request"/>, whose URI path and query must already be in the encoded form
    /// <see cref="UriEncode"/> gives. Returns the canonical request it signed, which holds no secret.
    /// </summary>
    public static string Sign(
        HttpRequestMessage request,
        ReadOnlySpan<byte> body,
        string accessKeyId,
        string secretAccessKey,
        string region,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        var uri = request.RequestUri ?? throw new ArgumentException("The request has no URI.", nameof(request));

        var utc = now.UtcDateTime;
        var amzDate = utc.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var date = utc.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var payloadHash = Convert.ToHexStringLower(SHA256.HashData(body));
        // IdnHost drops an IPv6 literal's brackets, and a Host header without them is malformed.
        var hostName = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host : uri.IdnHost;
        var host = uri.IsDefaultPort ? hostName : $"{hostName}:{uri.Port.ToString(CultureInfo.InvariantCulture)}";

        request.Headers.Host = host;
        request.Headers.Remove("x-amz-date");
        request.Headers.Remove("x-amz-content-sha256");
        request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);
        request.Headers.TryAddWithoutValidation("x-amz-content-sha256", payloadHash);

        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal) { ["host"] = host };
        foreach (var (name, values) in request.Headers)
        {
            var lower = name.ToLowerInvariant();
            if (lower.StartsWith("x-amz-", StringComparison.Ordinal))
            {
                headers[lower] = string.Join(',', values.Select(v => v.Trim()));
            }
        }

        if (request.Content is { } content)
        {
            if (content.Headers.ContentType is { } type)
            {
                headers["content-type"] = type.ToString();
            }

            if (content.Headers.ContentMD5 is { } md5)
            {
                headers["content-md5"] = Convert.ToBase64String(md5);
            }
        }

        var signedHeaders = string.Join(';', headers.Keys);
        var canonicalRequest = string.Join(
            '\n',
            request.Method.Method,
            uri.AbsolutePath,
            CanonicalQuery(uri.Query),
            string.Concat(headers.Select(h => $"{h.Key}:{h.Value}\n")),
            signedHeaders,
            payloadHash);

        var scope = $"{date}/{region}/{Service}/{Terminator}";
        var stringToSign = string.Join(
            '\n',
            Algorithm,
            amzDate,
            scope,
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));

        var signingKey = SigningKey(secretAccessKey, date, region);
        var signature = Convert.ToHexStringLower(HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(stringToSign)));
        CryptographicOperations.ZeroMemory(signingKey);

        request.Headers.TryAddWithoutValidation(
            "Authorization",
            $"{Algorithm} Credential={accessKeyId}/{scope}, SignedHeaders={signedHeaders}, Signature={signature}");

        return canonicalRequest;
    }

    /// <summary>S3's URI encoding: unreserved characters stay, everything else is <c>%XX</c> in upper case. <c>/</c> stays in a path.</summary>
    public static string UriEncode(string value, bool path)
    {
        var builder = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            var c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~' || (path && c == '/'))
            {
                builder.Append(c);
            }
            else
            {
                builder.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    private static string CanonicalQuery(string query)
    {
        if (string.IsNullOrEmpty(query) || query == "?")
        {
            return string.Empty;
        }

        var pairs = query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p =>
            {
                var equals = p.IndexOf('=', StringComparison.Ordinal);
                return equals < 0 ? (Name: p, Value: string.Empty) : (Name: p[..equals], Value: p[(equals + 1)..]);
            })
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal);

        return string.Join('&', pairs.Select(p => $"{p.Name}={p.Value}"));
    }

    private static byte[] SigningKey(string secretAccessKey, string date, string region)
    {
        var secret = Encoding.UTF8.GetBytes("AWS4" + secretAccessKey);
        try
        {
            var dateKey = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(date));
            var regionKey = HMACSHA256.HashData(dateKey, Encoding.UTF8.GetBytes(region));
            var serviceKey = HMACSHA256.HashData(regionKey, Encoding.UTF8.GetBytes(Service));
            return HMACSHA256.HashData(serviceKey, Encoding.UTF8.GetBytes(Terminator));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
