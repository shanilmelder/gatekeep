using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using Gatekeep.Adapters.Egress;
using Gatekeep.Adapters.ObjectLock;
using Xunit;

[assembly: AssemblyFixture(typeof(Gatekeep.Tests.Isolation.OffServer.ObjectLockFixture))]

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>One object version as the bucket lists it.</summary>
public sealed record ObjectVersion(string Key, string VersionId);

/// <summary>What a HEAD of one version says about its lock.</summary>
public sealed record ObjectLock(HttpStatusCode Status, string? Mode, DateTimeOffset? RetainUntil, string? ContentType);

/// <summary>
/// Story 1.30: an S3-API bucket on a separate provider, as one MinIO container for the run. Its bucket
/// is versioned and locked. Its default retention is deliberately weaker than what the adapter asks
/// for, one day in governance mode, so a compliance lock or a 90-day date on an object can only have
/// come from the headers the adapter sent, never from the bucket filling them in. Its server
/// user, made through <c>mc</c>, may only <c>PutObject</c> and <c>PutObjectRetention</c>: the second
/// is what S3 and MinIO require of a <c>PUT</c> that carries Object Lock headers, and compliance mode
/// keeps it from shortening anything. Every credential is fresh and random for the run.
/// </summary>
/// <remarks>
/// MinIO's own <c>minio/minio</c> images are no longer pullable from Docker Hub, so this is Bitnami's
/// legacy build of MinIO <c>RELEASE.2025-07-23T15-54-02Z</c>, which carries <c>mc</c> too, pinned by
/// digest. The fixture runs the <c>minio</c> binary itself, not Bitnami's scripts.
/// </remarks>
public sealed class ObjectLockFixture : IAsyncLifetime
{
    public const string Image =
        "bitnamilegacy/minio:2025.7.23@sha256:8935e75fa5d11295c17171e4aa49efe390a1193cd7f12e4d21b92af9ffef09d7";

    public const string Bucket = "gatekeep-records";
    public const string Region = "us-east-1";

    private const int Port = 9000;
    private const string PolicyName = "gatekeep-put-only";
    private const string PolicyFile = "/tmp/gatekeep-put-only.json";

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-bucket-").FullName;

    private IContainer? _container;

    public string RootUser { get; } = "root" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));

    public string RootPassword { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(20));

    /// <summary>The server's write-only credential, as the Operator would hand it to the stack.</summary>
    public string AccessKeyId { get; } = "gk" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(9));

    public string SecretAccessKey { get; } = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(20));

    /// <summary>The S3 API, over plain HTTP at the mapped address: only EgressHttp's test permit reaches it.</summary>
    public Uri Endpoint { get; private set; } = null!;

    public string AccessKeyIdFile => Path.Combine(_directory, "access-key-id");

    public string SecretAccessKeyFile => Path.Combine(_directory, "secret-access-key");

    public IContainer Container => _container ?? throw new InvalidOperationException("Not started.");

    /// <summary>The handler every adapter here uses: EgressHttp, with the private-address and plain-HTTP refusals relaxed.</summary>
    public static HttpMessageHandler Permitted() => EgressHttp.Create(new EgressPermit(PrivateAddresses: true, PlainHttp: true));

    public async ValueTask InitializeAsync()
    {
        _container = new ContainerBuilder(Image)
            .WithEntrypoint("minio")
            .WithCommand("server", "/tmp/data", "--address", $":{Port}", "--console-address", ":9001")
            .WithEnvironment("MINIO_ROOT_USER", RootUser)
            .WithEnvironment("MINIO_ROOT_PASSWORD", RootPassword)
            .WithEnvironment("MC_CONFIG_DIR", "/tmp/mc")
            .WithEnvironment("MC_HOST_local", $"http://{RootUser}:{RootPassword}@127.0.0.1:{Port}")
            .WithPortBinding(Port, assignRandomHostPort: true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilHttpRequestIsSucceeded(r => r.ForPort(Port).ForPath("/minio/health/live")))
            .Build();
        await _container.StartAsync();

        Endpoint = new UriBuilder(Uri.UriSchemeHttp, _container.Hostname, _container.GetMappedPublicPort(Port)).Uri;

        var policy = $$"""
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectRetention"],"Resource":["arn:aws:s3:::{{Bucket}}/*"]}]}
            """;
        await _container.CopyAsync(Encoding.UTF8.GetBytes(policy), PolicyFile);

        await McAsync("mb", "--with-lock", $"local/{Bucket}");
        await McAsync("retention", "set", "--default", "GOVERNANCE", "1d", $"local/{Bucket}");
        await McAsync("admin", "policy", "create", "local", PolicyName, PolicyFile);
        await McAsync("admin", "user", "add", "local", AccessKeyId, SecretAccessKey);
        await McAsync("admin", "policy", "attach", "local", PolicyName, "--user", AccessKeyId);

        await File.WriteAllTextAsync(AccessKeyIdFile, AccessKeyId + "\n");
        await File.WriteAllTextAsync(SecretAccessKeyFile, SecretAccessKey + "\n");
    }

    public async ValueTask DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }

        Directory.Delete(_directory, recursive: true);
    }

    /// <summary>The adapter's options for the server credential, at the mapped address.</summary>
    public ObjectLockOptions Options(string? accessKeyIdFile = null, string? secretAccessKeyFile = null, Uri? endpoint = null) => new()
    {
        Endpoint = endpoint ?? Endpoint,
        Region = Region,
        Bucket = Bucket,
        AccessKeyIdFile = accessKeyIdFile ?? AccessKeyIdFile,
        SecretAccessKeyFile = secretAccessKeyFile ?? SecretAccessKeyFile,
    };

    public S3ObjectLockStore Store(TimeProvider? time = null) => new(Permitted(), Options(), time ?? TimeProvider.System);

    /// <summary>One raw request, signed for the root user or the server credential, to show what each may do.</summary>
    public async Task<(HttpStatusCode Status, string Body, HttpResponseMessage Response)> SendAsync(
        HttpMethod method,
        string pathAndQuery,
        bool asRoot,
        byte[]? body = null,
        IReadOnlyDictionary<string, string>? headers = null)
    {
        using var http = new HttpClient(Permitted());
        var request = new HttpRequestMessage(method, new Uri(Endpoint, pathAndQuery));
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentMD5 = MD5.HashData(body);
        }

        foreach (var (name, value) in headers ?? new Dictionary<string, string>())
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        SigV4.Sign(
            request,
            body ?? [],
            asRoot ? RootUser : AccessKeyId,
            asRoot ? RootPassword : SecretAccessKey,
            Region,
            DateTimeOffset.UtcNow);

        var response = await http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, text, response);
    }

    /// <summary>Every version under <paramref name="prefix"/>, newest first per key, read as root.</summary>
    public async Task<IReadOnlyList<ObjectVersion>> VersionsAsync(string prefix)
    {
        var (status, body, _) = await SendAsync(
            HttpMethod.Get, $"/{Bucket}?prefix={SigV4.UriEncode(prefix, path: false)}&versions", asRoot: true);
        if (status != HttpStatusCode.OK)
        {
            throw new InvalidOperationException($"Listing versions failed with {(int)status}.");
        }

        var document = XDocument.Parse(body);
        XNamespace s3 = "http://s3.amazonaws.com/doc/2006-03-01/";
        return [.. document.Root!.Elements(s3 + "Version")
            .Select(v => new ObjectVersion(v.Element(s3 + "Key")!.Value, v.Element(s3 + "VersionId")!.Value))];
    }

    /// <summary>One version's content, read as root.</summary>
    public async Task<string> ReadAsync(ObjectVersion version)
    {
        var (status, body, _) = await SendAsync(HttpMethod.Get, VersionPath(version), asRoot: true);
        return status == HttpStatusCode.OK ? body : throw new InvalidOperationException($"Reading failed with {(int)status}.");
    }

    /// <summary>One version's lock and type, from a HEAD as root.</summary>
    public async Task<ObjectLock> LockAsync(ObjectVersion version)
    {
        var (status, _, response) = await SendAsync(HttpMethod.Head, VersionPath(version), asRoot: true);
        using (response)
        {
            string? Header(string name) => response.Headers.TryGetValues(name, out var values) ? values.Single() : null;
            var until = Header("x-amz-object-lock-retain-until-date");
            return new ObjectLock(
                status,
                Header("x-amz-object-lock-mode"),
                until is null ? null : DateTimeOffset.Parse(until, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal),
                response.Content.Headers.ContentType?.MediaType);
        }
    }

    /// <summary>
    /// Everything under <paramref name="prefix"/> as one text per version, with its lock, and then
    /// every header a HEAD of it answers, user metadata included, for the canary scan.
    /// </summary>
    public async Task<IReadOnlyList<(string Name, string Text)>> DumpAsync(string prefix)
    {
        var dumped = new List<(string, string)>();
        foreach (var version in await VersionsAsync(prefix))
        {
            var lockState = await LockAsync(version);
            dumped.Add(($"bucket object {version.Key}", await ReadAsync(version)));
            dumped.Add(($"bucket metadata {version.Key}", $"{lockState.Mode} {lockState.RetainUntil:O} {lockState.ContentType}\n{await HeadersAsync(version)}"));
        }

        return dumped;
    }

    /// <summary>Every response and content header a HEAD of one version answers, one per line, as root.</summary>
    public async Task<string> HeadersAsync(ObjectVersion version)
    {
        var (_, _, response) = await SendAsync(HttpMethod.Head, VersionPath(version), asRoot: true);
        using (response)
        {
            return string.Join('\n', response.Headers.Concat(response.Content.Headers).Select(h => $"{h.Key}: {string.Join(',', h.Value)}"));
        }
    }

    public static string VersionPath(ObjectVersion version) =>
        $"/{Bucket}/{SigV4.UriEncode(version.Key, path: true)}?versionId={SigV4.UriEncode(version.VersionId, path: false)}";

    private async Task McAsync(params string[] arguments)
    {
        var result = await Container.ExecAsync(["mc", .. arguments]);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"mc {string.Join(' ', arguments.Take(3))} failed: {result.Stderr}{result.Stdout}");
        }
    }
}
