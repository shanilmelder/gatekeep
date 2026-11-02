using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Adapters.OpenBao;

/// <summary>
/// <see cref="IKeyCustody"/> over OpenBao Transit (AD-10). It logs in with this host's
/// AppRole, reuses the token until three quarters of its lease have passed, and on a
/// refusal with a reused token logs in once more and retries once, because an expired
/// token and a forbidden path both answer 403. Errors never carry OpenBao's response text.
/// </summary>
public sealed class OpenBaoKeyCustody : IKeyCustody, IDisposable
{
    private const string Mount = "transit";
    private const string TokenHeader = "X-Vault-Token";
    private const string SocketBaseAddress = "http://openbao/";
    private const string DeploymentAssociatedData = "deployment";
    private const string HashAlgorithm = "sha2-256";
    private const string SignatureAlgorithm = "pkcs1v15";
    private const int DataKeyBits = 256;
    private const int HmacKeySize = 32;

    private readonly HttpClient _http;
    private readonly OpenBaoOptions _options;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _loginLock = new(1, 1);

    private LoginToken? _token;

    public OpenBaoKeyCustody(OpenBaoOptions options, TimeProvider time)
        : this(CreateHandler(options), options, time)
    {
    }

    /// <summary>Takes the handler from <see cref="CreateHandler"/>, which a test may wrap.</summary>
    public OpenBaoKeyCustody(HttpMessageHandler handler, OpenBaoOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(time);
        options.Validate();

        _options = options;
        _time = time;
        _http = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = options.SocketPath is null ? WithTrailingSlash(options.Address!) : new Uri(SocketBaseAddress),
            Timeout = options.Timeout,
        };
    }

    /// <summary>A handler that reaches OpenBao over its unix socket, or over HTTP when only an address is set.</summary>
    public static SocketsHttpHandler CreateHandler(OpenBaoOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };

        if (options.SocketPath is { } socketPath)
        {
            handler.ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            };
        }

        return handler;
    }

    public async Task<IReadOnlyList<KeyPublicVersion>> CreateKeyAsync(KeyName key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var body = key.Kind switch
        {
            KeyKind.Signing => new JsonObject { ["type"] = "rsa-3072" },
            KeyKind.Aead => new JsonObject { ["type"] = "aes256-gcm96" },
            KeyKind.Hmac => new JsonObject { ["type"] = "hmac", ["key_size"] = HmacKeySize },
            _ => throw new ArgumentOutOfRangeException(nameof(key), $"Key {key} has an unknown kind."),
        };

        var data = await SendAsync(key, KeyOperation.Create, HttpMethod.Post, $"keys/{key}", body, cancellationToken);

        return key.Kind == KeyKind.Signing ? PublicKeys(key, KeyOperation.Create, data) : [];
    }

    public async Task<KeySignature> SignAsync(KeyName key, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Signing);

        var body = new JsonObject
        {
            ["input"] = Convert.ToBase64String(data.Span),
            ["hash_algorithm"] = HashAlgorithm,
            ["signature_algorithm"] = SignatureAlgorithm,
        };

        var response = await SendAsync(key, KeyOperation.Sign, HttpMethod.Post, $"sign/{key}", body, cancellationToken);
        var (version, value) = ParseVersioned(key, KeyOperation.Sign, StringField(key, KeyOperation.Sign, response, "signature"));

        return new KeySignature(version, value);
    }

    public async Task<bool> VerifyAsync(
        KeyName key,
        ReadOnlyMemory<byte> data,
        KeySignature signature,
        CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Signing);
        ArgumentNullException.ThrowIfNull(signature);

        var body = new JsonObject
        {
            ["input"] = Convert.ToBase64String(data.Span),
            ["signature"] = $"vault:v{signature.KeyVersion}:{Convert.ToBase64String(signature.Value)}",
            ["hash_algorithm"] = HashAlgorithm,
            ["signature_algorithm"] = SignatureAlgorithm,
        };

        var response = await SendAsync(key, KeyOperation.Verify, HttpMethod.Post, $"verify/{key}", body, cancellationToken);

        return response is { ValueKind: JsonValueKind.Object } d
            && d.TryGetProperty("valid", out var valid)
            && valid.ValueKind == JsonValueKind.True;
    }

    public async Task<KeyCiphertext> EncryptAsync(
        KeyName key,
        Guid? tenantId,
        Secret<byte[]> plaintext,
        CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Aead);
        ArgumentNullException.ThrowIfNull(plaintext);

        var body = new JsonObject
        {
            ["plaintext"] = plaintext.Use(Convert.ToBase64String),
            ["associated_data"] = AssociatedData(key, tenantId),
        };

        var response = await SendAsync(key, KeyOperation.Encrypt, HttpMethod.Post, $"encrypt/{key}", body, cancellationToken);

        return new KeyCiphertext(StringField(key, KeyOperation.Encrypt, response, "ciphertext"));
    }

    public async Task<Secret<byte[]>> DecryptAsync(
        KeyName key,
        Guid? tenantId,
        KeyCiphertext ciphertext,
        CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Aead);
        ArgumentNullException.ThrowIfNull(ciphertext);

        var body = new JsonObject
        {
            ["ciphertext"] = ciphertext.Value,
            ["associated_data"] = AssociatedData(key, tenantId),
        };

        var response = await SendAsync(key, KeyOperation.Decrypt, HttpMethod.Post, $"decrypt/{key}", body, cancellationToken);

        return new Secret<byte[]>(Base64(key, KeyOperation.Decrypt, StringField(key, KeyOperation.Decrypt, response, "plaintext")));
    }

    public async Task<KeyHmac> HmacAsync(KeyName key, Secret<byte[]> input, CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Hmac);
        ArgumentNullException.ThrowIfNull(input);

        var body = new JsonObject
        {
            ["input"] = input.Use(Convert.ToBase64String),
            ["algorithm"] = HashAlgorithm,
        };

        var response = await SendAsync(key, KeyOperation.Hmac, HttpMethod.Post, $"hmac/{key}", body, cancellationToken);
        var (version, value) = ParseVersioned(key, KeyOperation.Hmac, StringField(key, KeyOperation.Hmac, response, "hmac"));

        return new KeyHmac(version, value);
    }

    public async Task<KeyCiphertext> CreateWrappedDataKeyAsync(KeyName key, Guid tenantId, CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Aead);

        var body = new JsonObject
        {
            ["bits"] = DataKeyBits,
            ["associated_data"] = AssociatedData(key, tenantId),
        };

        var response = await SendAsync(
            key, KeyOperation.WrapDataKey, HttpMethod.Post, $"datakey/wrapped/{key}", body, cancellationToken);

        return new KeyCiphertext(StringField(key, KeyOperation.WrapDataKey, response, "ciphertext"));
    }

    public async Task RotateAsync(KeyName key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        await SendAsync(key, KeyOperation.Rotate, HttpMethod.Post, $"keys/{key}/rotate", new JsonObject(), cancellationToken);
    }

    public async Task<KeyCiphertext> RewrapAsync(
        KeyName key,
        Guid? tenantId,
        KeyCiphertext ciphertext,
        CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Aead);
        ArgumentNullException.ThrowIfNull(ciphertext);

        var body = new JsonObject
        {
            ["ciphertext"] = ciphertext.Value,
            ["associated_data"] = AssociatedData(key, tenantId),
        };

        var response = await SendAsync(key, KeyOperation.Rewrap, HttpMethod.Post, $"rewrap/{key}", body, cancellationToken);

        return new KeyCiphertext(StringField(key, KeyOperation.Rewrap, response, "ciphertext"));
    }

    public async Task DeleteAsync(KeyName key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        // Transit refuses to delete a key until its config allows it.
        await SendAsync(
            key,
            KeyOperation.Delete,
            HttpMethod.Post,
            $"keys/{key}/config",
            new JsonObject { ["deletion_allowed"] = true },
            cancellationToken);
        await SendAsync(key, KeyOperation.Delete, HttpMethod.Delete, $"keys/{key}", null, cancellationToken);
    }

    public async Task<IReadOnlyList<KeyPublicVersion>> GetPublicKeysAsync(KeyName key, CancellationToken cancellationToken)
    {
        RequireKind(key, KeyKind.Signing);

        var data = await SendAsync(key, KeyOperation.ReadPublicKey, HttpMethod.Get, $"keys/{key}", null, cancellationToken);

        return PublicKeys(key, KeyOperation.ReadPublicKey, data);
    }

    public void Dispose()
    {
        _http.Dispose();
        _loginLock.Dispose();
    }

    private async Task<JsonElement?> SendAsync(
        KeyName key,
        KeyOperation operation,
        HttpMethod method,
        string path,
        JsonObject? body,
        CancellationToken cancellationToken)
    {
        var (token, fresh) = await TokenAsync(key, operation, stale: null, cancellationToken);

        using (var first = await SendOnceAsync(key, operation, method, $"v1/{Mount}/{path}", body, token, cancellationToken))
        {
            if (first.StatusCode != HttpStatusCode.Forbidden || fresh)
            {
                return await ReadAsync(key, operation, first, cancellationToken);
            }
        }

        // A reused token may have passed its TTL. One login and one retry, then the error stands.
        (token, _) = await TokenAsync(key, operation, stale: token, cancellationToken);

        using var second = await SendOnceAsync(key, operation, method, $"v1/{Mount}/{path}", body, token, cancellationToken);
        return await ReadAsync(key, operation, second, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendOnceAsync(
        KeyName key,
        KeyOperation operation,
        HttpMethod method,
        string path,
        JsonObject? body,
        string? token,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (token is not null)
        {
            request.Headers.Add(TokenHeader, token);
        }

        if (body is not null)
        {
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        }

        try
        {
            return await _http.SendAsync(request, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException
            && !cancellationToken.IsCancellationRequested)
        {
            // The inner exception isn't kept: only the key and operation are named.
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
        }
    }

    private static async Task<JsonElement?> ReadAsync(
        KeyName key,
        KeyOperation operation,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var failure = response.StatusCode switch
        {
            HttpStatusCode.OK or HttpStatusCode.NoContent => (KeyCustodyFailure?)null,
            HttpStatusCode.Forbidden => KeyCustodyFailure.Refused,
            HttpStatusCode.BadRequest or HttpStatusCode.NotFound => KeyCustodyFailure.Rejected,
            _ => KeyCustodyFailure.Unavailable,
        };

        if (failure is { } f)
        {
            throw new KeyCustodyException(key.Value, operation, f);
        }

        if (response.StatusCode == HttpStatusCode.NoContent)
        {
            return null;
        }

        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

            return document.RootElement.TryGetProperty("data", out var data) ? data.Clone() : null;
        }
        catch (JsonException)
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
        }
    }

    /// <summary>Returns a token and whether this call logged in to get it.</summary>
    private async Task<(string Token, bool Fresh)> TokenAsync(
        KeyName key,
        KeyOperation operation,
        string? stale,
        CancellationToken cancellationToken)
    {
        if (_token is { } current && current.Value != stale && _time.GetUtcNow() < current.RenewAt)
        {
            return (current.Value, false);
        }

        await _loginLock.WaitAsync(cancellationToken);
        try
        {
            // Another caller may have logged in while this one waited.
            if (_token is { } other && other.Value != stale && _time.GetUtcNow() < other.RenewAt)
            {
                return (other.Value, false);
            }

            _token = await LoginAsync(key, operation, cancellationToken);
            return (_token.Value, true);
        }
        finally
        {
            _loginLock.Release();
        }
    }

    private async Task<LoginToken> LoginAsync(KeyName key, KeyOperation operation, CancellationToken cancellationToken)
    {
        string roleId;
        string secretId;
        try
        {
            roleId = (await File.ReadAllTextAsync(_options.RoleIdFile, cancellationToken)).Trim();
            secretId = (await File.ReadAllTextAsync(_options.SecretIdFile, cancellationToken)).Trim();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.LoginFailed);
        }

        var body = new JsonObject { ["role_id"] = roleId, ["secret_id"] = secretId };
        var issuedAt = _time.GetUtcNow();

        using var response = await SendOnceAsync(
            key, operation, HttpMethod.Post, $"v1/auth/{_options.AuthMount}/login", body, token: null, cancellationToken);

        if (response.StatusCode != HttpStatusCode.OK)
        {
            // Only a refused credential is a login failure. A sealed or down OpenBao is unavailable.
            throw new KeyCustodyException(
                key.Value,
                operation,
                response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden
                    ? KeyCustodyFailure.LoginFailed
                    : KeyCustodyFailure.Unavailable);
        }

        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var auth = document.RootElement.GetProperty("auth");
            var token = auth.GetProperty("client_token").GetString();
            var lease = auth.GetProperty("lease_duration").GetInt64();

            if (string.IsNullOrEmpty(token))
            {
                throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.LoginFailed);
            }

            var renewAt = lease > 0 ? issuedAt + TimeSpan.FromSeconds(lease * 3 / 4.0) : DateTimeOffset.MaxValue;
            return new LoginToken(token, renewAt);
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.LoginFailed);
        }
    }

    /// <summary>
    /// The Tenant ID as associated data, not <c>context</c>, which a non-derived key ignores.
    /// A Deployment key binds to a fixed value instead.
    /// </summary>
    private static string AssociatedData(KeyName key, Guid? tenantId)
    {
        // A Tenant key binds only to its own Tenant, so any other ID is a caller bug.
        if (tenantId != key.TenantId)
        {
            throw new ArgumentException(
                key.TenantId.HasValue
                    ? $"Key {key} binds only to its own Tenant ID."
                    : $"Key {key} is a Deployment key, so it takes no Tenant ID.",
                nameof(tenantId));
        }

        var bound = tenantId is { } id ? id.ToString("D") : DeploymentAssociatedData;
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(bound));
    }

    private static void RequireKind(KeyName key, KeyKind kind)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Kind != kind)
        {
            throw new ArgumentException($"Key {key} is a {key.Kind} key, not {kind}.", nameof(key));
        }
    }

    private static string StringField(KeyName key, KeyOperation operation, JsonElement? data, string name) =>
        data is { ValueKind: JsonValueKind.Object } d
            && d.TryGetProperty(name, out var value)
            && value.GetString() is { Length: > 0 } text
            ? text
            : throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);

    /// <summary>Reads Transit's <c>vault:v{version}:{base64}</c> form.</summary>
    private static (int Version, byte[] Value) ParseVersioned(KeyName key, KeyOperation operation, string text)
    {
        var parts = text.Split(':');
        if (parts is ["vault", var version, var value]
            && version.StartsWith('v')
            && int.TryParse(version.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            && number > 0)
        {
            return (number, Base64(key, operation, value));
        }

        throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
    }

    private static byte[] Base64(KeyName key, KeyOperation operation, string text)
    {
        try
        {
            return Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
        }
    }

    private static List<KeyPublicVersion> PublicKeys(KeyName key, KeyOperation operation, JsonElement? data)
    {
        if (data is not { ValueKind: JsonValueKind.Object } d
            || !d.TryGetProperty("keys", out var keys)
            || keys.ValueKind != JsonValueKind.Object)
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
        }

        var versions = new List<KeyPublicVersion>();
        foreach (var version in keys.EnumerateObject())
        {
            if (int.TryParse(version.Name, out var number)
                && version.Value.ValueKind == JsonValueKind.Object
                && version.Value.TryGetProperty("public_key", out var publicKey)
                && publicKey.GetString() is { Length: > 0 } pem)
            {
                versions.Add(new KeyPublicVersion(number, pem));
            }
        }

        if (versions.Count == 0)
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
        }

        return [.. versions.OrderBy(v => v.KeyVersion)];
    }

    private static Uri WithTrailingSlash(Uri address) =>
        address.AbsoluteUri.EndsWith('/') ? address : new Uri(address.AbsoluteUri + "/");

    private sealed record LoginToken(string Value, DateTimeOffset RenewAt);
}
