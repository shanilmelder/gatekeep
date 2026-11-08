using System.Security.Cryptography;
using Gatekeep.Kernel.Records;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Tests.Isolation.OffServer;

/// <summary>
/// A stand-in for <c>dep-records</c> signing: an HMAC under a key of its own, version 1. It isn't
/// RS256; it proves what was signed and that a change fails to verify.
/// </summary>
internal sealed class SigningCustody : IKeyCustody
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

    public List<(KeyName Key, byte[] Data)> Signed { get; } = [];

    /// <summary>When set, every sign fails with this.</summary>
    public KeyCustodyFailure? Fails { get; set; }

    public Task<KeySignature> SignAsync(KeyName key, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (Fails is { } failure)
        {
            throw new KeyCustodyException(key.Value, KeyOperation.Sign, failure);
        }

        Signed.Add((key, data.ToArray()));
        return Task.FromResult(new KeySignature(1, HMACSHA256.HashData(_key, data.Span)));
    }

    public Task<bool> VerifyAsync(KeyName key, ReadOnlyMemory<byte> data, KeySignature signature, CancellationToken cancellationToken) =>
        Task.FromResult(
            key == OffServerRecords.SigningKey
            && signature.KeyVersion == 1
            && CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(_key, data.Span), signature.Value));

    public Task<IReadOnlyList<KeyPublicVersion>> CreateKeyAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> EncryptAsync(KeyName key, Guid? tenantId, Secret<byte[]> plaintext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<Secret<byte[]>> DecryptAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<KeyHmac> HmacAsync(KeyName key, Secret<byte[]> input, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> CreateWrappedDataKeyAsync(KeyName key, Guid tenantId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task RotateAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> RewrapAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task DeleteAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<IReadOnlyList<KeyPublicVersion>> GetPublicKeysAsync(KeyName key, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<ListedKey>> ListRowKeysAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
}

/// <summary>Keeps every write in memory, in order, or fails each one with <see cref="Fails"/>.</summary>
internal sealed class MemoryStore : IOffServerStore
{
    public List<(string Key, byte[] Content, string ContentType)> Puts { get; } = [];

    public OffServerStoreFailure? Fails { get; set; }

    public Task PutAsync(string key, ReadOnlyMemory<byte> content, string contentType, CancellationToken cancellationToken)
    {
        if (Fails is { } failure)
        {
            throw new OffServerStoreException(OffServerOperation.Put, failure);
        }

        Puts.Add((key, content.ToArray(), contentType));
        return Task.CompletedTask;
    }
}

/// <summary>A clock a test sets.</summary>
internal sealed class SetTime(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>
/// Answers every request with <see cref="Status"/> and keeps what each carried, headers and body,
/// so a test sees exactly what an adapter sent and how often.
/// </summary>
internal sealed class CapturingHandler(System.Net.HttpStatusCode status = System.Net.HttpStatusCode.OK) : HttpMessageHandler
{
    public System.Net.HttpStatusCode Status { get; set; } = status;

    public List<(HttpRequestMessage Request, Dictionary<string, string> Headers, byte[] Body)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
            .ToDictionary(h => h.Key.ToLowerInvariant(), h => string.Join(',', h.Value), StringComparer.Ordinal);
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        Requests.Add((request, headers, body));
        return new HttpResponseMessage(Status);
    }
}
