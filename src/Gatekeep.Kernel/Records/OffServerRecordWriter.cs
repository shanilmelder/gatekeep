using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Kernel.Records;

/// <summary>One signed record, as written.</summary>
/// <param name="Key">The object key it was written at.</param>
/// <param name="Content">The canonical JSON bytes the bucket holds.</param>
public sealed record OffServerRecord(string Key, Guid Id, DateTimeOffset WrittenAt, KeySignature Signature, byte[] Content);

/// <summary>
/// The signed record format (AD-17). A record is RFC 8785 JSON holding <c>kind</c>, <c>id</c>,
/// <c>writtenAt</c>, <c>payload</c> and <c>signature</c>. The signature is
/// <c>{ key: "dep-records", version, value }</c>, made by key custody over the canonical bytes of the
/// other four members, so anyone who can verify with <c>dep-records</c> can check a record, and a
/// changed member or a second spelling of the same JSON fails.
/// </summary>
public static class OffServerRecords
{
    /// <summary>The Deployment key that signs records. Only <c>Host.Worker</c> and <c>Gatekeep.Cli</c> may use it.</summary>
    public static readonly KeyName SigningKey = KeyName.ForDeployment(DeploymentKeyClass.Records);

    public const string ContentType = "application/json";

    private const string Kind = "kind";
    private const string Id = "id";
    private const string WrittenAt = "writtenAt";
    private const string Payload = "payload";
    private const string Signature = "signature";
    private const string SignatureKey = "key";
    private const string SignatureVersion = "version";
    private const string SignatureValue = "value";

    private const int MaxKindLength = 64;

    /// <summary>A kind is one lower-case word, with digits and underscores, such as <c>test</c>.</summary>
    public static bool IsValidKind(string? kind) =>
        !string.IsNullOrEmpty(kind)
        && kind.Length <= MaxKindLength
        && char.IsAsciiLetterLower(kind[0])
        && kind.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '_');

    /// <summary><c>records/{kind}/{yyyy}/{MM}/{dd}/{id}.json</c>, dated by the write in UTC.</summary>
    public static string ObjectKey(string kind, Guid id, DateTimeOffset writtenAt)
    {
        RequireKind(kind);
        var day = writtenAt.UtcDateTime;
        return string.Create(CultureInfo.InvariantCulture, $"records/{kind}/{day:yyyy}/{day:MM}/{day:dd}/{id:D}.json");
    }

    /// <summary>The canonical bytes a record's signature covers: its four members other than the signature.</summary>
    public static byte[] SignedBytes(string kind, Guid id, DateTimeOffset writtenAt, JsonObject payload)
    {
        RequireKind(kind);
        ArgumentNullException.ThrowIfNull(payload);

        return CanonicalJson.Utf8(Unsigned(kind, id, writtenAt, payload));
    }

    /// <summary>
    /// Whether <paramref name="record"/> is a signed record in canonical form whose signature verifies
    /// with <c>dep-records</c>. A malformed record is false, never an exception; a custody failure throws.
    /// </summary>
    public static async Task<bool> VerifyAsync(IKeyCustody custody, ReadOnlyMemory<byte> record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(custody);

        if (!TryRead(record.Span, out var signed, out var signature))
        {
            return false;
        }

        return await custody.VerifyAsync(SigningKey, CanonicalJson.Utf8(signed), signature, cancellationToken);
    }

    /// <summary>Reads the four signed members and the signature, only from a record in exact canonical form.</summary>
    public static bool TryRead(ReadOnlySpan<byte> record, out JsonObject signed, out KeySignature signature)
    {
        signed = new JsonObject();
        signature = new KeySignature(0, []);

        JsonObject parsed;
        try
        {
            if (JsonNode.Parse(record) is not JsonObject root)
            {
                return false;
            }

            parsed = root;

            // One spelling only: what was signed is what is stored.
            if (!record.SequenceEqual(CanonicalJson.Utf8(parsed)))
            {
                return false;
            }
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        {
            return false;
        }

        if (parsed.Count != 5
            || parsed[Signature] is not JsonObject sig
            || sig.Count != 3
            || !TryString(sig[SignatureKey], out var keyName)
            || keyName != SigningKey.Value
            || sig[SignatureVersion] is not JsonValue version
            || !version.TryGetValue<int>(out var keyVersion)
            || keyVersion < 1
            || !TryString(sig[SignatureValue], out var value)
            || !TryString(parsed[Kind], out var kind)
            || !IsValidKind(kind)
            || !TryString(parsed[Id], out _)
            || !TryString(parsed[WrittenAt], out _)
            || parsed[Payload] is not JsonObject)
        {
            return false;
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            return false;
        }

        parsed.Remove(Signature);
        signed = parsed;
        signature = new KeySignature(keyVersion, bytes);
        return true;
    }

    internal static JsonObject Unsigned(string kind, Guid id, DateTimeOffset writtenAt, JsonObject payload) => new()
    {
        [Kind] = kind,
        [Id] = id.ToString("D"),
        [WrittenAt] = Timestamp(writtenAt),
        [Payload] = payload.DeepClone(),
    };

    internal static JsonObject SignatureMember(KeySignature signature) => new()
    {
        [SignatureKey] = SigningKey.Value,
        [SignatureVersion] = signature.KeyVersion,
        [SignatureValue] = Convert.ToBase64String(signature.Value),
    };

    /// <summary>RFC 3339 in UTC to the microsecond, as audit events are (AD-16).</summary>
    internal static string Timestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    private static bool TryString(JsonNode? node, out string value)
    {
        value = string.Empty;
        if (node is JsonValue v && v.GetValueKind() == JsonValueKind.String)
        {
            value = v.GetValue<string>();
            return true;
        }

        return false;
    }

    private static void RequireKind(string kind)
    {
        if (!IsValidKind(kind))
        {
            throw new ArgumentException("A record kind is one lower-case word, with digits and underscores.", nameof(kind));
        }
    }
}

/// <summary>
/// Signs records with <c>dep-records</c> through key custody and writes them to the off-server
/// store (AD-17). The store keeps each one in compliance mode for at least
/// <see cref="Retention.RetentionPeriods.LogDays"/> days.
/// </summary>
public sealed class OffServerRecordWriter(IKeyCustody custody, IOffServerStore store, TimeProvider time)
{
    /// <summary>
    /// Signs and writes one record of <paramref name="kind"/>. Custody failures throw
    /// <see cref="KeyCustodyException"/> before anything is written; store failures throw
    /// <see cref="OffServerStoreException"/>. Neither is retried here.
    /// </summary>
    public async Task<OffServerRecord> WriteAsync(string kind, JsonObject payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var now = time.GetUtcNow();
        // Stored to the microsecond, so the value returned is the value written.
        var writtenAt = new DateTimeOffset(now.UtcTicks - (now.UtcTicks % 10), TimeSpan.Zero);
        var id = Guid.CreateVersion7(writtenAt);

        var signed = OffServerRecords.SignedBytes(kind, id, writtenAt, payload);
        var signature = await custody.SignAsync(OffServerRecords.SigningKey, signed, cancellationToken);

        var record = OffServerRecords.Unsigned(kind, id, writtenAt, payload);
        record["signature"] = OffServerRecords.SignatureMember(signature);
        var content = CanonicalJson.Utf8(record);
        var key = OffServerRecords.ObjectKey(kind, id, writtenAt);

        await store.PutAsync(key, content, OffServerRecords.ContentType, cancellationToken);
        return new OffServerRecord(key, id, writtenAt, signature, content);
    }
}
