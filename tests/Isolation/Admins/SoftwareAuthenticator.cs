using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>What a test makes a <see cref="SoftwareAuthenticator"/> get wrong in one response.</summary>
internal sealed record AttestationTweaks
{
    /// <summary>The client data's origin, when not the one asked for.</summary>
    public string? Origin { get; init; }

    /// <summary>The RP ID whose hash the authenticator data carries, when not the options' own.</summary>
    public string? RpId { get; init; }

    /// <summary>The client data's <c>crossOrigin</c>: absent when null.</summary>
    public bool? CrossOrigin { get; init; }

    /// <summary>A <c>topOrigin</c> in the client data.</summary>
    public string? TopOrigin { get; init; }

    /// <summary>Whether the UV flag is set.</summary>
    public bool UserVerified { get; init; } = true;

    /// <summary>The client data's challenge, base64url, when not the options' own.</summary>
    public string? Challenge { get; init; }

    /// <summary>The client data's type, when not <c>webauthn.create</c>.</summary>
    public string? Type { get; init; }

    /// <summary>The COSE algorithm the public key claims: ES256 (-7) unless set.</summary>
    public int Algorithm { get; init; } = -7;
}

/// <summary>What a test makes a <see cref="SoftwareAuthenticator"/> get wrong, or set, in one assertion.</summary>
internal sealed record AssertionTweaks
{
    /// <summary>The client data's origin, when not the one asked for.</summary>
    public string? Origin { get; init; }

    /// <summary>The RP ID whose hash the authenticator data carries, when not the options' own.</summary>
    public string? RpId { get; init; }

    /// <summary>The client data's <c>crossOrigin</c>: absent when null.</summary>
    public bool? CrossOrigin { get; init; }

    /// <summary>A <c>topOrigin</c> in the client data.</summary>
    public string? TopOrigin { get; init; }

    /// <summary>Whether the UV flag is set.</summary>
    public bool UserVerified { get; init; } = true;

    /// <summary>Whether the UP flag is set.</summary>
    public bool UserPresent { get; init; } = true;

    /// <summary>The client data's challenge, base64url, when not the options' own.</summary>
    public string? Challenge { get; init; }

    /// <summary>The client data's type, when not <c>webauthn.get</c>.</summary>
    public string? Type { get; init; }

    /// <summary>The signature counter, when not the authenticator's next one.</summary>
    public uint? SignCount { get; init; }

    /// <summary>The user handle sent, when not the one the credential was registered with.</summary>
    public byte[]? UserHandle { get; init; }

    /// <summary>Sends no user handle at all.</summary>
    public bool OmitUserHandle { get; init; }

    /// <summary>Signs with another key than the credential's: a bad signature.</summary>
    public bool OtherKey { get; init; }
}

/// <summary>
/// A WebAuthn authenticator in test code: one P-256 key and credential ID, answering creation
/// options with a <c>none</c> attestation, and request options with an assertion, as a browser
/// would hand them to the page, in WebAuthn's JSON form. It builds the CBOR itself, the few shapes
/// a <c>none</c> attestation needs. Its signature counter starts at 0, as registered, and each
/// assertion takes the next, unless a tweak says otherwise.
/// </summary>
internal sealed class SoftwareAuthenticator : IDisposable
{
    private const byte UserPresent = 0x01;
    private const byte UserVerifiedFlag = 0x04;
    private const byte AttestedCredentialData = 0x40;

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public SoftwareAuthenticator(byte[]? credentialId = null)
    {
        CredentialId = credentialId ?? RandomNumberGenerator.GetBytes(32);
    }

    public byte[] CredentialId { get; }

    public Guid Aaguid { get; } = Guid.NewGuid();

    /// <summary>The user handle of the account the credential was last registered to, from its creation options.</summary>
    public byte[]? UserHandle { get; set; }

    /// <summary>The signature counter the last assertion carried.</summary>
    public uint Counter { get; set; }

    /// <summary>
    /// The JSON body a page posts to complete a registration: the response to
    /// <paramref name="options"/> (a begin response), made at <paramref name="origin"/>. The
    /// options' user handle is kept, as a resident key keeps it, for assertions.
    /// </summary>
    public string Attest(JsonElement options, string origin, AttestationTweaks? tweaks = null)
    {
        tweaks ??= new AttestationTweaks();
        var rpId = tweaks.RpId ?? options.GetProperty("rp").GetProperty("id").GetString()!;
        var challenge = tweaks.Challenge ?? options.GetProperty("challenge").GetString()!;
        UserHandle = Base64Url.DecodeFromChars(options.GetProperty("user").GetProperty("id").GetString()!);
        return Attest(rpId, challenge, origin, tweaks);
    }

    /// <summary>
    /// The JSON body a page posts to complete a sign-in: the assertion for
    /// <paramref name="options"/> (a sign-in begin response), made at <paramref name="origin"/>.
    /// </summary>
    public string Assert(JsonElement options, string origin, AssertionTweaks? tweaks = null) =>
        Assert(options.GetProperty("rpId").GetString()!, options.GetProperty("challenge").GetString()!, origin, tweaks);

    public string Assert(string rpId, string challenge, string origin, AssertionTweaks? tweaks = null)
    {
        tweaks ??= new AssertionTweaks();
        var clientData = ClientData(tweaks.Type ?? "webauthn.get", tweaks.Challenge ?? challenge, tweaks.Origin ?? origin, tweaks.CrossOrigin, tweaks.TopOrigin);
        var count = tweaks.SignCount ?? Counter + 1;
        Counter = count;

        var authenticatorData = new List<byte>();
        authenticatorData.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(tweaks.RpId ?? rpId)));
        authenticatorData.Add((byte)((tweaks.UserPresent ? UserPresent : 0) | (tweaks.UserVerified ? UserVerifiedFlag : 0)));
        Span<byte> counter = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, count);
        authenticatorData.AddRange(counter.ToArray());
        byte[] data = [.. authenticatorData];

        byte[] signed = [.. data, .. SHA256.HashData(clientData)];
        byte[] signature;
        if (tweaks.OtherKey)
        {
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            signature = other.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        else
        {
            signature = _key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }

        var handle = tweaks.OmitUserHandle ? null : tweaks.UserHandle ?? UserHandle;
        var id = Base64Url.EncodeToString(CredentialId);
        return JsonSerializer.Serialize(new
        {
            id,
            rawId = id,
            type = "public-key",
            response = new
            {
                clientDataJSON = Base64Url.EncodeToString(clientData),
                authenticatorData = Base64Url.EncodeToString(data),
                signature = Base64Url.EncodeToString(signature),
                userHandle = handle is null ? null : Base64Url.EncodeToString(handle),
            },
            clientExtensionResults = new { },
            authenticatorAttachment = "cross-platform",
        });
    }

    public string Attest(string rpId, string challenge, string origin, AttestationTweaks? tweaks = null)
    {
        tweaks ??= new AttestationTweaks();
        var clientData = ClientData(tweaks.Type ?? "webauthn.create", tweaks.Challenge ?? challenge, tweaks.Origin ?? origin, tweaks.CrossOrigin, tweaks.TopOrigin);
        var attestationObject = AttestationObject(rpId, tweaks.UserVerified, tweaks.Algorithm);
        var id = Base64Url.EncodeToString(CredentialId);
        return JsonSerializer.Serialize(new
        {
            id,
            rawId = id,
            type = "public-key",
            response = new
            {
                clientDataJSON = Base64Url.EncodeToString(clientData),
                attestationObject = Base64Url.EncodeToString(attestationObject),
                transports = new[] { "usb", "internal" },
            },
            clientExtensionResults = new { },
            authenticatorAttachment = "cross-platform",
        });
    }

    /// <summary>The client data JSON as a browser serializes it, in its member order.</summary>
    public static byte[] ClientData(string type, string challenge, string origin, bool? crossOrigin, string? topOrigin)
    {
        var json = new StringBuilder();
        json.Append("{\"type\":").Append(JsonSerializer.Serialize(type));
        json.Append(",\"challenge\":").Append(JsonSerializer.Serialize(challenge));
        json.Append(",\"origin\":").Append(JsonSerializer.Serialize(origin));
        if (crossOrigin is { } cross)
        {
            json.Append(",\"crossOrigin\":").Append(cross ? "true" : "false");
        }

        if (topOrigin is not null)
        {
            json.Append(",\"topOrigin\":").Append(JsonSerializer.Serialize(topOrigin));
        }

        return Encoding.UTF8.GetBytes(json.Append('}').ToString());
    }

    public void Dispose() => _key.Dispose();

    /// <summary>{ "fmt": "none", "attStmt": {}, "authData": … }, keys in CTAP canonical order.</summary>
    private byte[] AttestationObject(string rpId, bool userVerified, int algorithm)
    {
        var cbor = new List<byte> { 0xA3 };
        Text(cbor, "fmt");
        Text(cbor, "none");
        Text(cbor, "attStmt");
        cbor.Add(0xA0);
        Text(cbor, "authData");
        Bytes(cbor, AuthenticatorData(rpId, userVerified, algorithm));
        return [.. cbor];
    }

    private byte[] AuthenticatorData(string rpId, bool userVerified, int algorithm)
    {
        var data = new List<byte>();
        data.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));
        data.Add((byte)(UserPresent | AttestedCredentialData | (userVerified ? UserVerifiedFlag : 0)));
        data.AddRange([0, 0, 0, 0]);

        // The AAGUID is big-endian, as its RFC 4122 bytes.
        data.AddRange(Aaguid.ToByteArray(bigEndian: true));
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)CredentialId.Length);
        data.AddRange(length.ToArray());
        data.AddRange(CredentialId);
        data.AddRange(CoseKey(algorithm));
        return [.. data];
    }

    /// <summary>The public key as a COSE EC2 key: { 1: 2, 3: alg, -1: 1, -2: x, -3: y }.</summary>
    private byte[] CoseKey(int algorithm)
    {
        var point = _key.ExportParameters(includePrivateParameters: false).Q;
        var cbor = new List<byte> { 0xA5, 0x01, 0x02, 0x03 };
        Integer(cbor, algorithm);
        cbor.AddRange([0x20, 0x01, 0x21]);
        Bytes(cbor, point.X!);
        cbor.Add(0x22);
        Bytes(cbor, point.Y!);
        return [.. cbor];
    }

    private static void Integer(List<byte> cbor, int value)
    {
        if (value >= 0)
        {
            Head(cbor, 0x00, (ulong)value);
        }
        else
        {
            Head(cbor, 0x20, (ulong)(-1L - value));
        }
    }

    private static void Text(List<byte> cbor, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Head(cbor, 0x60, (ulong)bytes.Length);
        cbor.AddRange(bytes);
    }

    private static void Bytes(List<byte> cbor, byte[] value)
    {
        Head(cbor, 0x40, (ulong)value.Length);
        cbor.AddRange(value);
    }

    private static void Head(List<byte> cbor, byte major, ulong value)
    {
        switch (value)
        {
            case < 24:
                cbor.Add((byte)(major | value));
                break;
            case <= byte.MaxValue:
                cbor.Add((byte)(major | 24));
                cbor.Add((byte)value);
                break;
            case <= ushort.MaxValue:
                cbor.Add((byte)(major | 25));
                cbor.Add((byte)(value >> 8));
                cbor.Add((byte)value);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(value));
        }
    }
}
