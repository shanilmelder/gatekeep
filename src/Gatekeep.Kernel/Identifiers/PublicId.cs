namespace Gatekeep.Kernel.Identifiers;

/// <summary>The kinds of public ID, each with its fixed prefix (spine Conventions, AD-9).</summary>
public enum PublicIdType
{
    /// <summary><c>ten_</c>: a Tenant, as <c>{tenantId}</c> in a path and <c>{tenantPublicId}</c> in an artifact.</summary>
    Tenant,

    /// <summary>
    /// <c>acr_</c>: one of an Admin's WebAuthn credentials, by its row, as <c>{credentialId}</c> in a
    /// path (Story 1.26). Never the WebAuthn credential ID, which no response carries.
    /// </summary>
    AdminCredential,

    /// <summary>
    /// <c>opr_</c>: an Operation (AD-30), as <c>{operationId}</c> in a path (Story 1.27). A malformed
    /// one is the unknown-path 404, like an unknown one.
    /// </summary>
    Operation,
}

/// <summary>
/// A public ID: the type's prefix, an underscore, then the UUID's 16 bytes in RFC 4648 base32
/// with the lowercase alphabet <c>a–z2–7</c> and no padding, 26 characters (spine Conventions).
/// Only the canonical spelling parses, after any URL decoding: the exact prefix, exactly 26
/// characters from the alphabet, and the last character's two unused bits zero. So every ID has exactly one spelling, and
/// uppercase, padding or any second spelling is malformed. The empty UUID is never an ID.
/// </summary>
public static class PublicId
{
    /// <summary>The base32 characters of 16 bytes: 128 bits in 5-bit groups, the last holding 3 bits and 2 zeros.</summary>
    public const int EncodedLength = 26;

    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    private const int Bytes = 16;

    /// <summary>The prefix of <paramref name="type"/>, without its underscore.</summary>
    public static string Prefix(PublicIdType type) => type switch
    {
        PublicIdType.Tenant => "ten",
        PublicIdType.AdminCredential => "acr",
        PublicIdType.Operation => "opr",
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    /// <summary>The public ID of <paramref name="id"/>, such as <c>ten_</c> followed by 26 characters.</summary>
    /// <exception cref="ArgumentException"><paramref name="id"/> is the empty UUID.</exception>
    public static string Format(PublicIdType type, Guid id)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("The empty UUID has no public ID.", nameof(id));
        }

        var prefix = Prefix(type);
        return string.Create(prefix.Length + 1 + EncodedLength, (prefix, id), static (chars, state) =>
        {
            state.prefix.AsSpan().CopyTo(chars);
            chars[state.prefix.Length] = '_';

            Span<byte> value = stackalloc byte[Bytes];
            state.id.TryWriteBytes(value, bigEndian: true, out _);

            var output = chars[(state.prefix.Length + 1)..];
            var buffer = 0;
            var bits = 0;
            var written = 0;
            foreach (var b in value)
            {
                buffer = (buffer << 8) | b;
                bits += 8;
                while (bits >= 5)
                {
                    bits -= 5;
                    output[written++] = Alphabet[(buffer >> bits) & 31];
                }

                buffer &= (1 << bits) - 1;
            }

            // The last 3 bits, padded with 2 zero bits.
            output[written] = Alphabet[(buffer << (5 - bits)) & 31];
        });
    }

    /// <summary>
    /// The UUID <paramref name="text"/> names, when it is the canonical public ID of
    /// <paramref name="type"/>. <paramref name="text"/> is the value itself, so a path segment is
    /// checked after URL decoding (Kestrel decodes <c>%xx</c>): <c>ten_%61…</c> arrives as
    /// <c>ten_a…</c> and is that same canonical ID, while anything still not canonical once decoded
    /// is refused. Never throws: anything else, a null or an undefined type included, is false.
    /// </summary>
    public static bool TryParse(PublicIdType type, string? text, out Guid id)
    {
        id = Guid.Empty;
        if (!Enum.IsDefined(type))
        {
            return false;
        }

        var prefix = Prefix(type);
        if (text is null
            || text.Length != prefix.Length + 1 + EncodedLength
            || !text.StartsWith(prefix, StringComparison.Ordinal)
            || text[prefix.Length] != '_')
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[Bytes];
        var buffer = 0;
        var bits = 0;
        var written = 0;
        foreach (var c in text.AsSpan(prefix.Length + 1))
        {
            var value = Value(c);
            if (value < 0)
            {
                return false;
            }

            buffer = ((buffer << 5) | value) & 0xFFF;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                bytes[written++] = (byte)(buffer >> bits);
            }
        }

        // 26 characters are 130 bits: the 2 left over must be zero, or a second spelling would parse.
        if (written != Bytes || bits != 2 || (buffer & 0b11) != 0)
        {
            return false;
        }

        var parsed = new Guid(bytes, bigEndian: true);
        if (parsed == Guid.Empty)
        {
            return false;
        }

        id = parsed;
        return true;
    }

    private static int Value(char c) => c switch
    {
        >= 'a' and <= 'z' => c - 'a',
        >= '2' and <= '7' => c - '2' + 26,
        _ => -1,
    };
}
