using System.Buffers.Text;
using System.Security.Cryptography;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// An Admin Session ID: 32 CSPRNG bytes, written as 43 base64url characters with no padding.
/// Only the SHA-256 of the bytes is stored. Its CSRF token is derived from the bytes, as
/// <c>base64url(SHA-256("gatekeep-admin-csrf\0" || ID))</c>: a different value, one-way, the same
/// in every tab, and never stored.
/// </summary>
internal static class SessionSecrets
{
    public const int Bytes = 32;

    private const int Length = 43;

    private static ReadOnlySpan<byte> CsrfLabel => "gatekeep-admin-csrf\0"u8;

    /// <summary>A fresh Session ID, the hash to store and its CSRF token.</summary>
    public static (Secret<string> Token, byte[] Hash, Secret<string> Csrf) Generate()
    {
        Span<byte> raw = stackalloc byte[Bytes];
        try
        {
            RandomNumberGenerator.Fill(raw);
            var csrf = DeriveCsrf(raw);
            try
            {
                return (new Secret<string>(Base64Url.EncodeToString(raw)), SHA256.HashData(raw), new Secret<string>(Encode(csrf)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(csrf);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>
    /// A fresh 256-bit value of the same form, such as a sign-in's binding cookie (Story 1.23),
    /// and the SHA-256 to store. No CSRF token goes with it.
    /// </summary>
    public static (Secret<string> Token, byte[] Hash) GenerateValue()
    {
        Span<byte> raw = stackalloc byte[Bytes];
        try
        {
            RandomNumberGenerator.Fill(raw);
            return (new Secret<string>(Base64Url.EncodeToString(raw)), SHA256.HashData(raw));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>The SHA-256 of a value in this form, or null when it isn't one.</summary>
    public static byte[]? TryHash(Secret<string>? value)
    {
        if (value is null)
        {
            return null;
        }

        var raw = new byte[Bytes];
        try
        {
            return value.Use(token => TryDecode(token, raw)) ? SHA256.HashData(raw) : null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>The CSRF token's bytes for the Session ID <paramref name="id"/>.</summary>
    public static byte[] DeriveCsrf(ReadOnlySpan<byte> id)
    {
        Span<byte> input = stackalloc byte[CsrfLabel.Length + Bytes];
        try
        {
            CsrfLabel.CopyTo(input);
            id.CopyTo(input[CsrfLabel.Length..]);
            return SHA256.HashData(input);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static string Encode(ReadOnlySpan<byte> bytes) => Base64Url.EncodeToString(bytes);

    /// <summary>
    /// Decodes <paramref name="token"/> into <paramref name="destination"/>, 32 bytes. False for
    /// anything but the canonical form: no padding, whitespace or stray bits in the last character.
    /// </summary>
    public static bool TryDecode(string? token, Span<byte> destination)
    {
        if (token is null || token.Length != Length || destination.Length != Bytes)
        {
            return false;
        }

        Span<byte> raw = stackalloc byte[Bytes + 1];
        Span<char> canonical = stackalloc char[Length];
        try
        {
            if (!Base64Url.TryDecodeFromChars(token, raw, out var written)
                || written != Bytes
                || !Base64Url.TryEncodeToChars(raw[..Bytes], canonical, out var chars)
                || chars != Length
                || !canonical.SequenceEqual(token))
            {
                return false;
            }

            raw[..Bytes].CopyTo(destination);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }
}
