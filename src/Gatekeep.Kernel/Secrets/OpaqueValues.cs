using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Limits;

namespace Gatekeep.Kernel.Secrets;

/// <summary>
/// The one way to make and hash an opaque browser value (Story 4.2, AD-12): a sign-in transaction's
/// <c>__Host-gk_txn</c> binding and a User Session's <c>__Host-gk_session</c> identifier. A value is
/// <see cref="SecurityLimits.OpaqueValueBytes"/> CSPRNG bytes as unpadded base64url text, and only the
/// SHA-256 of that text's ASCII bytes is stored, so a presented value is looked up by hashing it the same way.
/// </summary>
public static class OpaqueValues
{
    /// <summary>The length of a value's text: 43 base64url characters for 32 bytes.</summary>
    public static readonly int TextLength = Base64Url.GetEncodedLength(SecurityLimits.OpaqueValueBytes);

    /// <summary>A fresh value and the hash to store. The random bytes are zeroed once encoded.</summary>
    public static (Secret<string> Value, byte[] Hash) New()
    {
        var random = RandomNumberGenerator.GetBytes(SecurityLimits.OpaqueValueBytes);

        try
        {
            var value = Base64Url.EncodeToString(random);
            return (new Secret<string>(value), Hash(value));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    /// <summary>The SHA-256 of <paramref name="value"/>'s ASCII bytes: what is stored for it.</summary>
    public static byte[] Hash(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return SHA256.HashData(Encoding.ASCII.GetBytes(value));
    }

    /// <summary>
    /// Whether <paramref name="value"/> has a value's shape: exactly <see cref="TextLength"/> base64url
    /// characters. A presented value without it is never looked up.
    /// </summary>
    public static bool IsWellFormed(string? value) =>
        value is not null
        && value.Length == TextLength
        && value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
