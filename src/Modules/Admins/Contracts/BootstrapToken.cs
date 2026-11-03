using System.Security.Cryptography;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// The one-time bootstrap token's form (Story 1.19, AD-31): 32 CSPRNG bytes written as 64
/// lower-case hex characters. Only <see cref="Hash(ReadOnlySpan{byte})"/> of it is ever stored,
/// in <c>bootstrap_state.token_sha256</c>.
/// <para>
/// Story 1.21's contract: a submitted token is checked with <see cref="Hash(string)"/> and
/// compared in constant time with the stored hash, after a <c>SELECT … FOR UPDATE</c> of the
/// <c>bootstrap_state</c> row, in the transaction that sets <c>completed_at</c>, so two claims
/// can't both succeed and a claim can't race a reissue.
/// </para>
/// </summary>
public static class BootstrapToken
{
    /// <summary>The token's length in characters.</summary>
    public const int Length = 64;

    private const int RandomBytes = Length / 2;

    private const string HexDigits = "0123456789abcdef";

    /// <summary>A fresh token as its 64 ASCII characters. The caller zeroes the array when done.</summary>
    public static byte[] Generate()
    {
        Span<byte> random = stackalloc byte[RandomBytes];
        var token = new byte[Length];
        try
        {
            RandomNumberGenerator.Fill(random);
            for (var i = 0; i < RandomBytes; i++)
            {
                token[2 * i] = (byte)HexDigits[random[i] >> 4];
                token[(2 * i) + 1] = (byte)HexDigits[random[i] & 0xf];
            }

            return token;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    /// <summary>
    /// The SHA-256 of a submitted token: surrounding whitespace, such as the file's newline, is
    /// trimmed, then it must be exactly 64 lower-case hex characters, hashed as ASCII.
    /// </summary>
    /// <exception cref="ArgumentException">It isn't a token. The message never quotes it.</exception>
    public static byte[] Hash(string submitted)
    {
        ArgumentNullException.ThrowIfNull(submitted);

        var trimmed = submitted.AsSpan().Trim();
        if (trimmed.Length != Length)
        {
            throw NotAToken(nameof(submitted));
        }

        Span<byte> ascii = stackalloc byte[Length];
        try
        {
            for (var i = 0; i < Length; i++)
            {
                ascii[i] = trimmed[i] < 128 ? (byte)trimmed[i] : (byte)0;
            }

            return Hash(ascii);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ascii);
        }
    }

    /// <summary>As <see cref="Hash(string)"/>, over the token's ASCII bytes, such as the file's contents.</summary>
    /// <exception cref="ArgumentException">It isn't a token. The message never quotes it.</exception>
    public static byte[] Hash(ReadOnlySpan<byte> submitted)
    {
        var trimmed = submitted.Trim(" \t\r\n"u8);
        if (trimmed.Length != Length)
        {
            throw NotAToken(nameof(submitted));
        }

        foreach (var c in trimmed)
        {
            if (c is not ((>= (byte)'0' and <= (byte)'9') or (>= (byte)'a' and <= (byte)'f')))
            {
                throw NotAToken(nameof(submitted));
            }
        }

        return SHA256.HashData(trimmed);
    }

    private static ArgumentException NotAToken(string parameter) =>
        new($"A bootstrap token is {Length} lower-case hex characters.", parameter);
}
