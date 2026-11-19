using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Konscious.Security.Cryptography;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// Argon2id password hashing (Story 4.7, NFR-2) as a PHC string, <c>$argon2id$v=19$m={KiB},t={iterations},p={lanes}$salt$hash</c>,
/// salt and hash unpadded base64. A new hash takes <see cref="SecurityLimits"/>' parameters; a stored one is verified with
/// its own, read from its string, so the defaults can be raised later. The password's bytes are zeroed once used.
/// </summary>
internal static class PasswordHasher
{
    private const string Prefix = "$argon2id$v=19$";

    /// <summary>The most memory a stored hash may name: 1 GiB. A string asking for more is refused, never computed.</summary>
    private const int MaxMemoryKiB = 1024 * 1024;

    private const int MaxIterations = 64;

    private const int MaxParallelism = 16;

    /// <summary>A new PHC string for <paramref name="password"/>, with a fresh random salt and the default parameters.</summary>
    public static async Task<string> HashAsync(Secret<string> password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SecurityLimits.Argon2SaltBytes);
        var parameters = new Parameters(SecurityLimits.Argon2MemoryKiB, SecurityLimits.Argon2Iterations, SecurityLimits.Argon2Parallelism);
        var hash = await ComputeAsync(password, salt, parameters, SecurityLimits.Argon2HashBytes);
        try
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"{Prefix}m={parameters.MemoryKiB},t={parameters.Iterations},p={parameters.Parallelism}${Encode(salt)}${Encode(hash)}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    /// <summary>
    /// Whether <paramref name="password"/> is the one <paramref name="phc"/> was made from, compared in constant time. A
    /// string that isn't an Argon2id PHC string Gatekeep could have made is no match.
    /// </summary>
    public static async Task<bool> VerifyAsync(Secret<string> password, string phc)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (!TryParse(phc, out var parameters, out var salt, out var expected))
        {
            return false;
        }

        var actual = await ComputeAsync(password, salt, parameters, expected.Length);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    /// <summary>The parameters <paramref name="phc"/> names, or null when it isn't a PHC string this reads.</summary>
    public static Parameters? ParametersOf(string phc) => TryParse(phc, out var parameters, out _, out _) ? parameters : null;

    private static async Task<byte[]> ComputeAsync(Secret<string> password, byte[] salt, Parameters parameters, int length)
    {
        var bytes = password.Use(static value => Encoding.UTF8.GetBytes(value));
        try
        {
            using var argon = new Argon2id(bytes)
            {
                Salt = salt,
                MemorySize = parameters.MemoryKiB,
                Iterations = parameters.Iterations,
                DegreeOfParallelism = parameters.Parallelism,
            };
            return await argon.GetBytesAsync(length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool TryParse(string? phc, out Parameters parameters, out byte[] salt, out byte[] hash)
    {
        parameters = default;
        salt = [];
        hash = [];
        if (phc is null || !phc.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var parts = phc[Prefix.Length..].Split('$');
        if (parts.Length != 3)
        {
            return false;
        }

        int? memory = null, iterations = null, parallelism = null;
        foreach (var pair in parts[0].Split(','))
        {
            var equals = pair.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0 || !int.TryParse(pair.AsSpan(equals + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return false;
            }

            switch (pair[..equals])
            {
                case "m" when memory is null:
                    memory = value;
                    break;
                case "t" when iterations is null:
                    iterations = value;
                    break;
                case "p" when parallelism is null:
                    parallelism = value;
                    break;
                default:
                    return false;
            }
        }

        if (memory is not { } m || iterations is not { } t || parallelism is not { } p
            || p < 1 || p > MaxParallelism || t < 1 || t > MaxIterations || m < 8 * p || m > MaxMemoryKiB)
        {
            return false;
        }

        if (!TryDecode(parts[1], out salt) || salt.Length < 8 || !TryDecode(parts[2], out hash) || hash.Length < 16 || hash.Length > 64)
        {
            return false;
        }

        parameters = new Parameters(m, t, p);
        return true;
    }

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static bool TryDecode(string text, out byte[] bytes)
    {
        bytes = [];
        if (text.Length == 0 || text.Contains('=', StringComparison.Ordinal))
        {
            return false;
        }

        var padded = text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '=');
        var buffer = new byte[padded.Length * 3 / 4];
        if (!Convert.TryFromBase64String(padded, buffer, out var written))
        {
            return false;
        }

        bytes = buffer[..written];
        return true;
    }

    /// <summary>An Argon2id hash's cost: memory in KiB, iterations and lanes.</summary>
    public readonly record struct Parameters(int MemoryKiB, int Iterations, int Parallelism);
}
