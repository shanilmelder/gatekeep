using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Identity.Core;

/// <summary>
/// An email verification link's token (Story 4.7, AD-9): <c>{tenantPublicId}.{base64url of 32 random bytes}</c>, so a
/// link from another Tenant is refused by its prefix before any lookup. Only the SHA-256 of the whole value's ASCII text
/// is stored. The log scrubber masks the shape as any other Tenant artifact.
/// </summary>
internal static class VerificationLinks
{
    /// <summary>The length of the random part's text: 43 base64url characters for 32 bytes.</summary>
    private static readonly int RandomTextLength = Base64Url.GetEncodedLength(SecurityLimits.OpaqueValueBytes);

    private const string Base64UrlCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>A new link token for <paramref name="tenantId"/> and the hash to store. The random bytes are zeroed once encoded.</summary>
    public static (Secret<string> Token, byte[] Hash) New(Guid tenantId)
    {
        var random = RandomNumberGenerator.GetBytes(SecurityLimits.OpaqueValueBytes);
        try
        {
            var token = Prefix(tenantId) + Base64Url.EncodeToString(random);
            return (new Secret<string>(token), Hash(token));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    /// <summary>
    /// The stored hash of <paramref name="token"/> when it has a link's shape and <paramref name="tenantId"/>'s prefix, else
    /// null: a foreign or malformed value is never looked up.
    /// </summary>
    public static byte[]? OwnHash(Guid tenantId, string token) =>
        IsShaped(token) && token.StartsWith(Prefix(tenantId), StringComparison.Ordinal) ? Hash(token) : null;

    /// <summary>
    /// Whether <paramref name="token"/> has a link's shape, for any Tenant: <c>ten_</c>, 26 base32 characters, a dot and 43
    /// base64url characters.
    /// </summary>
    public static bool IsShaped(string? token)
    {
        if (token is null)
        {
            return false;
        }

        var dot = token.IndexOf('.', StringComparison.Ordinal);
        if (dot < 0 || token.Length - dot - 1 != RandomTextLength)
        {
            return false;
        }

        return PublicId.TryParse(PublicIdType.Tenant, token[..dot], out _)
            && token.AsSpan(dot + 1).IndexOfAnyExcept(Base64UrlCharacters.AsSpan()) < 0;
    }

    /// <summary>The SHA-256 of <paramref name="token"/>'s ASCII bytes: what is stored for it.</summary>
    public static byte[] Hash(string token) => SHA256.HashData(Encoding.ASCII.GetBytes(token));

    private static string Prefix(Guid tenantId) => PublicId.Format(PublicIdType.Tenant, tenantId) + ".";
}
