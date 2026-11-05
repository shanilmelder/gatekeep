using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The global signing and encryption credentials OpenIddict insists on at startup (AD-8). They pass
/// its configuration checks, but every cryptographic use throws, so a request that reached the
/// global options could produce no signature, token or JWKS entry. No Tenant's options hold them.
/// </summary>
internal sealed class InertCredentials
{
    public const string SigningKeyId = "inert-global-signing";

    public const string EncryptionKeyId = "inert-global-encryption";

    public InertCredentials()
    {
        var factory = new InertCryptoProviderFactory();

        Signing = new SigningCredentials(
            new InertAsymmetricKey { KeyId = SigningKeyId, CryptoProviderFactory = factory },
            SecurityAlgorithms.RsaSha256);

        // All zero: it's never used, and a key that worked would be a finding.
        Encrypting = new EncryptingCredentials(
            new SymmetricSecurityKey(new byte[32]) { KeyId = EncryptionKeyId, CryptoProviderFactory = factory },
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256CbcHmacSha512);
    }

    public SigningCredentials Signing { get; }

    public EncryptingCredentials Encrypting { get; }

    /// <summary>Whether <paramref name="key"/> is one of the inert global keys.</summary>
    public static bool IsInert(SecurityKey? key) => key?.KeyId is SigningKeyId or EncryptionKeyId;
}

internal sealed class InertKeyUsedException(string operation)
    : InvalidOperationException($"An inert global credential was used for {operation}.");

/// <summary>An asymmetric key that claims a private half it doesn't have, and holds no key at all.</summary>
internal sealed class InertAsymmetricKey : AsymmetricSecurityKey
{
    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
    public override bool HasPrivateKey => true;

    public override PrivateKeyStatus PrivateKeyStatus => PrivateKeyStatus.Exists;

    public override int KeySize => 3072;
}

/// <summary>Refuses every operation it is asked for.</summary>
internal sealed class InertCryptoProviderFactory : CryptoProviderFactory
{
    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => true;

    public override bool IsSupportedAlgorithm(string algorithm) => true;

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        throw new InertKeyUsedException("signing");

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm, bool cacheProvider) =>
        throw new InertKeyUsedException("signing");

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        throw new InertKeyUsedException("verifying");

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm, bool cacheProvider) =>
        throw new InertKeyUsedException("verifying");

    public override KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm) =>
        throw new InertKeyUsedException("key wrapping");

    public override KeyWrapProvider CreateKeyWrapProviderForUnwrap(SecurityKey key, string algorithm) =>
        throw new InertKeyUsedException("key unwrapping");

    public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) =>
        throw new InertKeyUsedException("encryption");

    public override HashAlgorithm CreateHashAlgorithm(string algorithm) =>
        throw new InertKeyUsedException("hashing");

    public override HashAlgorithm CreateHashAlgorithm(HashAlgorithmName algorithm) =>
        throw new InertKeyUsedException("hashing");

    public override KeyedHashAlgorithm CreateKeyedHashAlgorithm(byte[] keyBytes, string algorithm) =>
        throw new InertKeyUsedException("keyed hashing");
}
