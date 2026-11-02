using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>
/// The global signing and encryption credentials OpenIddict insists on at startup (AD-8). They
/// look real enough to pass its configuration checks, but any cryptographic use throws and is
/// counted, so a request that reaches the global options can't produce a token.
/// </summary>
public sealed class InertCredentials
{
    public const string SigningKeyId = "inert-global-signing";
    public const string EncryptionKeyId = "inert-global-encryption";

    private int _uses;

    public InertCredentials()
    {
        var factory = new InertCryptoProviderFactory(this);

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

    /// <summary>Every attempt to sign, verify, wrap, unwrap, encrypt, decrypt or hash with an inert key.</summary>
    public int Uses => Volatile.Read(ref _uses);

    internal InertKeyUsedException Refuse(string operation)
    {
        Interlocked.Increment(ref _uses);
        return new InertKeyUsedException(operation);
    }
}

public sealed class InertKeyUsedException(string operation)
    : InvalidOperationException($"An inert global credential was used for {operation}.");

/// <summary>An asymmetric key that claims a private half it doesn't have.</summary>
internal sealed class InertAsymmetricKey : AsymmetricSecurityKey
{
    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus.")]
    public override bool HasPrivateKey => true;

    public override PrivateKeyStatus PrivateKeyStatus => PrivateKeyStatus.Exists;

    public override int KeySize => 3072;
}

internal sealed class InertCryptoProviderFactory(InertCredentials owner) : CryptoProviderFactory
{
    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) => true;

    public override bool IsSupportedAlgorithm(string algorithm) => true;

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        throw owner.Refuse("signing");

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm, bool cacheProvider) =>
        throw owner.Refuse("signing");

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        throw owner.Refuse("verifying");

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm, bool cacheProvider) =>
        throw owner.Refuse("verifying");

    public override KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm) =>
        throw owner.Refuse("key wrapping");

    public override KeyWrapProvider CreateKeyWrapProviderForUnwrap(SecurityKey key, string algorithm) =>
        throw owner.Refuse("key unwrapping");

    public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) =>
        throw owner.Refuse("encryption");

    public override HashAlgorithm CreateHashAlgorithm(string algorithm) =>
        throw owner.Refuse("hashing");

    public override HashAlgorithm CreateHashAlgorithm(HashAlgorithmName algorithm) =>
        throw owner.Refuse("hashing");

    public override KeyedHashAlgorithm CreateKeyedHashAlgorithm(byte[] keyBytes, string algorithm) =>
        throw owner.Refuse("keyed hashing");
}
