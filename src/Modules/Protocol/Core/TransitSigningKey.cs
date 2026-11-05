using System.Security.Cryptography;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// One published Signing Key as OpenIddict sees it (AD-10): an RSA key holding only the public
/// half, with <c>kid = {transit key name}.v{version}</c>. Only the <c>current</c> key can sign,
/// and its signing goes to Transit through <see cref="IKeyCustody.SignAsync"/>, bounded by the
/// custody timeout. Verifying uses the public half here, because Host.Hosted can't call Transit
/// verify. No private key material is ever in this process.
/// </summary>
internal sealed class TransitSigningKey
{
    public TransitSigningKey(IKeyCustody custody, PublishedSigningKey published, RSAParameters publicParameters)
    {
        Custody = custody;
        Published = published;
        PublicParameters = publicParameters;

        SecurityKey = new RsaSecurityKey(publicParameters)
        {
            KeyId = published.KeyId,
            CryptoProviderFactory = new TransitCryptoProviderFactory(this),
        };

        Credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256);
    }

    public IKeyCustody Custody { get; }

    public PublishedSigningKey Published { get; }

    public RSAParameters PublicParameters { get; }

    public RsaSecurityKey SecurityKey { get; }

    public SigningCredentials Credentials { get; }

    /// <summary>Only the current key signs: next and previous are published to verify with only.</summary>
    public bool CanSign => Published.State == PublishedKeyState.Current;

    /// <summary>A plain public key with the default crypto, for Wilson's own verifier.</summary>
    public RsaSecurityKey VerificationKey() => new(PublicParameters) { KeyId = Published.KeyId };

    /// <summary>An RS256 signature is exactly as long as the modulus.</summary>
    public int SignatureLength => PublicParameters.Modulus!.Length;

    /// <summary>
    /// The synchronous signature Wilson asks for, made by blocking on Transit. Story 2.5 must
    /// load-test this before the token endpoint ships (Story 2.1 spike).
    /// </summary>
    public byte[] SignBlocking(byte[] input)
    {
        if (!CanSign)
        {
            throw new InvalidOperationException("Only the current Signing Key signs.");
        }

        using var limit = new CancellationTokenSource(SecurityLimits.KeyCustodyCallTimeout);
        KeySignature signature;
        try
        {
            signature = Custody.SignAsync(Published.Key, input, limit.Token).WaitAsync(limit.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (limit.IsCancellationRequested)
        {
            throw new TimeoutException("Key custody didn't sign in time.");
        }

        // The kid names a version, so a signature from any other version would be a lie.
        if (signature.KeyVersion != Published.Version)
        {
            throw new InvalidOperationException("Transit signed with a version the kid doesn't name.");
        }

        return signature.Value;
    }
}

/// <summary>Hands Wilson a Transit signer and a local verifier for one Signing Key, RS256 only.</summary>
internal sealed class TransitCryptoProviderFactory(TransitSigningKey key) : CryptoProviderFactory
{
    public override SignatureProvider CreateForSigning(SecurityKey securityKey, string algorithm) =>
        CreateForSigning(securityKey, algorithm, cacheProvider: false);

    public override SignatureProvider CreateForSigning(SecurityKey securityKey, string algorithm, bool cacheProvider) =>
        algorithm == SecurityAlgorithms.RsaSha256 && key.CanSign
            ? new TransitSignatureProvider(key, securityKey, algorithm)
            : throw new NotSupportedException("This Signing Key doesn't sign with that algorithm.");

    public override SignatureProvider CreateForVerifying(SecurityKey securityKey, string algorithm) =>
        CreateForVerifying(securityKey, algorithm, cacheProvider: true);

    public override SignatureProvider CreateForVerifying(SecurityKey securityKey, string algorithm, bool cacheProvider) =>
        algorithm == SecurityAlgorithms.RsaSha256
            ? Default.CreateForVerifying(key.VerificationKey(), algorithm, cacheProvider: false)
            : throw new NotSupportedException($"Signing Keys verify only {SecurityAlgorithms.RsaSha256}.");

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey securityKey) =>
        algorithm == SecurityAlgorithms.RsaSha256;

    public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);
        signatureProvider.Dispose();
    }
}

internal sealed class TransitSignatureProvider : SignatureProvider
{
    private readonly TransitSigningKey _key;

    public TransitSignatureProvider(TransitSigningKey key, SecurityKey securityKey, string algorithm)
        : base(securityKey, algorithm)
    {
        _key = key;
        WillCreateSignatures = true;
    }

    public override byte[] Sign(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return _key.SignBlocking(input);
    }

    public override byte[] Sign(byte[] input, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(input);
        return _key.SignBlocking(input.AsSpan(offset, count).ToArray());
    }

    public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        // A buffer too small for the signature gets no Transit call at all.
        if (destination.Length < _key.SignatureLength)
        {
            bytesWritten = 0;
            return false;
        }

        var signature = _key.SignBlocking(data.ToArray());
        signature.AsSpan().CopyTo(destination);
        bytesWritten = signature.Length;
        return true;
    }

    public override bool Verify(byte[] input, byte[] signature) =>
        throw new NotSupportedException("Transit signers don't verify: the public half does.");

    public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength) =>
        throw new NotSupportedException("Transit signers don't verify: the public half does.");

    protected override void Dispose(bool disposing)
    {
    }
}
