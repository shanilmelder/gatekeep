using System.Security.Cryptography;
using Gatekeep.Kernel.Secrets;
using Microsoft.IdentityModel.Tokens;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>
/// One Tenant's Signing Key as OpenIddict sees it: an RSA key that holds only the public half,
/// whose signing goes to OpenBao Transit through <see cref="IKeyCustody.SignAsync"/>. Signing
/// happens in OpenBao; verifying happens here, with the public half, because <c>Host.Hosted</c>
/// may not call Transit verify.
/// </summary>
public sealed class TransitSigning
{
    private int _signs;

    public TransitSigning(IKeyCustody custody, KeyName key, KeyPublicVersion version)
    {
        Custody = custody;
        KeyName = key;
        KeyVersion = version.KeyVersion;
        PublicParameters = PublicParametersFromPem(version.PublicKeyPem);
        KeyId = $"{key.Value}.v{version.KeyVersion}";

        SecurityKey = new RsaSecurityKey(PublicParameters)
        {
            KeyId = KeyId,
            CryptoProviderFactory = new TransitCryptoProviderFactory(this),
        };

        Credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256);
    }

    public IKeyCustody Custody { get; }

    public KeyName KeyName { get; }

    public int KeyVersion { get; }

    /// <summary>The <c>kid</c>: the Transit key name and the version that signs.</summary>
    public string KeyId { get; }

    public RSAParameters PublicParameters { get; }

    public RsaSecurityKey SecurityKey { get; }

    public SigningCredentials Credentials { get; }

    /// <summary>How many times OpenIddict asked Transit to sign.</summary>
    public int Signs => Volatile.Read(ref _signs);

    /// <summary>A plain public key with the default crypto, for verifying outside OpenIddict.</summary>
    public RsaSecurityKey VerificationKey() => new(PublicParameters) { KeyId = KeyId };

    /// <summary>
    /// Story 2.3 must do this without <c>RSA.Create</c> or <c>ImportFromPem</c> in <c>src/</c>
    /// (<c>KeyCustodyRuleTests</c>). Tests may.
    /// </summary>
    public static RSAParameters PublicParametersFromPem(string pem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.ExportParameters(includePrivateParameters: false);
    }

    /// <summary>
    /// The synchronous signature OpenIddict needs, made by blocking on the async Transit call.
    /// That blocking is the behaviour under test.
    /// </summary>
    internal byte[] SignBlocking(byte[] input)
    {
        var signature = Custody.SignAsync(KeyName, input, CancellationToken.None).GetAwaiter().GetResult();

        // The kid names a version, so a signature from any other version would be a lie.
        if (signature.KeyVersion != KeyVersion)
        {
            throw new InvalidOperationException($"Transit signed with version {signature.KeyVersion}, not {KeyVersion}.");
        }

        Interlocked.Increment(ref _signs);
        return signature.Value;
    }

    /// <summary>An RS256 signature is exactly as long as the modulus.</summary>
    internal int SignatureLength => PublicParameters.Modulus!.Length;
}

/// <summary>Hands OpenIddict a Transit signer and a local verifier for one Signing Key.</summary>
internal sealed class TransitCryptoProviderFactory(TransitSigning signing) : CryptoProviderFactory
{
    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        CreateForSigning(key, algorithm, cacheProvider: false);

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm, bool cacheProvider) =>
        algorithm == SecurityAlgorithms.RsaSha256
            ? new TransitSignatureProvider(signing, key, algorithm)
            : throw new NotSupportedException($"Signing Keys sign only {SecurityAlgorithms.RsaSha256}.");

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
        CreateForVerifying(key, algorithm, cacheProvider: true);

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm, bool cacheProvider) =>
        algorithm == SecurityAlgorithms.RsaSha256
            ? Default.CreateForVerifying(signing.VerificationKey(), algorithm, cacheProvider: false)
            : throw new NotSupportedException($"Signing Keys verify only {SecurityAlgorithms.RsaSha256}.");

    public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) =>
        algorithm == SecurityAlgorithms.RsaSha256;

    public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);
        signatureProvider.Dispose();
    }
}

internal sealed class TransitSignatureProvider : SignatureProvider
{
    private readonly TransitSigning _signing;

    public TransitSignatureProvider(TransitSigning signing, SecurityKey key, string algorithm)
        : base(key, algorithm)
    {
        _signing = signing;
        WillCreateSignatures = true;
    }

    public override byte[] Sign(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return _signing.SignBlocking(input);
    }

    public override byte[] Sign(byte[] input, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(input);
        return _signing.SignBlocking(input.AsSpan(offset, count).ToArray());
    }

    public override bool Sign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        // A buffer too small for the signature gets no Transit call at all.
        if (destination.Length < _signing.SignatureLength)
        {
            bytesWritten = 0;
            return false;
        }

        var signature = _signing.SignBlocking(data.ToArray());
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
