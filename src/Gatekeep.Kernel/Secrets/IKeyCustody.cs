namespace Gatekeep.Kernel.Secrets;

/// <summary>
/// A value encrypted or wrapped by key custody. It isn't a secret, but it never reaches a
/// log either, so it prints no value.
/// </summary>
public sealed class KeyCiphertext
{
    public KeyCiphertext(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    /// <summary>The stored form, including the key version.</summary>
    public string Value { get; }

    public override string ToString() => "[ciphertext]";
}

/// <summary>A signature, with the key version that made it.</summary>
public sealed record KeySignature(int KeyVersion, byte[] Value);

/// <summary>An HMAC, with the key version that made it.</summary>
public sealed record KeyHmac(int KeyVersion, byte[] Value);

/// <summary>The public half of one version of a signing key, as PEM.</summary>
public sealed record KeyPublicVersion(int KeyVersion, string PublicKeyPem);

/// <summary>A Signing or Management key that exists in custody, and when custody created it.</summary>
public sealed record ListedKey(KeyName Key, DateTimeOffset CreatedAt);

/// <summary>
/// The only way to reach a key (AD-10). Keys stay in custody and are never exported:
/// signing, encryption and HMAC happen there, and only a wrapped data key ever leaves.
/// Each host's custody login allows only the operations AD-10 grants it, so a call
/// outside them throws <see cref="KeyCustodyException"/> with <see cref="KeyCustodyFailure.Refused"/>.
/// </summary>
public interface IKeyCustody
{
    /// <summary>
    /// Creates a non-exportable key of the type its name implies. For a signing key it
    /// returns the public halves, so a host with no read grant can store them. Creating a
    /// name that already exists returns the existing key unchanged, so callers must name
    /// Signing and Management keys from fresh row IDs.
    /// </summary>
    Task<IReadOnlyList<KeyPublicVersion>> CreateKeyAsync(KeyName key, CancellationToken cancellationToken);

    /// <summary>Signs <paramref name="data"/> with RS256 under the key's latest version.</summary>
    Task<KeySignature> SignAsync(KeyName key, ReadOnlyMemory<byte> data, CancellationToken cancellationToken);

    Task<bool> VerifyAsync(
        KeyName key,
        ReadOnlyMemory<byte> data,
        KeySignature signature,
        CancellationToken cancellationToken);

    /// <summary>
    /// Encrypts under an AEAD key, binding the ciphertext to <paramref name="tenantId"/> as
    /// associated data. Pass the key's own Tenant for a Tenant key, and
    /// <see langword="null"/> for a Deployment key; anything else throws <see cref="ArgumentException"/>.
    /// </summary>
    Task<KeyCiphertext> EncryptAsync(
        KeyName key,
        Guid? tenantId,
        Secret<byte[]> plaintext,
        CancellationToken cancellationToken);

    /// <summary>Decrypts at the moment of use. A ciphertext bound to another Tenant is rejected.</summary>
    Task<Secret<byte[]>> DecryptAsync(
        KeyName key,
        Guid? tenantId,
        KeyCiphertext ciphertext,
        CancellationToken cancellationToken);

    Task<KeyHmac> HmacAsync(KeyName key, Secret<byte[]> input, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a random 256-bit data key and returns it only wrapped, bound to
    /// <paramref name="tenantId"/>. <see cref="DecryptAsync"/> unwraps it.
    /// </summary>
    Task<KeyCiphertext> CreateWrappedDataKeyAsync(KeyName key, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Adds a new key version. Older versions still decrypt and verify.</summary>
    Task RotateAsync(KeyName key, CancellationToken cancellationToken);

    /// <summary>
    /// Re-encrypts a ciphertext under the key's latest version, without revealing it.
    /// OpenBao 2.7.2 rewrap takes no associated data, so today every Gatekeep ciphertext is
    /// <see cref="KeyCustodyFailure.Rejected"/> here: see G-16 in <c>docs/threat-model.md</c>.
    /// </summary>
    Task<KeyCiphertext> RewrapAsync(
        KeyName key,
        Guid? tenantId,
        KeyCiphertext ciphertext,
        CancellationToken cancellationToken);

    /// <summary>
    /// Destroys the key and every version of it. A key that doesn't exist counts as destroyed, so a
    /// repeat is harmless (Story 1.29).
    /// </summary>
    Task DeleteAsync(KeyName key, CancellationToken cancellationToken);

    Task<IReadOnlyList<KeyPublicVersion>> GetPublicKeysAsync(KeyName key, CancellationToken cancellationToken);

    /// <summary>
    /// Every key in custody whose name is a <c>sig-</c> or <c>mgmt-</c> row key
    /// (<see cref="KeyName.TryParseRowKey"/>), with when its first version was created (Story 2.4).
    /// Any other name is skipped without being read, and a row key that can't be read (deleted
    /// meanwhile, refused, unavailable or with no creation time) is left out rather than failing the list. A failed list itself throws.
    /// Only <c>Host.Worker</c>'s custody policy may list keys.
    /// </summary>
    Task<IReadOnlyList<ListedKey>> ListRowKeysAsync(CancellationToken cancellationToken);
}
