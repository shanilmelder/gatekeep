using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Core;

namespace Gatekeep.Modules.Keys.Contracts;

/// <summary>What other modules use to reach a Tenant's keys (AD-10).</summary>
public static class KeysContract
{
    /// <summary>
    /// A Tenant's six secret class keys, one per <see cref="TenantKeyClass"/> in enum order:
    /// <c>totp-</c>, <c>social-</c>, <c>email-</c>, <c>payload-</c>, <c>hmac-</c> and <c>tpk-{tenantId}</c>.
    /// They have no row (AD-10): only Tenant creation and deletion create or destroy them.
    /// </summary>
    public static IReadOnlyList<KeyName> SecretClassKeys(Guid tenantId) =>
        [.. Enum.GetValues<TenantKeyClass>().Select(c => KeyName.ForTenant(c, tenantId))];

    /// <summary>
    /// Creates <see cref="SecretClassKeys"/> through <paramref name="custody"/>, in order. Only
    /// <c>Host.Worker</c>'s custody policy may (AD-10). Creating a name that exists returns it
    /// unchanged, so a repeat is harmless. No row is written, and no other key is ever created here.
    /// </summary>
    /// <exception cref="KeyCustodyException">Custody refused or couldn't be reached. Keys created before it stay.</exception>
    public static async Task CreateSecretClassKeysAsync(IKeyCustody custody, Guid tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(custody);

        foreach (var key in SecretClassKeys(tenantId))
        {
            await custody.CreateKeyAsync(key, cancellationToken);
        }
    }

    /// <summary>The Tenant's token protection key's wrap key, <c>tpk-{tenantId}</c> (AD-10).</summary>
    public static KeyName TokenProtectionKey(Guid tenantId) => KeyName.ForTenant(TenantKeyClass.TokenProtection, tenantId);

    /// <summary>
    /// Gives the Tenant every key it lacks (Story 2.3, AD-10, AD-11), in its own
    /// <paramref name="context"/>: a <c>current</c> and a <c>next</c> Transit key for each purpose,
    /// <c>signing</c> and <c>management</c> (RS256, RSA-3072), and its token protection key, made by
    /// Transit and stored only wrapped. Each key is created in Transit first, from a fresh row ID,
    /// and its row inserted after; the <c>signing</c> rows are published at insert. One
    /// <see cref="KeysEvents.TenantKeysProvisioned"/> is written when anything was created, and
    /// nothing at all when the Tenant already has every key, so a repeat changes nothing. Only
    /// <c>Host.Worker</c>'s custody policy may create keys. Tenant creation and the hourly backfill
    /// both call this, and nothing else creates these keys.
    /// </summary>
    /// <returns>Whether anything was created.</returns>
    /// <exception cref="KeyCustodyException">
    /// Custody refused or couldn't be reached. Every row this call wrote is taken back; Transit keys
    /// it made stay, unnamed by any row.
    /// </exception>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    public static Task<bool> EnsureTenantKeysAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Guid tenantId,
        CancellationToken cancellationToken) =>
        TenantKeys.EnsureAsync(context, custody, appender, tenantId, cancellationToken);

    /// <summary>
    /// The Signing Keys the context's Tenant publishes in its JWKS: its <c>signing</c> rows in
    /// <c>current</c>, <c>next</c> or <c>previous</c>, current first. Never a <c>management</c> key.
    /// It only reads, so <c>gk_hosted</c> may run it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<IReadOnlyList<PublishedSigningKey>> ReadPublishedSigningKeysAsync(CommandContext context, CancellationToken cancellationToken) =>
        TenantKeys.ReadPublishedAsync(context, cancellationToken);

    /// <summary>
    /// The context's Tenant's token protection key, as Transit wrapped it under
    /// <see cref="TokenProtectionKey"/>, or null when it has none yet. It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<KeyCiphertext?> ReadProtectionKeyWrapAsync(CommandContext context, CancellationToken cancellationToken) =>
        TenantKeys.ReadWrapAsync(context, cancellationToken);

    /// <summary>
    /// The modulus and exponent of a Signing Key's public half, from the PEM custody returns
    /// (SubjectPublicKeyInfo or PKCS#1), decoded without the PEM import APIs (AD-10).
    /// </summary>
    /// <exception cref="FormatException">The text isn't an RSA public key.</exception>
    public static RSAParameters RsaPublicParameters(string publicKeyPem) => RsaPublicKeys.Parse(publicKeyPem);
}
