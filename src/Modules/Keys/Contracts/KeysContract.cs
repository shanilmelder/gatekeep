using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Jobs;
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

    /// <summary>
    /// Destroys <see cref="SecretClassKeys"/> through <paramref name="custody"/>, in order, with every
    /// version of each (Story 1.29). Only <c>Host.Worker</c>'s and the Cli's custody policies may
    /// (AD-10). A key already gone counts as destroyed, so a repeat, or a rerun after a failure part
    /// way, is harmless. No other key is ever destroyed here.
    /// </summary>
    /// <exception cref="KeyCustodyException">Custody refused or couldn't be reached. Keys destroyed before it stay destroyed.</exception>
    public static async Task DestroySecretClassKeysAsync(IKeyCustody custody, Guid tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(custody);

        foreach (var key in SecretClassKeys(tenantId))
        {
            await custody.DeleteAsync(key, cancellationToken);
        }
    }

    /// <summary>
    /// Destroys every Signing and Management Transit key of <paramref name="tenantId"/>, in any state,
    /// with every version of each (Story 1.29, after Story 2.3), in the Tenant's own
    /// <paramref name="context"/>: those its <c>signing_key</c> rows name, and those custody lists under
    /// its ID. Only <c>Host.Worker</c>'s custody policy may list keys (AD-10). A key already gone counts
    /// as destroyed, so a repeat is harmless. No row is changed, and no other Tenant's key is touched.
    /// </summary>
    /// <exception cref="KeyCustodyException">Custody refused or couldn't be reached. Keys destroyed before it stay destroyed.</exception>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    public static Task DestroyTenantRowKeysAsync(CommandContext context, IKeyCustody custody, Guid tenantId, CancellationToken cancellationToken) =>
        KeysPurge.DestroyRowKeysAsync(context, custody, tenantId, cancellationToken);

    /// <summary>
    /// Keys' Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>signing_key</c> and
    /// <c>protection_key_wrap</c> rows. The Transit keys are <see cref="DestroyTenantRowKeysAsync"/>'s.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new KeysPurge();

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

    /// <summary>The ID a <c>keys.signing_key.destroy</c> job's payload carries: the retired <c>signing_key</c> row's.</summary>
    public const string DestroyPayloadId = SigningKeyLifecycle.DestroyPayloadId;

    /// <summary>
    /// The <c>NOTIFY</c> channel a committed rotation or retirement signals on, with the Tenant ID as
    /// payload, so Host.Hosted drops that Tenant's runtime at once (Story 2.4).
    /// </summary>
    public const string SigningKeysChannel = SigningKeyLifecycle.Channel;

    /// <summary>
    /// The daily rotation of one Tenant, in its own <paramref name="context"/> (Story 2.4, AD-11), under
    /// the same per-Tenant lock as <see cref="EnsureTenantKeysAsync"/>. For each purpose whose
    /// <c>current</c> key is at least 150 days old by database time (from its <c>created_at</c>), and
    /// whose <c>next</c> qualifies (a <c>signing</c> one published at least 15 minutes ago; a
    /// <c>management</c> one at once), <c>current</c> becomes <c>previous</c>, <c>next</c> becomes
    /// <c>current</c>, and a new <c>next</c> is created in Transit first and then inserted. Each
    /// <c>previous</c> rotated at least 1 hour 15 minutes ago becomes <c>retired</c>, with
    /// <paramref name="destroyJob"/> enqueued for it through <paramref name="enqueuer"/>, and any retired,
    /// undestroyed row with no such job pending or running (one that went dead) gets a fresh one. One audit
    /// event per state change, and one <see cref="SigningKeysChannel"/> notification when anything
    /// changed. Every row stays one <c>current</c> and one <c>next</c> per purpose.
    /// </summary>
    /// <returns>Whether anything changed.</returns>
    /// <exception cref="KeyCustodyException">
    /// Custody failed to create a replacement. Nothing may be committed: the caller rolls the command back.
    /// </exception>
    /// <exception cref="InvalidOperationException">The context isn't <paramref name="tenantId"/>'s.</exception>
    [StateChanging]
    public static Task<bool> RotateTenantKeysAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        IJobEnqueuer enqueuer,
        JobType destroyJob,
        Guid tenantId,
        CancellationToken cancellationToken) =>
        SigningKeyLifecycle.RotateAsync(context, custody, appender, enqueuer, destroyJob, tenantId, cancellationToken);

    /// <summary>
    /// The Tenant Owner's rotation of the Tenant's Signing Key now (Story 9.2, FR-37), in its own
    /// <paramref name="context"/>, under the same per-Tenant lock as <see cref="RotateTenantKeysAsync"/>
    /// and <see cref="EnsureTenantKeysAsync"/>. Only the <c>signing</c> purpose: once its <c>next</c> has
    /// been published for at least 15 minutes by database time, a new <c>next</c> is created in Transit
    /// first, then <c>current</c> becomes <c>previous</c>, <c>next</c> becomes <c>current</c> and the new
    /// row is inserted, with <see cref="KeysEvents.SigningKeyRotated"/>, <see cref="KeysEvents.SigningKeyPromoted"/>
    /// and <see cref="KeysEvents.SigningKeyCreated"/> written as <paramref name="actor"/>, and one
    /// <see cref="SigningKeysChannel"/> notification. A younger <c>next</c> is
    /// <see cref="SigningKeyRotationStatus.NotReady"/> with the time left, and nothing is written.
    /// <c>current</c>'s age is never checked, and nothing is retired, destroyed or enqueued.
    /// </summary>
    /// <exception cref="KeyCustodyException">
    /// Custody failed to create the replacement. Nothing may be committed: the caller rolls the command back.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The context isn't <paramref name="tenantId"/>'s, or the Tenant has no signing <c>current</c> or <c>next</c>.
    /// </exception>
    [StateChanging]
    public static Task<SigningKeyRotation> RotateSigningKeyNowAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Actor actor,
        Guid tenantId,
        CancellationToken cancellationToken) =>
        SigningKeyLifecycle.RotateNowAsync(context, custody, appender, actor, tenantId, cancellationToken);

    /// <summary>
    /// Destroys a retired key's Transit key (Story 2.4), in its Tenant's own <paramref name="context"/>.
    /// The row is re-read and locked: only a <c>retired</c> row not yet destroyed is acted on, and
    /// then its Transit key is deleted, <c>destroyed_at</c> set and one event written. Any other row,
    /// or none, is left alone and false returned. No other row or key is touched.
    /// </summary>
    /// <returns>Whether the key was destroyed now.</returns>
    /// <exception cref="KeyCustodyException">
    /// Custody failed to delete the key. The caller rolls back, commits
    /// <see cref="RecordDestructionFailedAsync"/> in a fresh scope, and retries.
    /// </exception>
    [StateChanging]
    public static Task<bool> DestroyRetiredKeyAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        Guid tenantId,
        Guid signingKeyId,
        CancellationToken cancellationToken) =>
        SigningKeyLifecycle.DestroyAsync(context, custody, appender, tenantId, signingKeyId, cancellationToken);

    /// <summary>Writes <see cref="KeysEvents.SigningKeyDestructionFailed"/> on the context's Tenant's chain.</summary>
    [StateChanging]
    public static Task RecordDestructionFailedAsync(CommandContext context, IAuditAppender appender, CancellationToken cancellationToken) =>
        SigningKeyLifecycle.RecordDestructionFailedAsync(context, appender, cancellationToken);

    /// <summary>
    /// Whether the orphan sweep may consider a listed key (Story 2.4): its name parses as
    /// <c>sig-{tenantId}-{rowId}</c> or <c>mgmt-{tenantId}-{rowId}</c>, and custody created it at least
    /// 24 hours before <paramref name="now"/>. Never a secret class or Deployment key.
    /// </summary>
    public static bool IsOrphanCandidate(ListedKey listed, DateTimeOffset now) => SigningKeyLifecycle.IsSweepCandidate(listed, now);

    /// <summary>
    /// Whether a <c>signing_key</c> row names <paramref name="key"/>, read in the key's own Tenant's
    /// <paramref name="context"/>. It only reads.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="key"/> isn't a Signing or Management key.</exception>
    /// <exception cref="InvalidOperationException">The context isn't the key's Tenant's.</exception>
    public static Task<bool> IsKeyNamedAsync(CommandContext context, KeyName key, CancellationToken cancellationToken) =>
        SigningKeyLifecycle.IsNamedAsync(context, key, cancellationToken);

    /// <summary>
    /// Deletes an orphaned Signing or Management key from custody and writes
    /// <see cref="KeysEvents.OrphanKeySwept"/> on the Deployment's chain, in its Deployment
    /// <paramref name="context"/>. The caller has already found it old enough and named by no row.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="key"/> isn't a Signing or Management key.</exception>
    [StateChanging]
    public static Task RemoveOrphanKeyAsync(
        CommandContext context,
        IKeyCustody custody,
        IAuditAppender appender,
        KeyName key,
        CancellationToken cancellationToken) =>
        SigningKeyLifecycle.RemoveOrphanAsync(context, custody, appender, key, cancellationToken);

    /// <summary>
    /// The Signing Keys the context's Tenant publishes in its JWKS: its <c>signing</c> rows in
    /// <c>current</c>, <c>next</c> or <c>previous</c>, current first. Never a <c>management</c> key.
    /// It only reads, so <c>gk_hosted</c> may run it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<IReadOnlyList<PublishedSigningKey>> ReadPublishedSigningKeysAsync(CommandContext context, CancellationToken cancellationToken) =>
        TenantKeys.ReadPublishedAsync(context, cancellationToken);

    /// <summary>
    /// Every Signing Key of the context's Tenant, for the Signing keys page (Story 9.1): its
    /// <c>signing</c> rows in any state, <c>next</c>, then <c>current</c>, then <c>previous</c>, then
    /// <c>retired</c> and <c>revoked</c> together, newest first. A retired row is listed whether or not
    /// its Transit key is destroyed. Never a <c>management</c> key. It only reads, so <c>gk_admin</c> may
    /// run it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or a row names a Transit key that isn't its own.</exception>
    public static Task<IReadOnlyList<ListedSigningKey>> ListSigningKeysAsync(CommandContext context, CancellationToken cancellationToken) =>
        TenantKeys.ListAsync(context, cancellationToken);

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
