using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Keys.Contracts;

/// <summary>
/// The audit events Keys writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break. None holds a key
/// name, a key version, key material or a ciphertext.
/// </summary>
public static class KeysEvents
{
    /// <summary>
    /// Written on the Tenant's own chain, with a <c>system</c> Actor, in the transaction that inserts
    /// the rows, whenever <see cref="KeysContract.EnsureTenantKeysAsync"/> created anything (Story 2.3):
    /// from Tenant creation or from the hourly backfill. A run that finds everything in place writes none.
    /// </summary>
    public static readonly AuditEventDefinition TenantKeysProvisioned = new(
        new AuditTypeCode("keys.tenant_keys.provisioned"),
        "A Tenant's missing Signing Keys, Management keys or token protection key were created in key custody. Names no key.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Tenant's chain in the transaction that moves a <c>current</c> key to <c>previous</c>:
    /// by the daily rotation (Story 2.4), with a <c>system</c> Actor, once the key reached its rotation
    /// age, or by a Tenant Owner's rotation on demand (Story 9.2), with that Admin as Actor.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyRotated = new(
        new AuditTypeCode("keys.signing_key.rotated"),
        "A Tenant's Signing or Management key was rotated, by the daily rotation or a Tenant Owner: current became previous. Names no key.",
        AuditOutcome.Success,
        TenantLogClass.KeyOperation);

    /// <summary>
    /// Written by either rotation in the same transaction, with the same Actor, as the <c>next</c> key
    /// becomes <c>current</c>; and by a revocation of <c>current</c> (Story 9.3) when <c>next</c> had been
    /// published for at least the 15-minute JWKS cache limit.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyPromoted = new(
        new AuditTypeCode("keys.signing_key.promoted"),
        "A Tenant's next Signing or Management key became current. Names no key.",
        AuditOutcome.Success,
        TenantLogClass.KeyOperation);

    /// <summary>
    /// Written by either rotation, or a revocation of <c>current</c> or <c>next</c> (Story 9.3), in the same
    /// transaction, with the same Actor, for the new <c>next</c> key it created.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyCreated = new(
        new AuditTypeCode("keys.signing_key.created"),
        "A Tenant's replacement next Signing or Management key was created in key custody. Names no key.",
        AuditOutcome.Success,
        TenantLogClass.KeyOperation);

    /// <summary>
    /// Written on the Tenant's chain, with the Tenant Owner as Actor, in the transaction that revokes a
    /// published Signing Key (Story 9.3) and enqueues its destruction.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyRevoked = new(
        new AuditTypeCode("keys.signing_key.revoked"),
        "A Tenant Owner revoked a Signing Key: it left the JWKS and its private material is queued for destruction. Names no key.",
        AuditOutcome.Success,
        TenantLogClass.KeyOperation);

    /// <summary>
    /// Written by a revocation of <c>current</c> (Story 9.3), in place of <see cref="SigningKeyPromoted"/>,
    /// when <c>next</c> had been published for less than the 15-minute JWKS cache limit by database time.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyPromotedUnaged = new(
        new AuditTypeCode("keys.signing_key.promoted_unaged"),
        "A revoked Signing Key's next key became current before it had been published for 15 minutes; relying parties may not have it yet. Names no key.",
        AuditOutcome.Success,
        TenantLogClass.KeyOperation);

    /// <summary>
    /// Written by the daily rotation when a <c>previous</c> key's signed tokens have all expired: it
    /// leaves JWKS and its destruction job is enqueued in the same transaction.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyRetired = new(
        new AuditTypeCode("keys.signing_key.retired"),
        "A Tenant's previous Signing or Management key retired and its destruction was queued. Names no key.",
        AuditOutcome.Success);

    /// <summary>Written by the destruction job once a retired or revoked key's Transit key is deleted.</summary>
    public static readonly AuditEventDefinition SigningKeyDestroyed = new(
        new AuditTypeCode("keys.signing_key.destroyed"),
        "A Tenant's retired or revoked Signing or Management key was destroyed in key custody. Names no key.",
        AuditOutcome.Success);

    /// <summary>
    /// Kept by the destruction job, though its own changes are undone, when key custody failed to delete the key;
    /// the job then retries. Epic 11 alerts on it.
    /// </summary>
    public static readonly AuditEventDefinition SigningKeyDestructionFailed = new(
        new AuditTypeCode("keys.signing_key.destruction_failed"),
        "Key custody failed to destroy a Tenant's retired or revoked Signing or Management key; the destruction retries. Names no key.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the Deployment's chain, with a <c>system</c> Actor, by the daily orphan sweep for each
    /// <c>sig-</c> or <c>mgmt-</c> Transit key it deleted: one key custody created at least 24 hours earlier
    /// that no <c>signing_key</c> row named when the sweep checked.
    /// </summary>
    public static readonly AuditEventDefinition OrphanKeySwept = new(
        new AuditTypeCode("keys.transit_key.swept"),
        "A Signing or Management key at least 24 hours old, named by no row when checked, was deleted from key custody. Names no key.",
        AuditOutcome.Success);
}
