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
        "A Tenant's missing Signing Keys, Management keys or token protection key were created in key custody. Names no key.");
}
