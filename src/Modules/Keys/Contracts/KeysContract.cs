using Gatekeep.Kernel.Secrets;

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
}
