using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Custody;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>One Tenant as the spike stores it: what a <c>tenant</c> and <c>signing_key</c> row would hold.</summary>
public sealed record SpikeTenant(
    Guid Id,
    string Host,
    Uri Issuer,
    KeyName SigningKey,
    KeyName TokenProtectionKey,
    KeyCiphertext WrappedTokenProtectionKey);

/// <summary>
/// Two Tenants made the way <c>Host.Worker</c> will make them: a fresh Signing Key and a random
/// 256-bit token protection key wrapped by <c>tpk-{tenant}</c>. Host to Tenant is an in-memory
/// map standing in for <c>tenant_host</c>, which Story 2.3 resolves from the database.
/// </summary>
public sealed class SpikeTenants
{
    public const string HostA = "a.spike.test";
    public const string HostB = "b.spike.test";

    private readonly Dictionary<string, SpikeTenant> _byHost;

    private SpikeTenants(SpikeTenant a, SpikeTenant b)
    {
        A = a;
        B = b;
        _byHost = new(StringComparer.OrdinalIgnoreCase) { [a.Host] = a, [b.Host] = b };
    }

    public SpikeTenant A { get; }

    public SpikeTenant B { get; }

    public IEnumerable<SpikeTenant> All => [A, B];

    /// <summary>Exact match ignoring case, on the host without its port (the caller drops it).</summary>
    public bool TryResolve(string host, out SpikeTenant tenant) => _byHost.TryGetValue(host, out tenant!);

    public static async Task<SpikeTenants> CreateAsync(OpenBaoFixture bao, CancellationToken cancellationToken)
    {
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        return new SpikeTenants(
            await CreateAsync(worker, HostA, cancellationToken),
            await CreateAsync(worker, HostB, cancellationToken));
    }

    private static async Task<SpikeTenant> CreateAsync(IKeyCustody worker, string host, CancellationToken cancellationToken)
    {
        var id = Guid.CreateVersion7();
        var signing = KeyName.Signing(id, Guid.CreateVersion7());
        var protection = KeyName.ForTenant(TenantKeyClass.TokenProtection, id);

        await worker.CreateKeyAsync(signing, cancellationToken);
        await worker.CreateKeyAsync(protection, cancellationToken);
        var wrapped = await worker.CreateWrappedDataKeyAsync(protection, id, cancellationToken);

        return new SpikeTenant(id, host, new Uri($"https://{host}/"), signing, protection, wrapped);
    }
}
