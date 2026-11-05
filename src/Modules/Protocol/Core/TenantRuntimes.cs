using System.Collections.Concurrent;
using System.Security.Cryptography;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>What a Tenant's runtime is built from: its published Signing Keys and its wrapped token protection key.</summary>
internal sealed record TenantKeyMaterial(IReadOnlyList<PublishedSigningKey> SigningKeys, KeyCiphertext? ProtectionKeyWrap);

/// <summary>Reads <see cref="TenantKeyMaterial"/> as <c>gk_hosted</c>, in a short read-only Tenant scope.</summary>
internal interface ITenantKeyReader
{
    Task<TenantKeyMaterial> ReadAsync(Guid tenantId, CancellationToken cancellationToken);
}

/// <summary>A Tenant's OpenIddict options and the keys behind them.</summary>
internal sealed record TenantRuntime(Guid TenantId, Uri Issuer, OpenIddictServerOptions Options, IReadOnlyList<TransitSigningKey> SigningKeys);

/// <summary>
/// Builds and keeps each Tenant's runtime (Story 2.3, AD-8, AD-11). A copy of the options comes
/// from the same options pipeline as the global ones, so the handler list, degraded mode and every
/// Deployment-wide setting are identical; it then gets the Tenant's stored issuer, its published
/// Signing Keys, through Transit, and its unwrapped token protection key, in place of the inert
/// credentials, with the validation keys set explicitly. A runtime is kept for at most
/// <see cref="SecurityLimits.TenantRuntimeLifetime"/>, and a timer drops it then even if no request
/// comes, so a quiet Tenant's unwrapped protection key isn't kept; one whose build failed is dropped
/// at once, so the next request builds again. Concurrent requests share one build.
/// </summary>
internal sealed class TenantRuntimes(
    IOptionsFactory<OpenIddictServerOptions> factory,
    ITenantKeyReader reader,
    IServiceProvider services,
    TimeProvider time) : ITenantServerOptions
{
    /// <summary>An RSA-3072 modulus, in bytes.</summary>
    private const int RsaModulusBytes = 3072 / 8;

    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();

    public async ValueTask<OpenIddictServerOptions> GetAsync(ResolvedTenant tenant, CancellationToken cancellationToken) =>
        (await GetRuntimeAsync(tenant, cancellationToken)).Options;

    public async ValueTask<TenantRuntime> GetRuntimeAsync(ResolvedTenant tenant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tenant);

        while (true)
        {
            var entry = _entries.GetOrAdd(tenant.TenantId, _ => new Entry(e => BuildKeptAsync(tenant, e), time.GetTimestamp()));

            // Measured from the build's start, so no runtime outlives the keys it read by more than the lifetime.
            if (time.GetElapsedTime(entry.Started) >= SecurityLimits.TenantRuntimeLifetime)
            {
                Evict(tenant.TenantId, entry);
                continue;
            }

            try
            {
                return await entry.Build.Value.WaitAsync(cancellationToken);
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                // Never kept: the next request builds again.
                Evict(tenant.TenantId, entry);
                throw;
            }
        }
    }

    /// <summary>The Tenants whose runtime is kept now, built or being built.</summary>
    public int Kept => _entries.Count;

    /// <summary>Builds, then schedules the entry's removal for when its lifetime ends.</summary>
    private async Task<TenantRuntime> BuildKeptAsync(ResolvedTenant tenant, Entry entry)
    {
        var runtime = await BuildAsync(tenant);

        var remaining = SecurityLimits.TenantRuntimeLifetime - time.GetElapsedTime(entry.Started);
        entry.Expiry = time.CreateTimer(
            _ => Evict(tenant.TenantId, entry),
            state: null,
            remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero,
            Timeout.InfiniteTimeSpan);

        return runtime;
    }

    private void Evict(Guid tenantId, Entry entry)
    {
        if (_entries.TryRemove(KeyValuePair.Create(tenantId, entry)))
        {
            entry.Expiry?.Dispose();
        }
    }

    private async Task<TenantRuntime> BuildAsync(ResolvedTenant tenant)
    {
        var issuer = ProtocolIssuer.Parse(tenant.Issuer);

        // Its own bound, not one request's: other requests may be waiting on this build.
        var material = await Bounded(token => reader.ReadAsync(tenant.TenantId, token), "The Tenant's keys weren't read in time.");

        var custody = material.SigningKeys.Count == 0 && material.ProtectionKeyWrap is null
            ? null
            : services.GetService<IKeyCustody>()
                ?? throw new KeyCustodyException("custody", KeyOperation.ReadPublicKey, KeyCustodyFailure.Unavailable);

        var signingKeys = new List<TransitSigningKey>(material.SigningKeys.Count);
        foreach (var published in material.SigningKeys)
        {
            var versions = await Bounded(
                token => custody!.GetPublicKeysAsync(published.Key, token),
                "Key custody didn't return a public key in time.");

            // The row names the version its kid carries; any other is never published as that kid.
            var version = versions.SingleOrDefault(v => v.KeyVersion == published.Version)
                ?? throw new InvalidOperationException("Key custody has no public half for a Signing Key's version.");

            // RS256 with RSA-3072 is Deployment-wide (AD-9): any other key size is a misconfigured key, never published.
            var parameters = KeysContract.RsaPublicParameters(version.PublicKeyPem);
            if (parameters.Modulus!.Length != RsaModulusBytes)
            {
                throw new InvalidOperationException("A Signing Key isn't RSA-3072.");
            }

            signingKeys.Add(new TransitSigningKey(custody!, published, parameters));
        }

        SymmetricSecurityKey? protection = null;
        if (material.ProtectionKeyWrap is { } wrap)
        {
            var name = KeysContract.TokenProtectionKey(tenant.TenantId);
            var unwrapped = await Bounded(
                token => custody!.DecryptAsync(name, tenant.TenantId, wrap, token),
                "Key custody didn't unwrap the token protection key in time.");

            protection = unwrapped.Use(bytes =>
            {
                var key = new SymmetricSecurityKey(bytes.ToArray()) { KeyId = name.Value };
                CryptographicOperations.ZeroMemory(bytes);
                return key;
            });
        }

        var options = factory.Create(Options.DefaultName);
        options.Issuer = issuer;

        // The current key first: OpenIddict signs with the first signing credential that fits.
        options.SigningCredentials.Clear();
        foreach (var key in signingKeys.OrderBy(k => k.CanSign ? 0 : 1))
        {
            options.SigningCredentials.Add(key.Credentials);
        }

        options.EncryptionCredentials.Clear();
        if (protection is not null)
        {
            options.EncryptionCredentials.Add(new EncryptingCredentials(
                protection, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
        }

        // OpenIddict wires these lazily to the credential lists of the options it built, so a copy
        // must set them itself or it would still validate with the inert keys (Story 2.1).
        options.TokenValidationParameters.IssuerSigningKeys = [.. signingKeys.Select(k => k.SecurityKey)];
        options.TokenValidationParameters.TokenDecryptionKeys = protection is null ? [] : [protection];

        return new TenantRuntime(tenant.TenantId, issuer, options, signingKeys);
    }

    private static async Task<T> Bounded<T>(Func<CancellationToken, Task<T>> call, string timeout)
    {
        using var limit = new CancellationTokenSource(SecurityLimits.KeyCustodyCallTimeout);
        try
        {
            return await call(limit.Token).WaitAsync(limit.Token);
        }
        catch (OperationCanceledException) when (limit.IsCancellationRequested)
        {
            throw new TimeoutException(timeout);
        }
    }

    private sealed class Entry
    {
        public Entry(Func<Entry, Task<TenantRuntime>> build, long started)
        {
            Build = new(() => build(this), LazyThreadSafetyMode.ExecutionAndPublication);
            Started = started;
        }

        public Lazy<Task<TenantRuntime>> Build { get; }

        public long Started { get; }

        /// <summary>Drops the entry when its lifetime ends. Set once the build has succeeded.</summary>
        public ITimer? Expiry { get; set; }
    }
}

/// <summary>A Tenant's stored issuer as OpenIddict needs it: an origin, never with a path (Story 2.1 carry-over).</summary>
internal static class ProtocolIssuer
{
    /// <exception cref="InvalidOperationException">The stored issuer isn't an https origin with only the root path.</exception>
    public static Uri Parse(string stored)
    {
        if (!Uri.TryCreate(stored, UriKind.Absolute, out var issuer)
            || issuer.Scheme != Uri.UriSchemeHttps
            || issuer.UserInfo.Length > 0
            || issuer.AbsolutePath != "/"
            || issuer.Query.Length > 0
            || issuer.Fragment.Length > 0
            || !stored.EndsWith('/'))
        {
            throw new InvalidOperationException("A Tenant's stored issuer must be an https origin with no path.");
        }

        return issuer;
    }
}
