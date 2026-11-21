using System.Collections.Concurrent;
using Gatekeep.Modules.Authentication.Contracts;

namespace Gatekeep.Modules.Authentication.Core;

/// <summary>
/// The hashing budget (Story 4.7, AD-14): every Argon2id hash a host computes passes this one gate, which holds at most
/// <see cref="PasswordHashLimits.Concurrency"/> at once, at most <see cref="PasswordHashLimits.TenantShare"/> of them one
/// Tenant's, and waits for a slot only until <see cref="PasswordHashLimits.Wait"/> has passed. A request that gets no slot
/// is refused, and nothing is hashed.
/// </summary>
internal sealed class PasswordHashGate(PasswordHashLimits limits, TimeProvider? time = null) : IPasswordHashGate
{
    private readonly PasswordHashLimits _limits = limits ?? throw new ArgumentNullException(nameof(limits));

    private readonly TimeProvider _time = time ?? TimeProvider.System;

    private readonly SemaphoreSlim _deployment = new(limits.Concurrency, Math.Max(1, limits.Concurrency));

    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _tenants = new();

    /// <summary>A slot for <paramref name="tenantId"/>, released when disposed, or null when none came free in time.</summary>
    public async Task<IDisposable?> EnterAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        var tenant = _tenants.GetOrAdd(tenantId, _ => new SemaphoreSlim(_limits.TenantShare, Math.Max(1, _limits.TenantShare)));
        var deadline = _time.GetUtcNow() + _limits.Wait;

        if (!await tenant.WaitAsync(Remaining(deadline), cancellationToken))
        {
            return null;
        }

        try
        {
            if (!await _deployment.WaitAsync(Remaining(deadline), cancellationToken))
            {
                tenant.Release();
                return null;
            }
        }
        catch
        {
            tenant.Release();
            throw;
        }

        return new Lease(tenant, _deployment);
    }

    private TimeSpan Remaining(DateTimeOffset deadline)
    {
        var left = deadline - _time.GetUtcNow();
        return left > TimeSpan.Zero ? left : TimeSpan.Zero;
    }

    private sealed class Lease(SemaphoreSlim tenant, SemaphoreSlim deployment) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                deployment.Release();
                tenant.Release();
            }
        }
    }
}
