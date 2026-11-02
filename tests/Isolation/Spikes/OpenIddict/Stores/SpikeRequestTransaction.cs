using System.Collections.Concurrent;
using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;

/// <summary>
/// The request's transaction (AD-13): one <see cref="TenantScope"/> per OpenIddict request,
/// opened by the first Gatekeep handler and ended at endpoint end. Scoped to the HTTP request,
/// so the request's service scope disposes it, which rolls back anything left uncommitted.
/// </summary>
public sealed class SpikeRequestTransaction : IAsyncDisposable
{
    private readonly List<string> _revokedFamilies = [];
    private TenantScope? _scope;
    private CommandContext? _context;

    public SpikeTenant? Tenant { get; private set; }

    /// <summary>The Token Families a store revoked in this request, captured before any rollback.</summary>
    public IReadOnlyList<string> RevokedFamilies => _revokedFamilies;

    public bool IsOpen => _scope is not null;

    /// <summary>Every store call goes through this. A store call outside a request scope fails.</summary>
    public CommandContext Context =>
        _context ?? throw new InvalidOperationException("No request transaction: the first Gatekeep handler didn't open one.");

    public async Task BeginAsync(SpikeDatabase database, SpikeTenant tenant, CancellationToken cancellationToken)
    {
        if (_scope is not null)
        {
            throw new InvalidOperationException("This request already has a transaction.");
        }

        _scope = await TenantScope.BeginAsync(database.Hosted, tenant.Id, cancellationToken);
        _context = _scope.CreateCommandContext();
        Tenant = tenant;
    }

    public void RecordFamilyRevoked(string authorizationId)
    {
        if (!_revokedFamilies.Contains(authorizationId, StringComparer.Ordinal))
        {
            _revokedFamilies.Add(authorizationId);
        }
    }

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        var scope = Take();
        try
        {
            await scope.CommitAsync(cancellationToken);
        }
        finally
        {
            await scope.DisposeAsync();
        }
    }

    public async Task RollBackAsync()
    {
        var scope = Take();
        await scope.DisposeAsync();
    }

    /// <summary>Rolls the request back, then commits <paramref name="effect"/> in a fresh scope.</summary>
    public async Task CommitAfterRollbackAsync(Func<CommandContext, CancellationToken, Task> effect)
    {
        var scope = Take();
        try
        {
            await FailureContext.CommitAfterRollbackAsync(scope, effect);
        }
        finally
        {
            await scope.DisposeAsync();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_scope is not null)
        {
            await Take().DisposeAsync();
        }
    }

    private TenantScope Take()
    {
        var scope = _scope ?? throw new InvalidOperationException("No open request transaction.");
        _scope = null;
        _context = null;
        return scope;
    }
}

/// <summary>How a request's transaction ended, for the tests to read.</summary>
public enum SpikeRequestOutcome
{
    Committed,
    RolledBack,
    RevocationCommittedAfterRollback,
    RolledBackLosingRevocation,
}

/// <summary>
/// What the spike records about store use, and the switches the tests flip. Reference IDs are
/// recorded only as the hashes the store received, never as values.
/// </summary>
public sealed class SpikeStoreProbe
{
    public ConcurrentQueue<(Guid Tenant, string Hash)> ReferenceLookups { get; } = new();

    public ConcurrentQueue<SpikeRequestOutcome> Outcomes { get; } = new();

    private int _writes;

    /// <summary>Store writes (insert, update, revoke) run so far, committed or not.</summary>
    public int Writes => Volatile.Read(ref _writes);

    public void RecordWrite() => Interlocked.Increment(ref _writes);

    /// <summary>On by default. Off shows what happens to OpenIddict's own revoke without it.</summary>
    public bool CommitRevocationAfterRollback { get; set; } = true;

    /// <summary>Rejects a token request's sign-in after its tokens are written, to prove rollback.</summary>
    public bool RejectSignInAfterWrites { get; set; }
}
