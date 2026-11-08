using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The token endpoint's one transaction (AD-5, AD-8, AD-13): a <see cref="TenantScope"/> for the
/// request's Tenant, opened after Tenant selection by <see cref="BeginTokenTransaction"/> and ended by
/// <see cref="EndTokenTransaction"/> before the response is written. Scoped to the HTTP request, so the
/// request's service scope disposes it, which rolls back anything left uncommitted, an unhandled
/// exception included. Discovery and JWKS never open one. Every store call goes through
/// <see cref="Context"/>, so none can fall back to autocommit.
/// </summary>
internal sealed class TokenRequestTransaction : IAsyncDisposable
{
    private readonly List<Func<CommandContext, CancellationToken, Task>> _failureEffects = [];
    private TenantScope? _scope;
    private CommandContext? _context;

    public bool IsOpen => _scope is not null;

    /// <summary>The request's Tenant context. Any store call outside an open transaction throws.</summary>
    public CommandContext Context =>
        _context ?? throw new InvalidOperationException("No token request transaction is open.");

    /// <summary>Durable effects a refused request keeps, committed after its rollback (AD-5).</summary>
    public IReadOnlyList<Func<CommandContext, CancellationToken, Task>> FailureEffects => _failureEffects;

    public async Task BeginAsync(System.Data.Common.DbDataSource source, Guid tenantId, CancellationToken cancellationToken)
    {
        if (_scope is not null)
        {
            throw new InvalidOperationException("This request already has a transaction.");
        }

        _scope = await TenantScope.BeginAsync(source, tenantId, cancellationToken);
        _context = _scope.CreateCommandContext();
    }

    /// <summary>Records an effect the request keeps even when it is refused, such as a cross-Tenant event.</summary>
    public void KeepOnFailure(Func<CommandContext, CancellationToken, Task> effect) => _failureEffects.Add(effect);

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

    /// <summary>Rolls back, then commits every recorded failure effect in a fresh scope; with none, only rolls back.</summary>
    public async Task FailAsync()
    {
        var scope = Take();
        try
        {
            if (_failureEffects.Count == 0)
            {
                return;
            }

            var effects = _failureEffects.ToList();
            await FailureContext.CommitAfterRollbackAsync(scope, async (context, cancellationToken) =>
            {
                foreach (var effect in effects)
                {
                    await effect(context, cancellationToken);
                }
            });
        }
        finally
        {
            // Disposing an unfinished scope rolls it back; a finished one is left alone.
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
        var scope = _scope ?? throw new InvalidOperationException("No open token request transaction.");
        _scope = null;
        _context = null;
        return scope;
    }
}
