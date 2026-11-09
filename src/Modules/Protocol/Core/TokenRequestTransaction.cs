using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Contracts;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The one transaction of a request to an endpoint that writes (AD-5, AD-8, AD-13): the token endpoint
/// (Story 2.5) and the authorization endpoint (Story 2.9). A <see cref="TenantScope"/> for the request's
/// Tenant, opened after Tenant selection by <see cref="BeginTokenTransaction{TContext}"/> or
/// <see cref="BeginAuthorizeTransaction"/>, and ended before the response is written by
/// <see cref="EndTokenTransaction{TContext}"/> or <see cref="EndAuthorizeTransaction"/>. Scoped to the HTTP request,
/// so the request's service scope disposes it. Discovery and JWKS never open one. Every store call goes
/// through <see cref="Context"/>, so none can fall back to autocommit.
/// <para>
/// Effects a refused request keeps, a cross-Tenant event or a replayed code's revocation, are recorded
/// with <see cref="KeepOnFailure"/> and committed after the rollback through <see cref="FailureContext"/>,
/// on the normal end and also when the request never reached it (an unhandled exception), on disposal. A
/// failed statement a store reports with <see cref="MarkFailed"/> means the request never commits, since
/// PostgreSQL would turn a commit of the aborted transaction into a rollback without an error.
/// </para>
/// </summary>
internal sealed class TokenRequestTransaction : IAsyncDisposable
{
    private readonly List<Func<CommandContext, CancellationToken, Task>> _failureEffects = [];
    private readonly HashSet<Guid> _redeemed = [];
    private readonly ILogger? _logger;
    private TenantScope? _scope;
    private CommandContext? _context;

    public TokenRequestTransaction(ILoggerFactory? loggers = null)
    {
        _logger = loggers?.CreateLogger("Gatekeep.Protocol");
        Store = new StoreRequest(() => Context, KeepOnFailure, MarkFailed, id => _redeemed.Add(id));
    }

    public bool IsOpen => _scope is not null;

    /// <summary>Whether a statement in this transaction failed, so it can never commit.</summary>
    public bool Failed { get; private set; }

    /// <summary>The request's Tenant context. Any store call outside an open transaction throws.</summary>
    public CommandContext Context =>
        _context ?? throw new InvalidOperationException("No request transaction is open.");

    /// <summary>What the Sessions stores run in: this transaction's context, its kept effects and its failure flag.</summary>
    public StoreRequest Store { get; }

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

    /// <summary>Records an effect the request keeps even when it is refused, such as a cross-Tenant event or a revocation.</summary>
    public void KeepOnFailure(Func<CommandContext, CancellationToken, Task> effect)
    {
        ArgumentNullException.ThrowIfNull(effect);
        _failureEffects.Add(effect);
    }

    /// <summary>
    /// Whether this request's own redemption of the token <paramref name="tokenId"/> succeeded (Story 2.10), as
    /// the token store reported it. A request that lost a race to redeem it hasn't.
    /// </summary>
    public bool HasRedeemed(Guid tokenId) => _redeemed.Contains(tokenId);

    /// <summary>Marks the transaction failed: a statement in it failed, so it must not commit.</summary>
    public void MarkFailed() => Failed = true;

    /// <exception cref="InvalidOperationException">The transaction is marked failed; nothing is committed.</exception>
    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        if (Failed)
        {
            throw new InvalidOperationException("A failed request transaction is never committed.");
        }

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
            _failureEffects.Clear();
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

    /// <summary>
    /// A transaction still open here never reached its endpoint's end, such as after an unhandled
    /// exception: it is rolled back, and every recorded failure effect is still committed (AD-13). A
    /// failure to commit them is logged by its type only, and never replaces the request's own error.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_scope is null)
        {
            return;
        }

        if (_failureEffects.Count == 0)
        {
            await Take().DisposeAsync();
            return;
        }

        try
        {
            await FailAsync();
        }
        catch (Exception e)
        {
            _logger?.LogError("A refused request's kept effects weren't committed, on {ErrorType}.", e.GetType().Name);
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
