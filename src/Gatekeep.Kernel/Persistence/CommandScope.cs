using System.Data.Common;

namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// One transaction for one command. Disposing a scope that wasn't committed rolls it
/// back. Only Kernel derives from this: <see cref="TenantScope"/> and
/// <see cref="DeploymentScope"/> are the only kinds.
/// </summary>
public abstract class CommandScope : IAsyncDisposable
{
    private readonly DbConnection _connection;
    private readonly DbTransaction _transaction;
    private bool _finished;
    private bool _released;

    private protected CommandScope(DbConnection connection, DbTransaction transaction)
    {
        _connection = connection;
        _transaction = transaction;
    }

    /// <summary>The Tenant this scope is bound to. Null in a Deployment scope.</summary>
    internal abstract Guid? ContextTenantId { get; }

    public CommandContext CreateCommandContext()
    {
        ThrowIfFinished();
        return new CommandContext(this);
    }

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        ThrowIfFinished();
        _finished = true;

        try
        {
            await _transaction.CommitAsync(cancellationToken);
        }
        finally
        {
            // A command made earlier must fail, not run in autocommit on this connection.
            await ReleaseAsync();
        }
    }

    public async ValueTask DisposeAsync()
    {
        _finished = true;
        await ReleaseAsync();
    }

    internal DbCommand CreateEnlistedCommand()
    {
        ThrowIfFinished();

        var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        return command;
    }

    /// <summary>Rolls back explicitly, so the caller knows it happened before going on.</summary>
    internal async Task RollBackAsync(CancellationToken cancellationToken)
    {
        ThrowIfFinished();
        _finished = true;

        try
        {
            await _transaction.RollbackAsync(cancellationToken);
        }
        finally
        {
            await ReleaseAsync();
        }
    }

    /// <summary>Opens a new scope of the same kind, on its own connection.</summary>
    internal abstract Task<CommandScope> BeginFreshAsync(CancellationToken cancellationToken);

    private async ValueTask ReleaseAsync()
    {
        // Npgsql reuses its transaction object per connector, so a second dispose here
        // could roll back the next request's transaction on a pooled connector.
        if (_released)
        {
            return;
        }

        _released = true;

        try
        {
            // Disposing an uncompleted transaction rolls it back.
            await _transaction.DisposeAsync();
        }
        finally
        {
            await _connection.DisposeAsync();
        }
    }

    private void ThrowIfFinished()
    {
        if (_finished)
        {
            throw new InvalidOperationException("This scope has finished.");
        }
    }
}
