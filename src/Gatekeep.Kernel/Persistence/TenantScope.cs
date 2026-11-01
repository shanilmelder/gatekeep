using System.Data.Common;

namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// The only way to reach <c>tenant</c> tables (AD-4). One scope is one transaction
/// for one Tenant. The setting is transaction-local, so it ends with the scope.
/// Disposing a scope that wasn't committed rolls it back.
/// </summary>
public sealed class TenantScope : IAsyncDisposable
{
    private const string SetTenant = "SELECT set_config('gatekeep.tenant_id', @tenant_id, true)";

    private readonly DbConnection _connection;
    private readonly DbTransaction _transaction;
    private bool _finished;

    private TenantScope(DbConnection connection, DbTransaction transaction, Guid tenantId)
    {
        _connection = connection;
        _transaction = transaction;
        TenantId = tenantId;
    }

    public Guid TenantId { get; }

    public static async Task<TenantScope> BeginAsync(
        DbDataSource dataSource,
        Guid tenantId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataSource);

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A Tenant scope needs a Tenant ID.", nameof(tenantId));
        }

        var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        DbTransaction? transaction = null;

        try
        {
            transaction = await connection.BeginTransactionAsync(cancellationToken);

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = SetTenant;

            var parameter = command.CreateParameter();
            parameter.ParameterName = "tenant_id";
            parameter.Value = tenantId.ToString();
            command.Parameters.Add(parameter);

            await command.ExecuteNonQueryAsync(cancellationToken);

            return new TenantScope(connection, transaction, tenantId);
        }
        catch
        {
            try
            {
                if (transaction is not null)
                {
                    await transaction.DisposeAsync();
                }
            }
            finally
            {
                await connection.DisposeAsync();
            }

            throw;
        }
    }

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

    private async ValueTask ReleaseAsync()
    {
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
            throw new InvalidOperationException("This Tenant scope has finished.");
        }
    }
}
