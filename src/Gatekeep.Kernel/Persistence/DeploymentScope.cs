using System.Data.Common;

namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// One transaction with no Tenant setting, for commands on <c>control</c> tables.
/// A query on a <c>tenant</c> table here raises an error.
/// </summary>
public sealed class DeploymentScope : CommandScope
{
    private readonly DbDataSource _dataSource;

    private DeploymentScope(DbDataSource dataSource, DbConnection connection, DbTransaction transaction)
        : base(connection, transaction)
    {
        _dataSource = dataSource;
    }

    internal override Guid? ContextTenantId => null;

    public static async Task<DeploymentScope> BeginAsync(DbDataSource dataSource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dataSource);

        var connection = await dataSource.OpenConnectionAsync(cancellationToken);

        try
        {
            var transaction = await connection.BeginTransactionAsync(cancellationToken);

            return new DeploymentScope(dataSource, connection, transaction);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    internal override async Task<CommandScope> BeginFreshAsync(CancellationToken cancellationToken) =>
        await BeginAsync(_dataSource, cancellationToken);
}
