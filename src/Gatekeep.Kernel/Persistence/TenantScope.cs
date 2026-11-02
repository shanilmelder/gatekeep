using System.Data.Common;

namespace Gatekeep.Kernel.Persistence;

/// <summary>
/// The only way to reach <c>tenant</c> tables (AD-4). One scope is one transaction
/// for one Tenant. The setting is transaction-local, so it ends with the scope.
/// </summary>
public sealed class TenantScope : CommandScope
{
    private const string SetTenant = "SELECT set_config('gatekeep.tenant_id', @tenant_id, true)";

    private readonly DbDataSource _dataSource;

    private TenantScope(DbDataSource dataSource, DbConnection connection, DbTransaction transaction, Guid tenantId)
        : base(connection, transaction)
    {
        _dataSource = dataSource;
        TenantId = tenantId;
    }

    public Guid TenantId { get; }

    internal override Guid? ContextTenantId => TenantId;

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

            return new TenantScope(dataSource, connection, transaction, tenantId);
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

    internal override async Task<CommandScope> BeginFreshAsync(CancellationToken cancellationToken) =>
        await BeginAsync(_dataSource, TenantId, cancellationToken);
}
