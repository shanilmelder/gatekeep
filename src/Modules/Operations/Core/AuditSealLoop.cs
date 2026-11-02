using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Runs the Audit sealer over every chain (AD-16). The Deployment chain is sealed in a
/// Deployment scope and each Tenant chain in that Tenant's own scope, so row-level security
/// limits each pass to its one chain.
/// </summary>
internal sealed class AuditSealLoop : IAuditSealLoop
{
    private const string ListTenants = "SELECT id FROM tenant ORDER BY id";

    private readonly IAuditSealer _sealer = AuditContract.CreateSealer();
    private readonly TimeSpan _interval;
    private readonly ILogger? _logger;
    private readonly NpgsqlDataSource _sealerSource;
    private bool _roleChecked;

    public AuditSealLoop(string sealerDatabase, TimeSpan interval, ILogger? logger)
    {
        if (string.IsNullOrWhiteSpace(sealerDatabase))
        {
            throw new ArgumentException("The Sealer database has no connection string.", nameof(sealerDatabase));
        }

        if (interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval));
        }

        _interval = interval;
        _logger = logger;
        _sealerSource = NpgsqlDataSource.Create(sealerDatabase);
    }

    public async Task<int> PassAsync(CancellationToken cancellationToken)
    {
        await EnsureRoleAsync(cancellationToken);

        var sealedCount = 0;

        try
        {
            await using var scope = await DeploymentScope.BeginAsync(_sealerSource, cancellationToken);
            sealedCount += await _sealer.SealAsync(scope.CreateCommandContext(), IAuditSealLoop.MaxEventsPerChain, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (Exception e) when (!(e is OperationCanceledException && cancellationToken.IsCancellationRequested))
        {
            _logger?.LogError("Audit seal of the Deployment chain failed on {ErrorType}.", e.GetType().Name);
        }

        foreach (var tenantId in await ListTenantsAsync(cancellationToken))
        {
            try
            {
                await using var scope = await TenantScope.BeginAsync(_sealerSource, tenantId, cancellationToken);
                sealedCount += await _sealer.SealAsync(scope.CreateCommandContext(), IAuditSealLoop.MaxEventsPerChain, cancellationToken);
                await scope.CommitAsync(cancellationToken);
            }
            catch (Exception e) when (!(e is OperationCanceledException && cancellationToken.IsCancellationRequested))
            {
                // The Tenant ID and error type only: a message can quote a value.
                _logger?.LogError("Audit seal of Tenant {TenantId} failed on {ErrorType}.", tenantId, e.GetType().Name);
            }
        }

        return sealedCount;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var announced = false;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!announced)
                {
                    // Said once the role is confirmed, so a reader knows sealing has begun.
                    await EnsureRoleAsync(cancellationToken);
                    _logger?.LogInformation("Audit seal loop started.");
                    announced = true;
                }

                await PassAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (WrongJobRoleException)
            {
                // Misconfiguration never heals: stop, so the host stops too.
                throw;
            }
            catch (Exception e)
            {
                _logger?.LogError("Audit seal pass failed on {ErrorType}.", e.GetType().Name);
            }

            try
            {
                await Task.Delay(_interval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    public ValueTask DisposeAsync() => _sealerSource.DisposeAsync();

    /// <summary>
    /// A misconfigured connection would be refused by the seal columns' grants anyway, but it
    /// would fail every pass quietly instead of stopping the host.
    /// </summary>
    private async Task EnsureRoleAsync(CancellationToken cancellationToken)
    {
        if (!_roleChecked)
        {
            await RoleCheck.EnsureAsync(_sealerSource, JobRole.Sealer, cancellationToken);
            _roleChecked = true;
        }
    }

    private async Task<List<Guid>> ListTenantsAsync(CancellationToken cancellationToken)
    {
        await using var scope = await DeploymentScope.BeginAsync(_sealerSource, cancellationToken);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = ListTenants;

        var tenants = new List<Guid>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                tenants.Add(reader.GetGuid(0));
            }
        }

        await scope.CommitAsync(cancellationToken);
        return tenants;
    }
}
