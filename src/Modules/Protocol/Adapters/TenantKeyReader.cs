using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Protocol.Core;
using Npgsql;

namespace Gatekeep.Modules.Protocol.Adapters;

/// <summary>
/// Reads a Tenant's key rows as <c>gk_hosted</c>, in one short read-only Tenant scope that ends
/// before the request goes on (Story 2.3): discovery and JWKS hold no connection or transaction
/// through OpenIddict's pipeline, and write nothing. Short timeouts and a bounded pool, as Tenant
/// resolution has, so a slow database answers 503 rather than holding connections.
/// </summary>
internal sealed class TenantKeyReader(Func<string> connectionString) : ITenantKeyReader
{
    /// <summary>How long a read may take to answer, in seconds.</summary>
    public const int ReadTimeoutSeconds = 3;

    /// <summary>How long a read may wait to connect, or for a pooled connection, in seconds.</summary>
    public const int ConnectTimeoutSeconds = 5;

    /// <summary>The most connections reads hold at once, in this process.</summary>
    public const int MaxConnections = 10;

    private const string ReadOnly = "SET TRANSACTION READ ONLY";

    // Made on first use, so a host refused at startup never builds it, and only once: a second pool would never be disposed.
    private readonly Lazy<NpgsqlDataSource> _source = new(
        () => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(connectionString())
        {
            Timeout = ConnectTimeoutSeconds,
            CommandTimeout = ReadTimeoutSeconds,
            MaxPoolSize = MaxConnections,
        }.ConnectionString),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public async Task<TenantKeyMaterial> ReadAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        // Never committed: disposing it rolls back, and nothing was written to roll back.
        await using var scope = await TenantScope.BeginAsync(_source.Value, tenantId, cancellationToken);
        var context = scope.CreateCommandContext();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReadOnly;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var keys = await KeysContract.ReadPublishedSigningKeysAsync(context, cancellationToken);
        var wrap = await KeysContract.ReadProtectionKeyWrapAsync(context, cancellationToken);
        return new TenantKeyMaterial(keys, wrap);
    }
}
