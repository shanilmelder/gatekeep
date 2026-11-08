using System.Data.Common;
using Npgsql;

namespace Gatekeep.Modules.Protocol.Adapters;

/// <summary>
/// The token endpoint's connections, as <c>gk_hosted</c> (Story 2.5): its request transaction, its
/// short counting scopes and its read-only cross-Tenant check. Short timeouts and a bounded pool, as
/// Tenant resolution has, so a slow database answers an error rather than holding connections. Made
/// on first use, and only once: a second pool would never be disposed.
/// </summary>
internal sealed class HostedDataSource(Func<string> connectionString) : IAsyncDisposable
{
    /// <summary>How long a statement may take to answer, in seconds.</summary>
    public const int CommandTimeoutSeconds = 5;

    /// <summary>How long a request may wait to connect, or for a pooled connection, in seconds.</summary>
    public const int ConnectTimeoutSeconds = 5;

    /// <summary>The most connections token requests hold at once, in this process.</summary>
    public const int MaxConnections = 50;

    private readonly Lazy<NpgsqlDataSource> _source = new(
        () => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(connectionString())
        {
            Timeout = ConnectTimeoutSeconds,
            CommandTimeout = CommandTimeoutSeconds,
            MaxPoolSize = MaxConnections,
        }.ConnectionString),
        LazyThreadSafetyMode.ExecutionAndPublication);

    public DbDataSource Source => _source.Value;

    public async ValueTask DisposeAsync()
    {
        if (_source.IsValueCreated)
        {
            await _source.Value.DisposeAsync();
        }
    }
}
