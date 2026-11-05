using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Protocol.Core;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Modules.Protocol.Adapters;

/// <summary>
/// One dedicated <c>gk_hosted</c> connection that listens on <see cref="KeysContract.SigningKeysChannel"/>
/// (Story 2.4). Each notification names the Tenant whose keys a committed rotation changed. A lost
/// connection is opened again after a capped backoff, and every successful (re)connect is reported,
/// since notifications sent while it was down are gone. It holds no transaction and reads nothing.
/// </summary>
internal sealed class SigningKeyChangeListener(Func<string> connectionString, ILogger<SigningKeyChangeListener>? logger = null)
    : ITenantKeyChanges, IAsyncDisposable
{
    /// <summary>The first wait after a failure. It doubles to <see cref="MaxBackoff"/>.</summary>
    public static readonly TimeSpan MinBackoff = TimeSpan.FromSeconds(1);

    /// <summary>The longest wait between two connection attempts.</summary>
    public static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(30);

    /// <summary>How long one connection attempt may take, in seconds.</summary>
    private const int ConnectTimeoutSeconds = 5;

    /// <summary>How often an idle connection is probed, in seconds, so a dead server is noticed.</summary>
    private const int KeepAliveSeconds = 15;

    private readonly CancellationTokenSource _stop = new();
    private readonly Lock _lock = new();

    private Task? _loop;
    private TaskCompletionSource? _firstAttempt;
    private volatile bool _listening;

    public bool Listening => _listening;

    public Task StartAsync(Action<Guid> changed, Action reconnected)
    {
        ArgumentNullException.ThrowIfNull(changed);
        ArgumentNullException.ThrowIfNull(reconnected);

        lock (_lock)
        {
            if (_firstAttempt is null)
            {
                _firstAttempt = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _loop = Task.Run(() => RunAsync(changed, reconnected, _firstAttempt, _stop.Token));
            }

            return _firstAttempt.Task;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        if (_loop is { } loop)
        {
            try
            {
                await loop;
            }
            catch (OperationCanceledException)
            {
            }
        }

        _stop.Dispose();
    }

    private async Task RunAsync(Action<Guid> changed, Action reconnected, TaskCompletionSource firstAttempt, CancellationToken stop)
    {
        var backoff = MinBackoff;

        while (!stop.IsCancellationRequested)
        {
            try
            {
                // Unpooled: a pooled connection is reset on return, which would end the LISTEN unseen.
                await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString())
                {
                    Pooling = false,
                    Timeout = ConnectTimeoutSeconds,
                    KeepAlive = KeepAliveSeconds,
                }.ConnectionString);

                connection.Notification += (_, e) =>
                {
                    // Anything but a Tenant ID is ignored: the payload is never trusted further.
                    if (Guid.TryParseExact(e.Payload, "D", out var tenantId))
                    {
                        changed(tenantId);
                    }
                };

                await connection.OpenAsync(stop);
                await using (var listen = new NpgsqlCommand($"LISTEN {KeysContract.SigningKeysChannel}", connection))
                {
                    await listen.ExecuteNonQueryAsync(stop);
                }

                _listening = true;
                backoff = MinBackoff;

                // Whatever changed while no one listened is unknown, so every kept runtime goes.
                reconnected();
                firstAttempt.TrySetResult();

                while (true)
                {
                    await connection.WaitAsync(stop);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                _listening = false;
                firstAttempt.TrySetResult();

                // The type only: a message can quote a connection value.
                logger?.LogWarning(
                    "Signing Key change listener lost its connection on {ErrorType}; it reconnects in {Backoff}.",
                    e.GetType().Name,
                    backoff);

                try
                {
                    await Task.Delay(backoff, stop);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxBackoff.Ticks));
            }
        }

        _listening = false;
        firstAttempt.TrySetResult();
    }
}
