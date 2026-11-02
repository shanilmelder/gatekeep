using Gatekeep.Adapters.OpenBao;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Adapters.Hosting;

/// <summary>
/// <c>/healthz</c>, served only on the private health port. 200 when every database role
/// connects and, with custody configured, OpenBao answers. Otherwise 503 with a fixed body
/// naming the failed checks. Neither body ever holds a value.
/// </summary>
internal sealed class HealthEndpoint : IAsyncDisposable
{
    public const string Path = "/healthz";
    public const string Healthy = "healthy";
    public const string Database = "database";
    public const string Custody = "custody";

    /// <summary>
    /// One deadline for all checks, which run at once. It's shorter than the probe's 5-second
    /// timeout, so a hung dependency still gets its 503 body rather than a timed-out probe.
    /// </summary>
    public static readonly TimeSpan Deadline = TimeSpan.FromSeconds(3);

    private readonly NpgsqlDataSource[] _databases;
    private readonly OpenBaoHealth? _custody;
    private readonly ILogger _logger;

    public HealthEndpoint(ResolvedSettings settings, ILoggerFactory loggers)
    {
        _databases =
        [
            .. settings.Databases.Values.Select(connectionString => NpgsqlDataSource.Create(
                new NpgsqlConnectionStringBuilder(connectionString)
                {
                    Timeout = (int)Deadline.TotalSeconds,
                    CommandTimeout = (int)Deadline.TotalSeconds,
                    MaxPoolSize = 2,
                }.ConnectionString)),
        ];
        _custody = settings.Custody is { } options ? new OpenBaoHealth(options) : null;
        _logger = loggers.CreateLogger("Gatekeep.Health");
    }

    public async Task HandleAsync(HttpContext context)
    {
        if (context.Request.Path != Path || !(HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        deadline.CancelAfter(Deadline);

        var databases = Task.WhenAll(_databases.Select(d => ConnectsAsync(d, deadline.Token)));
        var custody = _custody is null ? Task.FromResult(true) : CustodyAnswersAsync(_custody, deadline.Token);
        await Task.WhenAll(databases, custody);

        var failed = new List<string>(2);
        if (!(await databases).All(ok => ok))
        {
            failed.Add(Database);
        }

        if (!await custody)
        {
            failed.Add(Custody);
        }

        context.Response.StatusCode = failed.Count == 0 ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable;
        context.Response.ContentType = "text/plain; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync(failed.Count == 0 ? Healthy : "unhealthy: " + string.Join(", ", failed), context.RequestAborted);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var database in _databases)
        {
            await database.DisposeAsync();
        }

        _custody?.Dispose();
    }

    private async Task<bool> ConnectsAsync(NpgsqlDataSource database, CancellationToken cancellationToken)
    {
        try
        {
            await using var command = database.CreateCommand("SELECT 1");
            await command.ExecuteScalarAsync(cancellationToken);
            return true;
        }
        catch (Exception e)
        {
            // The type only: a message can quote a value. A passed deadline is a failure too.
            _logger.LogWarning("Health check {Check} failed on {ErrorType}.", Database, e.GetType().Name);
            return false;
        }
    }

    private static async Task<bool> CustodyAnswersAsync(OpenBaoHealth custody, CancellationToken cancellationToken)
    {
        try
        {
            return await custody.IsAvailableAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}

/// <summary>Puts the health branch first, ahead of anything a host maps, and only on the health port.</summary>
internal sealed class HealthStartupFilter(ResolvedSettings settings, HealthEndpoint health) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            if (context.Connection.LocalPort == settings.HealthPort)
            {
                await health.HandleAsync(context);
                return;
            }

            await nextMiddleware(context);
        });

        next(app);
    };
}
