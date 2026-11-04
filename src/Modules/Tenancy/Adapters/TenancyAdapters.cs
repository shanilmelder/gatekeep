using System.Data.Common;
using System.Globalization;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Gatekeep.Modules.Tenancy.Adapters;

/// <summary>
/// Tenant resolution on Host.Hosted (AD-6): the whole request host, lower-cased with the invariant
/// culture and without its port, matched exactly against the stored host of an <c>active</c>
/// Tenant, as <c>gk_hosted</c>, with no transaction, scope or cache. No code parses a subdomain
/// out of a host, and no forwarded header or absolute-form target is ever read. No match is the one
/// fixed 404 and a lookup failure the one fixed 503, neither depending on the host or path, both
/// written before routing, so no Tenant code runs for them.
/// </summary>
internal static class TenancyAdapters
{
    private const string Lookup =
        """
        SELECT t.id, t.issuer, t.rp_id, t.email_link_base
        FROM tenant_host h
        JOIN tenant t ON t.id = h.tenant_id
        WHERE h.host = @host AND t.status = 'active'
        """;

    /// <summary>How long a lookup may take to answer, in seconds.</summary>
    public const int LookupTimeoutSeconds = 3;

    /// <summary>How long a lookup may wait to connect, or for a pooled connection, in seconds.</summary>
    public const int ConnectTimeoutSeconds = 5;

    /// <summary>The most connections lookups hold at once, in this process.</summary>
    public const int MaxConnections = 20;

    public static IApplicationBuilder UseTenantResolution(IApplicationBuilder app, Func<string> connectionString)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(connectionString);

        // Made on first use, so a host refused at startup never builds it, and built again after a
        // failure rather than caching it. Short timeouts and a bounded pool: a slow or flooded lookup
        // answers 503 rather than holding every connection.
        var source = new Lazy<NpgsqlDataSource>(
            () => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(connectionString())
            {
                Timeout = ConnectTimeoutSeconds,
                CommandTimeout = LookupTimeoutSeconds,
                MaxPoolSize = MaxConnections,
            }.ConnectionString),
            LazyThreadSafetyMode.PublicationOnly);
        var logger = app.ApplicationServices.GetService<ILoggerFactory>()?.CreateLogger("Gatekeep.Tenancy");

        return app.Use(async (context, next) =>
        {
            ResolvedTenant? tenant;
            try
            {
                tenant = await ResolveAsync(source.Value, context.Request.Host.Host, context.RequestAborted);
            }
            catch (Exception e) when (e is DbException or TimeoutException or OperationCanceledException
                && !context.RequestAborted.IsCancellationRequested)
            {
                // The type only: a message can quote a value, and the host is never logged.
                logger?.LogWarning("Tenant resolution failed on {ErrorType}.", e.GetType().Name);
                await UnavailableAsync(context);
                return;
            }

            if (tenant is null)
            {
                await NotFoundAsync(context);
                return;
            }

            context.Features.Set(tenant);
            await next(context);
        });
    }

    /// <summary>The one fixed 404: the response Host.Hosted gave every request before Story 1.27, with no body.</summary>
    public static Task NotFoundAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }

    /// <summary>The one fixed 503, with no body, never cached.</summary>
    public static Task UnavailableAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    }

    private static async Task<ResolvedTenant?> ResolveAsync(NpgsqlDataSource source, string host, CancellationToken cancellationToken)
    {
        // The whole host as sent, lower-cased: no trailing-dot removal or other normalization.
        var key = host.ToLower(CultureInfo.InvariantCulture);
        if (key.Length == 0)
        {
            return null;
        }

        await using var command = source.CreateCommand(Lookup);
        command.Parameters.AddWithValue("host", key);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ResolvedTenant(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3));
    }
}
