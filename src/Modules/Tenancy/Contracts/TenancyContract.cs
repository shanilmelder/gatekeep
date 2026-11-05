using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Tenancy.Adapters;
using Gatekeep.Modules.Tenancy.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Modules.Tenancy.Contracts;

/// <summary>What composition roots and other modules use to reach Tenancy.</summary>
public static class TenancyContract
{
    /// <summary>
    /// The Tenants and their hosts (Story 1.27). Activation writes <see cref="TenancyEvents.TenantActivated"/>,
    /// and a deletion's completion <see cref="TenancyEvents.TenantDeleted"/> (Story 1.29), through <paramref name="appender"/>.
    /// </summary>
    public static ITenants CreateTenants(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new Tenants(appender);
    }

    /// <summary>
    /// Tenancy's Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>tenant_settings</c>
    /// row, which only a <c>deleting</c> Tenant's may. Its <c>tenant</c> and <c>tenant_host</c> rows stay
    /// for good, as its tombstone.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new TenancyPurge();

    /// <summary>
    /// Host.Hosted's first middleware on its public port (AD-6), before routing: resolves the
    /// request's host to an active Tenant as <c>gk_hosted</c> through <paramref name="connectionString"/>,
    /// read on first use, and sets <see cref="ResolvedTenant"/> as a request feature. Any other host,
    /// a Tenant still being created, or being or already deleted (Story 1.29), included, gets the one fixed 404, and a lookup failure the one
    /// fixed 503, before anything else runs.
    /// </summary>
    public static IApplicationBuilder UseTenantResolution(this IApplicationBuilder app, Func<string> connectionString) =>
        TenancyAdapters.UseTenantResolution(app, connectionString);

    /// <summary>The one fixed 404 an unknown host gets, for a resolved request no endpoint answers too.</summary>
    public static Task NotFoundAsync(HttpContext context) => TenancyAdapters.NotFoundAsync(context);
}
