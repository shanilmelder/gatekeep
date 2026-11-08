using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Adapters;
using Gatekeep.Modules.Directory.Core;
using OpenIddict.Abstractions;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>What a composition root uses to wire Directory.</summary>
public static class DirectoryContract
{
    /// <summary>Applications and client secrets over the Kernel audit port. <paramref name="time"/> stamps each creation.</summary>
    public static IDirectory CreateDirectory(IAuditAppender audit, TimeProvider time) => new DirectoryService(audit, time);

    /// <summary>
    /// OpenIddict's application store (AD-8: each store lives in its owner). Every call runs in
    /// <paramref name="context"/>'s result, the request's own Tenant context, so it reads only that
    /// Tenant's Applications. It only reads, and hands OpenIddict no secret.
    /// </summary>
    public static IOpenIddictApplicationStore<DirectoryApplication> CreateApplicationStore(Func<CommandContext> context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new ApplicationStore(context);
    }

    /// <summary>
    /// Directory's Tenant purge (Story 2.5, AD-30): deletes the context Tenant's <c>client_secret</c>, then
    /// <c>application</c> rows. Sessions' and Authentication's purges must run first: their rows reference Applications.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new DirectoryPurge();
}
