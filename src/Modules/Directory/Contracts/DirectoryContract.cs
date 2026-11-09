using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Adapters;
using Gatekeep.Modules.Directory.Core;
using OpenIddict.Abstractions;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>What a composition root uses to wire Directory.</summary>
public static class DirectoryContract
{
    /// <summary>
    /// The fixed name of each Tenant's hidden <c>system</c> Application (Story 2.8). The migration that
    /// backfills existing Tenants writes the same text.
    /// </summary>
    public const string SystemApplicationName = "Account Portal";

    /// <summary>The <c>application.kind</c> of a confidential client that signs Users in by the code flow (Story 2.9).</summary>
    public const string WebKind = "web";

    /// <summary>The most redirect URIs a <c>web</c> client registers: 10, as the table checks (Story 2.9).</summary>
    public const int MaxRedirectUris = 10;

    /// <summary>The longest redirect URI a <c>web</c> client registers: 2000 characters (Story 2.9).</summary>
    public const int MaxRedirectUriLength = 2000;

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
