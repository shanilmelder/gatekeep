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

    /// <summary>The <c>application.kind</c> of a confidential machine-to-machine client, which uses Client Credentials (Story 2.5).</summary>
    public const string MachineKind = "machine";

    /// <summary>The <c>application.kind</c> of a single-page Application: a public client with no credential (Story 3.1).</summary>
    public const string SpaKind = "spa";

    /// <summary>The <c>application.kind</c> of a native Application: a public client with no credential (Story 3.1).</summary>
    public const string NativeKind = "native";

    /// <summary>The kinds an Admin may create (Story 3.1), in a fixed order. Never the hidden <c>system</c> kind.</summary>
    public static readonly IReadOnlyList<string> CreatableKinds = [SpaKind, WebKind, NativeKind, MachineKind];

    /// <summary>The longest Application name: 200 characters, as the table checks.</summary>
    public const int MaxNameLength = 200;

    /// <summary>Whether an Application of <paramref name="kind"/> authenticates with a credential: <c>web</c> and <c>machine</c> do (Story 3.1).</summary>
    public static bool CredentialRequired(string kind) => kind is WebKind or MachineKind;

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
