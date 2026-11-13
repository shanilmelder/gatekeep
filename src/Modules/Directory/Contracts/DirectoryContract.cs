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

    /// <summary>Whether an Application of <paramref name="kind"/> is a public client, authenticating by its <c>client_id</c> alone: <c>spa</c> and <c>native</c> (Story 3.2).</summary>
    public static bool IsPublic(string kind) => kind is SpaKind or NativeKind;

    /// <summary>Whether an Application of <paramref name="kind"/> may sign Users in by the code flow: <c>web</c>, <c>spa</c> and <c>native</c> (Story 3.2).</summary>
    public static bool SignsUsersIn(string kind) => kind is WebKind or SpaKind or NativeKind;

    /// <summary>The most entries in each of an Application's URL lists: 10, as the table checks (Stories 2.9 and 3.2).</summary>
    public const int MaxRedirectUris = 10;

    /// <summary>The longest entry in any of an Application's URL lists: 2000 characters (Stories 2.9 and 3.2).</summary>
    public const int MaxRedirectUriLength = 2000;

    /// <summary>The <c>authorization_code</c> grant: the code flow with PKCE.</summary>
    public const string AuthorizationCodeGrant = "authorization_code";

    /// <summary>The <c>refresh_token</c> grant: rotating refresh tokens, only with the code flow.</summary>
    public const string RefreshTokenGrant = "refresh_token";

    /// <summary>The <c>client_credentials</c> grant: a machine-to-machine Application's tokens.</summary>
    public const string ClientCredentialsGrant = "client_credentials";

    /// <summary>The only grant types an Application can hold, in their stored (sorted) order (Story 3.2).</summary>
    public static readonly IReadOnlyList<string> GrantTypes = [AuthorizationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant];

    /// <summary>
    /// Every problem in <paramref name="settings"/> for an Application of <paramref name="kind"/> (Story 3.2),
    /// each naming its field, its 0-based line (or null for the whole field) and one of
    /// <see cref="ApplicationSettingsReasons"/>; empty when the settings may be saved. It decides the type
    /// table: a <c>machine</c> Application has no URL and <c>{}</c> or <c>{client_credentials}</c>; the
    /// others <c>{}</c>, <c>{authorization_code}</c> or <c>{authorization_code, refresh_token}</c>, https
    /// URLs or http on <c>127.0.0.1</c> or <c>[::1]</c> only, a <c>native</c> one custom schemes as well and
    /// no web origin.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="kind"/> isn't an Admin's kind.</exception>
    public static IReadOnlyList<ApplicationSettingsProblem> CheckSettings(string kind, ApplicationSettings settings) =>
        ApplicationSettingsRules.Check(kind, settings);

    /// <summary>
    /// Every lifetime in <paramref name="lifetimes"/> outside its limits (Story 3.4): under 1 second is
    /// <see cref="ApplicationLifetimeReasons.BelowMinimum"/>, over its <c>SecurityLimits</c> hard limit
    /// <see cref="ApplicationLifetimeReasons.AboveMaximum"/> with that limit in seconds. Empty when the lifetimes may be saved.
    /// </summary>
    public static IReadOnlyList<ApplicationLifetimeProblem> CheckLifetimes(ApplicationLifetimes lifetimes) =>
        ApplicationLifetimeRules.Check(lifetimes);

    /// <summary>The name of each Tenant's built-in Management API (Story 3.6). The migration that backfills existing Tenants writes the same text.</summary>
    public const string ManagementApiName = "Gatekeep Management API";

    /// <summary>
    /// The identifier of each Tenant's built-in Management API (Story 3.6): the only one under the reserved
    /// <c>urn:gatekeep:</c> prefix. The migration that backfills existing Tenants writes the same text.
    /// </summary>
    public const string ManagementApiIdentifier = "urn:gatekeep:management";

    /// <summary>
    /// The built-in Management API's Permissions (Story 3.6, FR-42): one <c>resource:action</c> for each Tenant
    /// capability a machine client may be allowed, <c>tenant.applications.manage</c> becoming <c>applications:manage</c>,
    /// in the capability table's order. An Architecture test holds this list to that table, and the migration that
    /// backfills existing Tenants writes the same values.
    /// </summary>
    public static readonly IReadOnlyList<string> ManagementPermissions =
    [
        "configuration:read",
        "users:read",
        "logs:read",
        "log_detail:read",
        "applications:manage",
        "apis:manage",
        "roles:manage",
        "users:manage",
        "theme:manage",
        "templates:manage",
        "settings:manage",
        "connections:toggle",
        "configuration:export",
        "password_policy:manage",
        "connection_credentials:manage",
        "user_data:export",
        "user_data:erase",
    ];

    /// <summary>
    /// Each of <see cref="ManagementPermissions"/>'s description, as the built-in Management API shows it. The migration that
    /// backfills existing Tenants writes the same pairs; an Architecture test holds them equal.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> ManagementPermissionDescriptions = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["configuration:read"] = "Read Tenant configuration",
        ["users:read"] = "Read Users",
        ["logs:read"] = "Read Log summaries",
        ["log_detail:read"] = "Read raw Log detail",
        ["applications:manage"] = "Manage Applications",
        ["apis:manage"] = "Manage APIs",
        ["roles:manage"] = "Manage Roles",
        ["users:manage"] = "Manage Users",
        ["theme:manage"] = "Manage the theme",
        ["templates:manage"] = "Manage email templates",
        ["settings:manage"] = "Manage Tenant settings",
        ["connections:toggle"] = "Enable or disable Connections",
        ["configuration:export"] = "Export Tenant configuration",
        ["password_policy:manage"] = "Manage the password policy",
        ["connection_credentials:manage"] = "Manage Connection credentials",
        ["user_data:export"] = "Export User data",
        ["user_data:erase"] = "Erase User data",
    };

    /// <summary>
    /// Every problem with an API create (Story 3.6): the <paramref name="name"/>, already trimmed, 1 to 200 characters
    /// with no control character; the <paramref name="identifier"/> 1 to 255 characters, an absolute URI with a scheme,
    /// no fragment and no white space (<see cref="ApiReasons.Invalid"/>), and not under <c>urn:gatekeep:</c>
    /// (<see cref="ApiReasons.Reserved"/>). Empty when the API may be created.
    /// </summary>
    public static IReadOnlyList<ApiFieldProblem> CheckApi(string name, string identifier) => ApiRules.CheckCreate(name, identifier);

    /// <summary>
    /// Every problem with a Permission (Story 3.6): the <paramref name="value"/> <c>resource:action</c>, lowercase, each
    /// part a letter or digit then up to 63 of letters, digits, <c>_</c>, <c>.</c> and <c>-</c>; the
    /// <paramref name="description"/> 0 to 200 characters with no control character. Empty when it may be added.
    /// </summary>
    public static IReadOnlyList<ApiFieldProblem> CheckPermission(string value, string description) => ApiRules.CheckPermission(value, description);

    /// <summary>Whether <paramref name="value"/> is a <c>resource:action</c> Permission value (Story 3.6).</summary>
    public static bool IsPermissionValue(string? value) => ApiRules.ValidPermission(value);

    /// <summary>
    /// Whether <paramref name="url"/> has a custom scheme, such as <c>com.example.app:/callback</c>: one that
    /// isn't <c>http</c> or <c>https</c> (Story 3.2). Only a <c>native</c> Application may register one, and
    /// a Prod Tenant's needs an acknowledgement.
    /// </summary>
    public static bool IsCustomScheme(string url) => ApplicationSettingsRules.IsCustomScheme(url);

    /// <summary>
    /// Whether an authorization request's <paramref name="redirectUri"/> is one of <paramref name="application"/>'s
    /// callback URLs (Stories 2.9 and 3.2): exactly, string for string; or, for a <c>native</c> Application only,
    /// a registered <c>http://127.0.0.1</c> or <c>http://[::1]</c> URL that differs from it only in the port
    /// (RFC 8252 §7.3). Never the name <c>localhost</c>, and never a <c>web</c> or <c>spa</c> Application's.
    /// </summary>
    public static bool MatchesRedirectUri(DirectoryApplication application, string redirectUri)
    {
        ArgumentNullException.ThrowIfNull(application);
        return !string.IsNullOrEmpty(redirectUri)
            && application.RedirectUris.Any(registered =>
                string.Equals(registered, redirectUri, StringComparison.Ordinal)
                || (application.IsNative && LoopbackRedirects.SameButPort(registered, redirectUri)));
    }

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
    /// <c>application</c> rows, and from Story 3.6 its <c>permission</c>, then <c>api</c> rows. Sessions' and Authentication's purges must run first: their rows reference Applications.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new DirectoryPurge();

    /// <summary>
    /// The context Tenant's deleted Applications' IDs (Story 3.5), whose rows the <c>directory.application.purge</c>
    /// Operation removes: Sessions' and Authentication's purges take them, so neither reads Directory's tables. It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<IReadOnlyList<Guid>> DeletedApplicationIdsAsync(CommandContext context, CancellationToken cancellationToken) =>
        DirectoryApplicationPurge.DeletedAsync(context, cancellationToken);

    /// <summary>
    /// Directory's purge of deleted Applications (Story 3.5, AD-30): deletes the context Tenant's <c>client_secret</c>
    /// rows of <paramref name="applicationIds"/>, then those <c>application</c> rows, and of those only the ones whose
    /// <c>deleted_at</c> is set: a visible or <c>system</c> Application is never deleted. Pass the list
    /// <see cref="DeletedApplicationIdsAsync"/> read, after Sessions' and Authentication's purges of the same list: their
    /// rows reference Applications. An empty list deletes nothing. A second run deletes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task PurgeDeletedApplicationsAsync(CommandContext context, IReadOnlyCollection<Guid> applicationIds, CancellationToken cancellationToken) =>
        DirectoryApplicationPurge.PurgeAsync(context, applicationIds, cancellationToken);
}
