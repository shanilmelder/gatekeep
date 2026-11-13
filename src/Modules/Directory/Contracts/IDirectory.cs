using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// A machine client just created (Story 2.5): its Application, its OAuth <c>client_id</c> (the
/// Application's <c>app_</c> public ID) and its client secret, shown this once (AD-24). The secret is
/// <c>{tenantPublicId}.{base64url of 32 random bytes}</c> (AD-9); only its SHA-256 is stored, so it can
/// never be read back.
/// </summary>
public sealed class CreatedMachineClient
{
    public required Guid ApplicationId { get; init; }

    public required string ClientId { get; init; }

    public required RevealOnce<string> Secret { get; init; }
}

/// <summary>
/// A web client just created (Story 2.9): a confidential client allowed only the authorization code
/// grant, to its registered redirect URIs. Its <c>client_id</c> and secret have the shape and the
/// once-only reveal of <see cref="CreatedMachineClient"/>'s.
/// </summary>
public sealed class CreatedWebClient
{
    public required Guid ApplicationId { get; init; }

    public required string ClientId { get; init; }

    public required RevealOnce<string> Secret { get; init; }
}

/// <summary>
/// One page of a Tenant's Applications (Story 3.1), newest first, and the ID to pass as the next
/// page's <c>after</c> when another page follows, else null.
/// </summary>
public sealed record DirectoryApplicationPage(IReadOnlyList<DirectoryApplication> Applications, Guid? NextAfter);

/// <summary>
/// One live client secret of an Application (Story 3.3): its row ID, when it was created and, for a
/// rotated-out secret still in its overlap, when it stops working; null for the current secret. Never its
/// value or its hash.
/// </summary>
public sealed record DirectoryClientSecret(Guid Id, DateTimeOffset CreatedAt, DateTimeOffset? ExpiresAt);

/// <summary>How a client secret create, rotation or revocation ended (Story 3.3).</summary>
public enum ClientSecretWriteStatus
{
    /// <summary>Written, with its event: the result holds the live secrets after the write.</summary>
    Done,

    /// <summary>The Tenant has no visible Application by that ID, or no live secret by that ID of it. Nothing was written.</summary>
    NotFound,

    /// <summary>The Application is a <c>spa</c> or <c>native</c> one, which holds no secret. Nothing was written.</summary>
    NotApplicable,

    /// <summary>The Application already holds <see cref="Gatekeep.Kernel.Limits.SecurityLimits.MaxLiveClientSecrets"/> live secrets. Nothing was written.</summary>
    LimitReached,
}

/// <summary>
/// A client secret write's result (Story 3.3): its status, the live secrets after it, newest first, and, for
/// a create or rotation, the new secret, shown this once (AD-24) and stored only as its SHA-256.
/// </summary>
public sealed class ClientSecretWrite
{
    public required ClientSecretWriteStatus Status { get; init; }

    /// <summary>The new secret, <c>{tenantPublicId}.{base64url of 32 random bytes}</c>, on a create or rotation only.</summary>
    public RevealOnce<string>? Secret { get; init; }

    /// <summary>The Application's live secrets after the write, newest first; empty when nothing was written.</summary>
    public IReadOnlyList<DirectoryClientSecret> Secrets { get; init; } = [];
}

/// <summary>Applications and their client secrets (AD-8, AD-27). Directory owns <c>application</c> and <c>client_secret</c>.</summary>
public interface IDirectory
{
    /// <summary>
    /// Writes a <c>machine</c> Application allowed the <c>client_credentials</c> grant, with no audience
    /// (Story 3.7 adds them), its one client secret, and one <c>directory.application.created</c> audit
    /// event by the System, all in the caller's context and only in its Tenant. Directory writes the rows
    /// itself, never through OpenIddict's manager, whose validation wants a secret column.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException"><paramref name="name"/> is empty, longer than 200 characters or holds a NUL character.</exception>
    [StateChanging]
    Task<CreatedMachineClient> CreateMachineClientAsync(CommandContext context, string name, CancellationToken cancellationToken);

    /// <summary>
    /// Writes a <c>web</c> Application allowed the <c>authorization_code</c> grant and, from Story 2.10,
    /// <c>refresh_token</c>, so it may ask for <c>offline_access</c>, with its
    /// <paramref name="redirectUris"/> registered exactly as given and no audience, its one client
    /// secret, and one <c>directory.application.created</c> audit event by the System, all in the
    /// caller's context and only in its Tenant (Story 2.9), as <see cref="CreateMachineClientAsync"/> does.
    /// Every web client is confidential: it authenticates at the token endpoint with its secret, and
    /// must also use PKCE.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="name"/> is empty, longer than 200 characters or holds a NUL character; or there
    /// are no redirect URIs, more than <see cref="DirectoryContract.MaxRedirectUris"/>, or a repeated one;
    /// or one isn't an absolute <c>https</c> URI (or <c>http</c> on a loopback host only), has a fragment,
    /// userinfo or white space, or is longer than <see cref="DirectoryContract.MaxRedirectUriLength"/>
    /// characters. Nothing is written.
    /// </exception>
    [StateChanging]
    Task<CreatedWebClient> CreateWebClientAsync(
        CommandContext context,
        string name,
        IReadOnlyList<string> redirectUris,
        CancellationToken cancellationToken);

    /// <summary>
    /// Writes an Application an Admin registers (Story 3.1, FR-11): <paramref name="name"/> as given and
    /// <paramref name="kind"/>, one of <see cref="DirectoryContract.CreatableKinds"/>, with the kind's
    /// default grants (<c>machine</c> <c>{client_credentials}</c>, <c>web</c> <c>{authorization_code}</c>,
    /// <c>spa</c> and <c>native</c> none), no redirect URI, no audience and no client secret, and one
    /// <c>directory.application.created</c> audit event by <paramref name="actor"/>, all in the caller's
    /// context and only in its Tenant. With no secret, a <c>web</c> or <c>machine</c> Application fails
    /// client authentication until one is created (Story 3.3), and no flow serves the others yet.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="name"/> is empty or white space, longer than <see cref="DirectoryContract.MaxNameLength"/>
    /// characters or holds a control character; or <paramref name="kind"/> isn't creatable. Nothing is written.
    /// </exception>
    [StateChanging]
    Task<DirectoryApplication> CreateApplicationAsync(
        CommandContext context,
        Actor actor,
        string name,
        string kind,
        CancellationToken cancellationToken);

    /// <summary>
    /// One page of the context Tenant's Applications (Story 3.1): at most <paramref name="limit"/>,
    /// newest first by ID (UUIDv7), after <paramref name="after"/> when it is given. The <c>system</c>
    /// Application is never among them (AD-12). It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<DirectoryApplicationPage> ListApplicationsPageAsync(
        CommandContext context,
        Guid? after,
        int limit,
        CancellationToken cancellationToken);

    /// <summary>
    /// The context Tenant's Application <paramref name="id"/>, or null when it has none by that ID, the
    /// <c>system</c> Application's included (AD-12), and from Story 3.5 a deleted one's. It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<DirectoryApplication?> FindApplicationAsync(CommandContext context, Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// As <see cref="FindApplicationAsync"/>, under the row's lock (<c>FOR NO KEY UPDATE</c>), held to the end
    /// of the caller's transaction (Story 3.2): a settings save decides on the settings it replaces. The
    /// <c>system</c> Application is never found.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<DirectoryApplication?> LockApplicationAsync(CommandContext context, Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the context Tenant's Application <paramref name="id"/>'s settings (Story 3.2, FR-11, FR-13):
    /// its callback, logout and web origin URLs exactly as given and its grants sorted, then writes
    /// <c>directory.application.updated</c> by <paramref name="actor"/> and, when
    /// <paramref name="prodCallbackAdded"/>, <c>directory.application.prod_callback_added</c>, all in the
    /// caller's transaction. The caller has decided that something changes. The <c>system</c> Application is
    /// never updated. Returns the updated Application, or null when the Tenant has no visible one by that ID.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">
    /// The settings break a rule of <see cref="DirectoryContract.CheckSettings"/> for the Application's kind. Nothing is written.
    /// </exception>
    [StateChanging]
    Task<DirectoryApplication?> UpdateApplicationSettingsAsync(
        CommandContext context,
        Actor actor,
        Guid id,
        ApplicationSettings settings,
        bool prodCallbackAdded,
        CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the context Tenant's Application <paramref name="id"/>'s four token lifetimes (Story 3.4, FR-15),
    /// under the row's lock, in the caller's transaction. When they differ from what is stored it writes them and
    /// <c>directory.application.updated</c> by <paramref name="actor"/>; when they don't it writes nothing and
    /// no event. The <c>system</c> Application is never updated. Returns the Application as it now stands and
    /// whether it changed, or null when the Tenant has no visible one by that ID.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">
    /// A lifetime breaks a limit of <see cref="DirectoryContract.CheckLifetimes"/>. Nothing is written.
    /// </exception>
    [StateChanging]
    Task<ApplicationLifetimesWrite?> UpdateApplicationLifetimesAsync(
        CommandContext context,
        Actor actor,
        Guid id,
        ApplicationLifetimes lifetimes,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes the context Tenant's Application <paramref name="id"/> (Story 3.5, FR-11, AD-13), under the row's
    /// lock, in the caller's transaction: sets its <c>deleted_at</c>, so every read hides it at once and client
    /// authentication refuses it; revokes its live client secrets; revokes every Token Family and token of it
    /// through <c>ISessions.RevokeAccessAsync</c> with the Application scope and the <c>application_deleted</c>
    /// reason, which writes <c>sessions.access.revoked</c>; then writes <c>directory.application.deleted</c>, all by
    /// <paramref name="actor"/>. Access tokens already issued stay valid until they expire. No row is deleted: the
    /// <c>directory.application.purge</c> Operation does that. The <c>system</c> Application is never deleted.
    /// Returns false, with nothing written, when the Tenant has no visible Application by that ID: an unknown one,
    /// one already deleted and the <c>system</c> one alike.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<bool> DeleteApplicationAsync(CommandContext context, Actor actor, Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// The live client secrets of the context Tenant's Application <paramref name="applicationId"/> (Story 3.3),
    /// newest first: not revoked, and with no <c>expires_at</c> or one still ahead by the database's clock.
    /// Always empty for a <c>spa</c> or <c>native</c> Application. Null when the Tenant has no visible
    /// Application by that ID. It only reads, and never reads a hash.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<IReadOnlyList<DirectoryClientSecret>?> ListClientSecretsAsync(CommandContext context, Guid applicationId, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a client secret for the context Tenant's <c>web</c> or <c>machine</c> Application
    /// <paramref name="applicationId"/> (Story 3.3, FR-12, AD-24), under the Application's row lock, in the
    /// caller's transaction. With no current secret it inserts one and writes
    /// <c>directory.client_secret.created</c>. With one, it rotates: the current secret's <c>expires_at</c>
    /// becomes the database's <c>now()</c> plus <see cref="Gatekeep.Kernel.Limits.SecurityLimits.ClientSecretOverlap"/>,
    /// the new one is inserted, and <c>directory.client_secret.rotated</c> is written. Each event is by
    /// <paramref name="actor"/> and names the Application only. Only the new secret's SHA-256 is stored.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<ClientSecretWrite> CreateClientSecretAsync(CommandContext context, Actor actor, Guid applicationId, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes the live client secret <paramref name="secretId"/> of the context Tenant's <c>web</c> or
    /// <c>machine</c> Application <paramref name="applicationId"/> (Story 3.3, FR-12): its <c>revoked_at</c> becomes
    /// the database's <c>now()</c>, so client authentication refuses it at once, and
    /// <c>directory.client_secret.revoked</c> is written by <paramref name="actor"/>, in the caller's
    /// transaction. It ends a rotated-out secret's overlap early and revokes the current one alike, even when
    /// none is left. A secret that is unknown, another Application's, or already revoked or expired is
    /// <see cref="ClientSecretWriteStatus.NotFound"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<ClientSecretWrite> RevokeClientSecretAsync(CommandContext context, Actor actor, Guid applicationId, Guid secretId, CancellationToken cancellationToken);

    /// <summary>
    /// Whether <paramref name="secret"/> is a live secret of the Application <paramref name="clientId"/>
    /// names, in the context's Tenant: not revoked, and with no <c>expires_at</c> or one still ahead. The
    /// stored hashes are compared in constant time. A malformed or unknown client ID, the <c>system</c> Application's
    /// and from Story 3.5 a deleted Application's, is false, exactly like a wrong secret. It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<bool> VerifyClientSecretAsync(CommandContext context, string clientId, Secret<string> secret, CancellationToken cancellationToken);

    /// <summary>
    /// Makes sure the context's Tenant has its one hidden <c>system</c> Application (AD-12, AR-43, Story 2.8),
    /// the one Portal sign-in binds its <c>signin_transaction</c> to: inserts it, named
    /// <see cref="DirectoryContract.SystemApplicationName"/>, with no grant, audience or secret, only if the
    /// Tenant has none, and returns its ID either way. It writes no audit event: the Tenant's
    /// <c>tenancy.tenant.activated</c>, in the same transaction, records the creation, and a Log event naming
    /// the hidden Application would expose it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<Guid> EnsureSystemApplicationAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// The ID of the context Tenant's <c>system</c> Application, or null when it has none (Story 2.8). It
    /// only reads, and is the only query that selects that row: every other read hides it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<Guid?> FindSystemApplicationAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// The context Tenant's Applications, ordered by creation time then ID. The <c>system</c> Application is
    /// never among them (AD-12). It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<IReadOnlyList<DirectoryApplication>> ListApplicationsAsync(CommandContext context, CancellationToken cancellationToken);
}
