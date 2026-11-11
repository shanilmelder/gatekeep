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
    /// <c>system</c> Application's included (AD-12). It only reads.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<DirectoryApplication?> FindApplicationAsync(CommandContext context, Guid id, CancellationToken cancellationToken);

    /// <summary>
    /// Whether <paramref name="secret"/> is a live secret of the Application <paramref name="clientId"/>
    /// names, in the context's Tenant: not revoked, and with no <c>expires_at</c> or one still ahead. The
    /// stored hashes are compared in constant time. A malformed or unknown client ID is false, exactly
    /// like a wrong secret. It only reads.
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
