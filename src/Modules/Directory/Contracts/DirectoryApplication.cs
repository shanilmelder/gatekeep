using System.Collections.Immutable;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// One <c>application</c> row as OpenIddict's application store hands it over (AD-8). Only Directory
/// makes one, from the row; it holds no secret, because OpenIddict never checks one (Gatekeep's
/// client authentication calls <see cref="IDirectory.VerifyClientSecretAsync"/>).
/// </summary>
public sealed class DirectoryApplication
{
    internal DirectoryApplication(
        Guid id,
        string clientId,
        string name,
        string kind,
        ImmutableArray<string> grantTypes,
        ImmutableArray<string> redirectUris,
        ImmutableArray<string> postLogoutRedirectUris,
        ImmutableArray<string> webOrigins,
        DateTimeOffset createdAt,
        ApplicationLifetimes lifetimes)
    {
        Id = id;
        ClientId = clientId;
        Name = name;
        Kind = kind;
        GrantTypes = grantTypes;
        RedirectUris = redirectUris;
        PostLogoutRedirectUris = postLogoutRedirectUris;
        WebOrigins = webOrigins;
        CreatedAt = createdAt;
        Lifetimes = lifetimes;
        AccessTokenLifetime = TimeSpan.FromSeconds(lifetimes.AccessTokenLifetime);
        IdTokenLifetime = TimeSpan.FromSeconds(lifetimes.IdTokenLifetime);
        RefreshTokenAbsoluteLifetime = TimeSpan.FromSeconds(lifetimes.RefreshTokenAbsoluteLifetime);
        RefreshTokenInactivityLifetime = TimeSpan.FromSeconds(lifetimes.RefreshTokenInactivityLifetime);
    }

    public Guid Id { get; }

    /// <summary>The Application's <c>app_</c> public ID.</summary>
    public string ClientId { get; }

    public string Name { get; }

    /// <summary>
    /// The row's kind: <c>machine</c> (Client Credentials, Story 2.5), <c>web</c> (the code flow,
    /// Story 2.9), or from Story 3.1 <c>spa</c> or <c>native</c>, the code flow's public clients from
    /// Story 3.2. The hidden <c>system</c> Application is never handed out.
    /// </summary>
    public string Kind { get; }

    /// <summary>Whether its kind authenticates with a credential: <c>web</c> and <c>machine</c> do, <c>spa</c> and <c>native</c> don't (Story 3.1).</summary>
    public bool CredentialRequired => DirectoryContract.CredentialRequired(Kind);

    /// <summary>Whether this is a <c>web</c> client, a confidential client of the code flow.</summary>
    public bool IsWeb => Kind == DirectoryContract.WebKind;

    /// <summary>Whether its kind may sign Users in by the code flow with PKCE: <c>web</c>, <c>spa</c> and <c>native</c> (Story 3.2).</summary>
    public bool SignsUsersIn => DirectoryContract.SignsUsersIn(Kind);

    /// <summary>Whether it is a public client, which holds no secret and authenticates by its <c>client_id</c> alone: <c>spa</c> and <c>native</c> (Story 3.2).</summary>
    public bool IsPublic => DirectoryContract.IsPublic(Kind);

    /// <summary>Whether it is a <c>native</c> Application, whose loopback redirect URIs may vary in port (RFC 8252 §7.3, Story 3.2).</summary>
    public bool IsNative => Kind == DirectoryContract.NativeKind;

    /// <summary>The OAuth grant types it may use, from the row's checked set, stored sorted.</summary>
    public ImmutableArray<string> GrantTypes { get; }

    /// <summary>
    /// Its Allowed Callback URLs, the OAuth redirect URIs, matched exactly but for a <c>native</c>
    /// Application's loopback port (Story 3.2). Always empty for <c>machine</c>.
    /// </summary>
    public ImmutableArray<string> RedirectUris { get; }

    /// <summary>Its Allowed Logout URLs, the post-logout redirect URIs (Story 3.2; Story 4.13 uses them). Always empty for <c>machine</c>.</summary>
    public ImmutableArray<string> PostLogoutRedirectUris { get; }

    /// <summary>Its Allowed Web Origins, each <c>scheme://host[:port]</c> (Story 3.2). Always empty for <c>native</c> and <c>machine</c>.</summary>
    public ImmutableArray<string> WebOrigins { get; }

    /// <summary>When the row was written.</summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>Its four token lifetimes in whole seconds, as stored (Story 3.4).</summary>
    public ApplicationLifetimes Lifetimes { get; }

    /// <summary>How long its access tokens live (Story 3.4): 15 minutes by default, never more than 1 hour.</summary>
    public TimeSpan AccessTokenLifetime { get; }

    /// <summary>How long its ID tokens live (Story 3.4): 15 minutes by default, never more than 1 hour.</summary>
    public TimeSpan IdTokenLifetime { get; }

    /// <summary>
    /// How long a Token Family of its refresh tokens lives from its authorization, however often it rotates
    /// (Story 3.4): 30 days by default, never more than 90. It is read at each refresh.
    /// </summary>
    public TimeSpan RefreshTokenAbsoluteLifetime { get; }

    /// <summary>How long one of its refresh tokens lives unused from its issue (Story 3.4): 7 days by default, never more than 30.</summary>
    public TimeSpan RefreshTokenInactivityLifetime { get; }
}
