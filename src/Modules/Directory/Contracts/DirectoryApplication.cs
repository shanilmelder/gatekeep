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
        ImmutableArray<string> audiences,
        ImmutableArray<string> redirectUris,
        DateTimeOffset createdAt)
    {
        Id = id;
        ClientId = clientId;
        Name = name;
        Kind = kind;
        GrantTypes = grantTypes;
        Audiences = audiences;
        RedirectUris = redirectUris;
        CreatedAt = createdAt;
    }

    public Guid Id { get; }

    /// <summary>The Application's <c>app_</c> public ID.</summary>
    public string ClientId { get; }

    public string Name { get; }

    /// <summary>
    /// The row's kind: <c>machine</c> (Client Credentials, Story 2.5), <c>web</c> (the code flow,
    /// Story 2.9), or from Story 3.1 <c>spa</c> or <c>native</c>, which no flow serves yet. The hidden
    /// <c>system</c> Application is never handed out.
    /// </summary>
    public string Kind { get; }

    /// <summary>Whether its kind authenticates with a credential: <c>web</c> and <c>machine</c> do, <c>spa</c> and <c>native</c> don't (Story 3.1).</summary>
    public bool CredentialRequired => DirectoryContract.CredentialRequired(Kind);

    /// <summary>Whether this is a <c>web</c> client, which signs Users in by the code flow with PKCE.</summary>
    public bool IsWeb => Kind == DirectoryContract.WebKind;

    /// <summary>The OAuth grant types it may use, from the row's checked set.</summary>
    public ImmutableArray<string> GrantTypes { get; }

    /// <summary>The audiences its tokens carry. Empty until Story 3.7 adds APIs.</summary>
    public ImmutableArray<string> Audiences { get; }

    /// <summary>A <c>web</c> client's registered redirect URIs, matched exactly. Empty for any other kind.</summary>
    public ImmutableArray<string> RedirectUris { get; }

    /// <summary>When the row was written.</summary>
    public DateTimeOffset CreatedAt { get; }
}
