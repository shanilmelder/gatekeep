using System.Collections.Immutable;

namespace Gatekeep.Modules.Directory.Contracts;

/// <summary>
/// One <c>application</c> row as OpenIddict's application store hands it over (AD-8). Only Directory
/// makes one, from the row; it holds no secret, because OpenIddict never checks one (Gatekeep's
/// client authentication calls <see cref="IDirectory.VerifyClientSecretAsync"/>).
/// </summary>
public sealed class DirectoryApplication
{
    internal DirectoryApplication(Guid id, string clientId, string name, ImmutableArray<string> grantTypes, ImmutableArray<string> audiences)
    {
        Id = id;
        ClientId = clientId;
        Name = name;
        GrantTypes = grantTypes;
        Audiences = audiences;
    }

    public Guid Id { get; }

    /// <summary>The Application's <c>app_</c> public ID.</summary>
    public string ClientId { get; }

    public string Name { get; }

    /// <summary>The OAuth grant types it may use, from the row's checked set.</summary>
    public ImmutableArray<string> GrantTypes { get; }

    /// <summary>The audiences its tokens carry. Empty until Story 3.7 adds APIs.</summary>
    public ImmutableArray<string> Audiences { get; }
}
