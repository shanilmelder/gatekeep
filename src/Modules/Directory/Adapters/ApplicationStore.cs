using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Directory.Core;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Gatekeep.Modules.Directory.Adapters;

/// <summary>
/// OpenIddict's application store (AD-8), on the request's own context. It only reads: Directory
/// writes Applications itself, never through OpenIddict's manager, so every write is refused, as are
/// LINQ queries and listing, which nothing on the Hosted path calls. Every Application is a
/// confidential client with no secret column: Gatekeep's client authentication calls
/// <see cref="IDirectory.VerifyClientSecretAsync"/> in place of OpenIddict's secret check. Both lookups
/// hide the Tenant's <c>system</c> Application (Story 2.8, AD-12): its ID and <c>client_id</c> find
/// nothing, so OpenIddict refuses it as an unknown client and never issues a code or token for it.
/// Story 2.9: a <c>web</c> client's redirect URIs, its authorization endpoint and <c>code</c> response
/// type permissions and its PKCE requirement. Every Application stays confidential.
/// </summary>
internal sealed class ApplicationStore(Func<CommandContext> context) : IOpenIddictApplicationStore<DirectoryApplication>
{
    public async ValueTask<DirectoryApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken) =>
        Guid.TryParse(identifier, out var id) && id != Guid.Empty
            ? await ApplicationRows.FindAsync(context(), id, cancellationToken)
            : null;

    public async ValueTask<DirectoryApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken) =>
        PublicId.TryParse(PublicIdType.Application, identifier, out var id)
            ? await ApplicationRows.FindAsync(context(), id, cancellationToken)
            : null;

    public ValueTask<string?> GetIdAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(Checked(application).Id.ToString());

    public ValueTask<string?> GetClientIdAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(Checked(application).ClientId);

    /// <summary>Always empty: no secret is kept where OpenIddict could read it (AD-8).</summary>
    public ValueTask<string?> GetClientSecretAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new((string?)null);

    public ValueTask<string?> GetClientTypeAsync(DirectoryApplication application, CancellationToken cancellationToken)
    {
        Checked(application);
        return new(ClientTypes.Confidential);
    }

    public ValueTask<string?> GetApplicationTypeAsync(DirectoryApplication application, CancellationToken cancellationToken)
    {
        Checked(application);
        return new(ApplicationTypes.Web);
    }

    public ValueTask<string?> GetConsentTypeAsync(DirectoryApplication application, CancellationToken cancellationToken)
    {
        Checked(application);
        return new(ConsentTypes.Implicit);
    }

    public ValueTask<string?> GetDisplayNameAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(Checked(application).Name);

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(ImmutableDictionary<CultureInfo, string>.Empty);

    public ValueTask<JsonWebKeySet?> GetJsonWebKeySetAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new((JsonWebKeySet?)null);

    /// <summary>
    /// The token endpoint, and a <c>gt:</c> permission for each grant type the row allows. A <c>web</c>
    /// client also gets the authorization endpoint and the <c>code</c> response type, the only one
    /// (Story 2.9). No <c>scp:</c> permission is given: <c>openid</c>, the one scope, needs none.
    /// </summary>
    public ValueTask<ImmutableArray<string>> GetPermissionsAsync(DirectoryApplication application, CancellationToken cancellationToken)
    {
        var row = Checked(application);
        string[] code = row.IsWeb ? [Permissions.Endpoints.Authorization, Permissions.ResponseTypes.Code] : [];
        return new([Permissions.Endpoints.Token, .. code, .. row.GrantTypes.Select(g => Permissions.Prefixes.GrantType + g)]);
    }

    public ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(ImmutableArray<string>.Empty);

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(ImmutableDictionary<string, JsonElement>.Empty);

    /// <summary>A <c>web</c> client's registered redirect URIs, which OpenIddict matches exactly (Story 2.9).</summary>
    public ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(Checked(application).RedirectUris);

    /// <summary>A <c>web</c> client must use PKCE (Story 2.9), as every client must on the Deployment.</summary>
    public ValueTask<ImmutableArray<string>> GetRequirementsAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(Checked(application).IsWeb ? [Requirements.Features.ProofKeyForCodeExchange] : ImmutableArray<string>.Empty);

    public ValueTask<ImmutableDictionary<string, string>> GetSettingsAsync(DirectoryApplication application, CancellationToken cancellationToken) =>
        new(ImmutableDictionary<string, string>.Empty);

    public IAsyncEnumerable<DirectoryApplication> FindByPostLogoutRedirectUriAsync(string uri, CancellationToken cancellationToken) =>
        throw Unsupported();

    /// <summary>
    /// Unused: OpenIddict checks a redirect URI against the client its <c>client_id</c> names, never by
    /// looking an Application up by URI.
    /// </summary>
    public IAsyncEnumerable<DirectoryApplication> FindByRedirectUriAsync(string uri, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> CountAsync(CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<DirectoryApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<DirectoryApplication>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<DirectoryApplication> ListAsync(int? count, int? offset, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<DirectoryApplication>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<DirectoryApplication> InstantiateAsync(CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask CreateAsync(DirectoryApplication application, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask UpdateAsync(DirectoryApplication application, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask DeleteAsync(DirectoryApplication application, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetApplicationTypeAsync(DirectoryApplication application, string? type, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetClientIdAsync(DirectoryApplication application, string? identifier, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetClientSecretAsync(DirectoryApplication application, string? secret, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetClientTypeAsync(DirectoryApplication application, string? type, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetConsentTypeAsync(DirectoryApplication application, string? type, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetDisplayNameAsync(DirectoryApplication application, string? name, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetDisplayNamesAsync(DirectoryApplication application, ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken) =>
        throw ReadOnly();

    public ValueTask SetJsonWebKeySetAsync(DirectoryApplication application, JsonWebKeySet? set, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask SetPermissionsAsync(DirectoryApplication application, ImmutableArray<string> permissions, CancellationToken cancellationToken) =>
        throw ReadOnly();

    public ValueTask SetPostLogoutRedirectUrisAsync(DirectoryApplication application, ImmutableArray<string> uris, CancellationToken cancellationToken) =>
        throw ReadOnly();

    public ValueTask SetPropertiesAsync(DirectoryApplication application, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        throw ReadOnly();

    public ValueTask SetRedirectUrisAsync(DirectoryApplication application, ImmutableArray<string> uris, CancellationToken cancellationToken) =>
        throw ReadOnly();

    public ValueTask SetRequirementsAsync(DirectoryApplication application, ImmutableArray<string> requirements, CancellationToken cancellationToken) =>
        throw ReadOnly();

    public ValueTask SetSettingsAsync(DirectoryApplication application, ImmutableDictionary<string, string> settings, CancellationToken cancellationToken) =>
        throw ReadOnly();

    private static DirectoryApplication Checked(DirectoryApplication application) =>
        application ?? throw new ArgumentNullException(nameof(application));

    private static NotSupportedException ReadOnly() =>
        new("Directory writes Applications itself, never through OpenIddict (AD-8).");

    private static NotSupportedException Unsupported() =>
        new("Nothing on the Hosted path lists or queries Applications.");
}
