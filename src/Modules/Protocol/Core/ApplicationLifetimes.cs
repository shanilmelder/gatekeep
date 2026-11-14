using System.Security.Claims;
using Gatekeep.Modules.Directory.Contracts;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The lifetimes one token request's tokens are issued with (Story 3.4): its access and ID tokens', and its
/// refresh tokens' inactivity lifetime from issue and their family's absolute lifetime from authorization.
/// </summary>
internal sealed record IssuedTokenLifetimes(
    TimeSpan AccessToken,
    TimeSpan IdentityToken,
    TimeSpan RefreshTokenAbsolute,
    TimeSpan RefreshTokenInactivity);

/// <summary>
/// Where a token request's lifetimes come from (Stories 3.4 and 3.6, FR-15). <see cref="Of"/> is the one lookup: the
/// client's Application and the API the request names, the shorter of each lifetime winning. Until Story 3.7 resolves
/// the audience, no request names an API.
/// The global OpenIddict lifetimes stay the Deployment defaults, and <see cref="ApplyApplicationLifetimes"/>
/// replaces them on every token the request issues.
/// </summary>
internal static class ApplicationTokenLifetimes
{
    /// <summary>Where <see cref="ForClientAsync"/> leaves the request's lifetimes, so each handler reads the Application once.</summary>
    public const string Property = ".gatekeep_token_lifetimes";

    /// <summary>
    /// The lifetimes <paramref name="application"/>'s tokens for <paramref name="api"/> are issued with (Stories 3.4 and
    /// 3.6, FR-15): each of the four the shorter of the Application's and the API's; with no API, the Application's own,
    /// as saved. Until Story 3.7 resolves a request's audience, every caller passes no API.
    /// </summary>
    public static IssuedTokenLifetimes Of(DirectoryApplication application, DirectoryApi? api)
    {
        ArgumentNullException.ThrowIfNull(application);
        var own = new IssuedTokenLifetimes(
            application.AccessTokenLifetime,
            application.IdTokenLifetime,
            application.RefreshTokenAbsoluteLifetime,
            application.RefreshTokenInactivityLifetime);

        if (api is null)
        {
            return own;
        }

        return new IssuedTokenLifetimes(
            Shorter(own.AccessToken, api.Lifetimes.AccessTokenLifetime),
            Shorter(own.IdentityToken, api.Lifetimes.IdTokenLifetime),
            Shorter(own.RefreshTokenAbsolute, api.Lifetimes.RefreshTokenAbsoluteLifetime),
            Shorter(own.RefreshTokenInactivity, api.Lifetimes.RefreshTokenInactivityLifetime));
    }

    private static TimeSpan Shorter(TimeSpan application, int apiSeconds)
    {
        var api = TimeSpan.FromSeconds(apiSeconds);
        return api < application ? api : application;
    }

    /// <summary>
    /// The lifetimes of the request's client <paramref name="clientId"/>, read once per request from its
    /// Application in the request's own Tenant context, and kept on <paramref name="transaction"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The request has no client, or its client has no Application.</exception>
    public static async ValueTask<IssuedTokenLifetimes> ForClientAsync(
        OpenIddictServerTransaction transaction,
        IOpenIddictApplicationManager applications,
        string? clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(applications);

        if (transaction.GetProperty<IssuedTokenLifetimes>(Property) is { } known)
        {
            return known;
        }

        var application = (string.IsNullOrEmpty(clientId) ? null : await applications.FindByClientIdAsync(clientId, cancellationToken)) as DirectoryApplication
            ?? throw new InvalidOperationException("A token is issued only to a known Application.");

        // Story 3.7 passes the API the request's audience names; until then, none.
        var lifetimes = Of(application, api: null);
        transaction.SetProperty(Property, lifetimes);
        return lifetimes;
    }
}

/// <summary>
/// Issues every token of a token request for its Application's lifetimes (Story 3.4, FR-15), on
/// authorization_code, refresh_token and client_credentials alike, after OpenIddict's
/// <c>Prepare*TokenPrincipal</c> handlers set the global defaults and before the tokens are made:
/// <list type="bullet">
/// <item>the access token expires its access lifetime after its issue;</item>
/// <item>the ID token its ID lifetime after its issue;</item>
/// <item>a refresh token its inactivity lifetime after its issue; <see cref="CapRefreshTokenLifetime"/>, which runs
/// next, then cuts it to its family's absolute end.</item>
/// </list>
/// <c>expires_in</c> follows, since <see cref="ReportAccessTokenLifetime"/> reads the access token's own <c>iat</c>
/// and <c>exp</c>.
/// </summary>
internal sealed class ApplyApplicationLifetimes(IOpenIddictApplicationManager applications, TokenEndpointServices services)
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseScopedHandler<ApplyApplicationLifetimes>()
            .SetOrder(OpenIddictServerHandlers.PrepareUserCodePrincipal.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is not OpenIddictServerEndpointType.Token
            || (context.AccessTokenPrincipal is null && context.IdentityTokenPrincipal is null && context.RefreshTokenPrincipal is null))
        {
            return;
        }

        var lifetimes = await ApplicationTokenLifetimes.ForClientAsync(
            context.Transaction, applications, context.ClientId ?? context.Request?.ClientId, context.CancellationToken);

        Expire(context.AccessTokenPrincipal, lifetimes.AccessToken);
        Expire(context.IdentityTokenPrincipal, lifetimes.IdentityToken);
        Expire(context.RefreshTokenPrincipal, lifetimes.RefreshTokenInactivity);
    }

    /// <summary>Sets <paramref name="principal"/>'s expiry to its issue plus <paramref name="lifetime"/>, so <c>exp</c> − <c>iat</c> is the lifetime.</summary>
    private void Expire(ClaimsPrincipal? principal, TimeSpan lifetime)
    {
        if (principal is null)
        {
            return;
        }

        var issued = principal.GetCreationDate() ?? services.Time.GetUtcNow();
        principal.SetCreationDate(issued);
        principal.SetExpirationDate(issued + lifetime);
    }
}
