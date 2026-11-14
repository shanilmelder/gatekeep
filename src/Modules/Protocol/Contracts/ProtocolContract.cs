using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Adapters;
using Gatekeep.Modules.Protocol.Core;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// Each Tenant's own OpenID Provider on Host.Hosted (Stories 2.3, 2.5, 2.9, 2.10 and 2.11, AD-8, AD-9): OpenIddict
/// 7.7.2, wrapped per Tenant. It serves discovery, JWKS, the authorization endpoint (the code flow with
/// S256 PKCE only), the token endpoint (Client Credentials, the authorization code grant and its
/// rotating refresh tokens), userinfo and revocation.
/// </summary>
public static class ProtocolContract
{
    public const string ConfigurationPath = "/.well-known/openid-configuration";

    public const string JsonWebKeySetPath = "/.well-known/jwks";

    public const string TokenPath = "/connect/token";

    /// <summary>The authorization endpoint (Story 2.9): the code flow with S256 PKCE, and nothing else.</summary>
    public const string AuthorizePath = "/connect/authorize";

    /// <summary>
    /// The userinfo endpoint (Story 2.11, OIDC Core §5.3): GET or POST with this Tenant's access token as a
    /// bearer in the <c>Authorization</c> header only. It answers exactly <c>{"sub": "usr_…"}</c>.
    /// </summary>
    public const string UserinfoPath = "/connect/userinfo";

    /// <summary>
    /// The revocation endpoint (Story 2.11, RFC 7009): a client ends its own refresh token's Token Family.
    /// Access and ID tokens aren't revocable (AD-13) and get <c>unsupported_token_type</c>.
    /// </summary>
    public const string RevocationPath = "/connect/revoke";

    /// <summary>The <c>kid</c> of the global signing credential, which is inert: no Tenant's JWKS or token carries it.</summary>
    public const string InertSigningKeyId = InertCredentials.SigningKeyId;

    /// <summary>The <c>kid</c> of the global encryption credential, which is inert as well.</summary>
    public const string InertEncryptionKeyId = InertCredentials.EncryptionKeyId;

    /// <summary>
    /// Registers the OpenIddict server, its stores and the Tenant runtimes. Its global options hold only
    /// inert credentials, which throw on any use; the first Gatekeep handler swaps in the request's Tenant
    /// options, built from the same options pipeline, with that Tenant's stored issuer, its Signing
    /// Keys through Transit and its unwrapped token protection key, read in a short read-only Tenant
    /// scope as <c>gk_hosted</c> through <paramref name="hostedConnectionString"/>, read on first use.
    /// The authorization and token endpoints run as <c>gk_hosted</c> too, in one transaction per request.
    /// Key custody is the host's <c>IKeyCustody</c>, and audit the host's <c>IAuditAppender</c>. The token
    /// request limits are <see cref="TokenRequestLimits"/>'s, unless the host registered its own first.
    /// The authorization endpoint completes a sign-in through <see cref="IAuthorizationSignIn"/>:
    /// <see cref="UnavailableSignIn"/>, which completes none, unless the host registered its own first.
    /// <paramref name="pageHeaders"/> sets the host's browser-page headers (AD-21) on the one page the
    /// authorization endpoint shows itself, for a request it can't send back to any client.
    /// </summary>
    public static IServiceCollection AddGatekeepProtocol(
        this IServiceCollection services,
        Func<IServiceProvider, string> hostedConnectionString,
        Action<IHeaderDictionary> pageHeaders)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(hostedConnectionString);
        ArgumentNullException.ThrowIfNull(pageHeaders);

        services.AddSingleton<ITenantKeyReader>(provider => new TenantKeyReader(() => hostedConnectionString(provider)));

        // One listening connection, as gk_hosted, started on the first Tenant request (Story 2.4).
        services.AddSingleton<ITenantKeyChanges>(provider => new SigningKeyChangeListener(
            () => hostedConnectionString(provider),
            provider.GetService<Microsoft.Extensions.Logging.ILogger<SigningKeyChangeListener>>()));
        services.AddSingleton(new ProtocolPageHeaders(pageHeaders));

        // The release build's sign-in, unless the host registered its own first (only tests do).
        services.TryAddSingleton<IAuthorizationSignIn, UnavailableSignIn>();
        ProtocolServer.Add(services, hostedConnectionString);
        return services;
    }

    /// <summary>
    /// Runs OpenIddict on the request, after Tenant resolution and before routing, then the authorization
    /// endpoint's passthrough, which completes a validated authorization request. A path OpenIddict
    /// doesn't serve passes through to whatever follows.
    /// </summary>
    public static IApplicationBuilder UseGatekeepProtocol(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.UseAuthentication();
        return app.Use(AuthorizePassthrough.InvokeAsync);
    }
}

/// <summary>
/// The sign-in seam of the authorization endpoint (Story 2.9, AD-8). Protocol begins the sign-in with
/// <c>IAuthentication.BeginAsync</c>, then asks this port to complete it. A result signs the User in:
/// the Token Family is anchored to its Session and a code is issued. <see langword="null"/> means no
/// sign-in completed, and the client gets <c>temporarily_unavailable</c>. A release build registers
/// <see cref="UnavailableSignIn"/> until Stories 4.1 and 4.2 add the screens; only the tests plug in an
/// authenticator.
/// </summary>
public interface IAuthorizationSignIn
{
    /// <summary>
    /// Completes <paramref name="signIn"/>, begun for the validated authorization request on
    /// <paramref name="http"/>, in the request's own Tenant <paramref name="context"/>, whose transaction
    /// commits only if a code is issued. <paramref name="authenticatedSince"/> is the freshness the request
    /// demands (Story 2.11, OIDC Core §3.1.2.1): from <c>prompt=login</c>, the time the request started; from
    /// <c>max_age</c>, that many seconds before now; the later of the two when both are given; null when
    /// neither is. A result whose <see cref="AuthenticationResult.AuthTime"/> is before it (exactly for
    /// <c>prompt=login</c>, to the second for <c>max_age</c>) is refused with <c>login_required</c> and no code, so a sign-in should authenticate the User again
    /// rather than reuse an older authentication (Story 4.2).
    /// </summary>
    ValueTask<AuthenticationResult?> CompleteAsync(
        CommandContext context,
        StartedSignIn signIn,
        DateTimeOffset? authenticatedSince,
        HttpContext http,
        CancellationToken cancellationToken);
}

/// <summary>
/// The release build's sign-in (Story 2.9): it completes nothing, so the authorization endpoint answers
/// every valid request with <c>temporarily_unavailable</c> and issues no code. Stories 4.1 and 4.2
/// replace it with the sign-in screens and transaction-cookie resumption.
/// </summary>
public sealed class UnavailableSignIn : IAuthorizationSignIn
{
    public ValueTask<AuthenticationResult?> CompleteAsync(
        CommandContext context,
        StartedSignIn signIn,
        DateTimeOffset? authenticatedSince,
        HttpContext http,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<AuthenticationResult?>(null);
}

/// <summary>
/// A Tenant's OpenIddict options, as its requests use them: a copy of the Deployment's options
/// with that Tenant's issuer and credentials. A copy is kept for at most five seconds and never
/// when building it failed.
/// </summary>
public interface ITenantServerOptions
{
    /// <exception cref="Gatekeep.Kernel.Secrets.KeyCustodyException">Key custody failed.</exception>
    /// <exception cref="TimeoutException">Key custody or the database didn't answer in time.</exception>
    /// <exception cref="InvalidOperationException">The Tenant's stored issuer or keys can't be served.</exception>
    ValueTask<OpenIddictServerOptions> GetAsync(ResolvedTenant tenant, CancellationToken cancellationToken);
}

/// <summary>
/// The limits a Tenant's token endpoint counts every request under, before its client is
/// authenticated (Story 2.5, AD-14): per Tenant and per source. The defaults are Authentication's
/// policies, from the §5.2 limits; a host registers its own only to test them.
/// </summary>
public sealed record TokenRequestLimits(Gatekeep.Kernel.RateLimiting.RateLimitPolicy Tenant, Gatekeep.Kernel.RateLimiting.RateLimitPolicy Source);
