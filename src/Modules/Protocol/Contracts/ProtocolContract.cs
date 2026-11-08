using Gatekeep.Modules.Protocol.Adapters;
using Gatekeep.Modules.Protocol.Core;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// Each Tenant's own OpenID Provider on Host.Hosted (Stories 2.3 and 2.5, AD-8, AD-9): OpenIddict
/// 7.7.2, wrapped per Tenant. It serves discovery, JWKS and the token endpoint, which issues access
/// tokens by Client Credentials only.
/// </summary>
public static class ProtocolContract
{
    public const string ConfigurationPath = "/.well-known/openid-configuration";

    public const string JsonWebKeySetPath = "/.well-known/jwks";

    public const string TokenPath = "/connect/token";

    /// <summary>
    /// The one audience a Client Credentials token carries while its Application has none (Story 2.5).
    /// Story 3.7 replaces it with real APIs. No request may name an audience or resource here, so the
    /// Management API audience is never minted on a Tenant host.
    /// </summary>
    public const string PlaceholderAudience = "urn:gatekeep:placeholder";

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
    /// The token endpoint runs as <c>gk_hosted</c> too, in one transaction per request. Key custody is
    /// the host's <c>IKeyCustody</c>, and audit the host's <c>IAuditAppender</c>. The token request limits
    /// are <see cref="TokenRequestLimits"/>'s, unless the host registered its own first.
    /// </summary>
    public static IServiceCollection AddGatekeepProtocol(
        this IServiceCollection services,
        Func<IServiceProvider, string> hostedConnectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(hostedConnectionString);

        services.AddSingleton<ITenantKeyReader>(provider => new TenantKeyReader(() => hostedConnectionString(provider)));

        // One listening connection, as gk_hosted, started on the first Tenant request (Story 2.4).
        services.AddSingleton<ITenantKeyChanges>(provider => new SigningKeyChangeListener(
            () => hostedConnectionString(provider),
            provider.GetService<Microsoft.Extensions.Logging.ILogger<SigningKeyChangeListener>>()));
        ProtocolServer.Add(services, hostedConnectionString);
        return services;
    }

    /// <summary>
    /// Runs OpenIddict on the request, after Tenant resolution and before routing. A path OpenIddict
    /// doesn't serve passes through to whatever follows.
    /// </summary>
    public static IApplicationBuilder UseGatekeepProtocol(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseAuthentication();
    }
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
