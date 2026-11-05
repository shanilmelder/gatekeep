using Gatekeep.Modules.Protocol.Adapters;
using Gatekeep.Modules.Protocol.Core;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// Each Tenant's own OpenID Provider on Host.Hosted (Story 2.3, AD-8, AD-9): OpenIddict 7.7.2,
/// wrapped per Tenant. So far it serves only discovery and JWKS. Its token endpoint exists only
/// because OpenIddict won't start without a flow, and it refuses every request until Story 2.5.
/// </summary>
public static class ProtocolContract
{
    public const string ConfigurationPath = "/.well-known/openid-configuration";

    public const string JsonWebKeySetPath = "/.well-known/jwks";

    public const string TokenPath = "/connect/token";

    /// <summary>The <c>kid</c> of the global signing credential, which is inert: no Tenant's JWKS or token carries it.</summary>
    public const string InertSigningKeyId = InertCredentials.SigningKeyId;

    /// <summary>The <c>kid</c> of the global encryption credential, which is inert as well.</summary>
    public const string InertEncryptionKeyId = InertCredentials.EncryptionKeyId;

    /// <summary>
    /// Registers the OpenIddict server and the Tenant runtimes. Its global options hold only inert
    /// credentials, which throw on any use; the first Gatekeep handler swaps in the request's Tenant
    /// options, built from the same options pipeline, with that Tenant's stored issuer, its Signing
    /// Keys through Transit and its unwrapped token protection key, read in a short read-only Tenant
    /// scope as <c>gk_hosted</c> through <paramref name="hostedConnectionString"/>, read on first use.
    /// Key custody is the host's <c>IKeyCustody</c>.
    /// </summary>
    public static IServiceCollection AddGatekeepProtocol(
        this IServiceCollection services,
        Func<IServiceProvider, string> hostedConnectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(hostedConnectionString);

        services.AddSingleton<ITenantKeyReader>(provider => new TenantKeyReader(() => hostedConnectionString(provider)));
        ProtocolServer.Add(services);
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
