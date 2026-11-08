using System.Globalization;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Protocol.Adapters;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The OpenIddict server registration (Stories 2.3 and 2.5, AD-8). Degraded mode is off. The stores
/// live in their owners (Directory's application store, Sessions' token and authorization stores), and
/// every store call runs in the token request's one transaction; entity caching is off, no scope store
/// is registered, and nothing prunes. The token endpoint serves Client Credentials only, authenticated
/// by Gatekeep's handler against Directory, with <c>client_secret_basic</c> and <c>client_secret_post</c>.
/// </summary>
internal static class ProtocolServer
{
    public static void Add(IServiceCollection services, Func<IServiceProvider, string> hostedConnectionString)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<TenantRuntimes>();
        services.AddSingleton<ITenantServerOptions>(provider => provider.GetRequiredService<TenantRuntimes>());

        services.AddSingleton(provider => new HostedDataSource(() => hostedConnectionString(provider)));
        services.TryAddSingleton(new TokenRequestLimits(
            AuthenticationContract.TokenRequestTenantPolicy, AuthenticationContract.TokenRequestSourcePolicy));
        services.AddSingleton(provider => new TokenEndpointServices(
            provider.GetRequiredService<HostedDataSource>(),
            AuthenticationContract.CreateAttemptLimiter(),
            DirectoryContract.CreateDirectory(provider.GetRequiredService<IAuditAppender>(), provider.GetRequiredService<TimeProvider>()),
            provider.GetRequiredService<IAuditAppender>(),
            provider.GetRequiredService<TokenRequestLimits>(),
            provider.GetService<ILoggerFactory>()));
        services.AddScoped<TokenRequestTransaction>();

        var inert = new InertCredentials();

        var openIddict = services.AddOpenIddict();

        // AD-8: each store in its owner's adapters, on the request's own transaction. No scope store:
        // no scope is known yet, and RefuseTokenTargets refuses any.
        openIddict.AddCore(core =>
        {
            core.SetDefaultApplicationEntity<DirectoryApplication>()
                .SetDefaultAuthorizationEntity<SessionsAuthorization>()
                .SetDefaultTokenEntity<SessionsToken>()
                .DisableEntityCaching();

            core.Services.Replace(ServiceDescriptor.Scoped(provider =>
                DirectoryContract.CreateApplicationStore(() => provider.GetRequiredService<TokenRequestTransaction>().Context)));
            core.Services.Replace(ServiceDescriptor.Scoped(provider =>
                SessionsContract.CreateTokenStore(() => provider.GetRequiredService<TokenRequestTransaction>().Context)));
            core.Services.Replace(ServiceDescriptor.Scoped(_ => SessionsContract.CreateAuthorizationStore()));
        });

        openIddict.AddServer(options =>
        {
            options.SetConfigurationEndpointUris(ProtocolContract.ConfigurationPath[1..])
                .SetJsonWebKeySetEndpointUris(ProtocolContract.JsonWebKeySetPath[1..])
                .SetTokenEndpointUris(ProtocolContract.TokenPath[1..]);

            // The one grant type (Story 2.5): any other is unsupported_grant_type.
            options.AllowClientCredentialsFlow();

            // Access tokens are JWS, unencrypted (AD-8), for the §5.2 default lifetime.
            options.DisableAccessTokenEncryption();
            options.SetAccessTokenLifetime(SecurityLimits.DefaultAccessTokenLifetime);

            // No scope store, so OpenIddict's own scope check, which needs one, is off.
            options.DisableScopeValidation();

            // client_secret_basic (which the ASP.NET Core host adds) and client_secret_post only, so
            // discovery advertises exactly those; no client assertion is accepted.
            options.Configure(server =>
            {
                server.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.PrivateKeyJwt);
                server.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretJwt);
                server.ClientAssertionTypes.Clear();
            });

            options.AddSigningCredentials(inert.Signing);
            options.AddEncryptionCredentials(inert.Encrypting);

            // The built-in handler would set BaseUri from the Host header after Gatekeep's (Story 2.1).
            options.RemoveEventHandler(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri.Descriptor);
            options.AddEventHandler(SelectTenantOptions.Descriptor);
            options.AddEventHandler(RequireTenantOptions.Descriptor);
            options.AddEventHandler(CacheJsonWebKeySet.Descriptor);

            // The token endpoint (Story 2.5): counted, then one transaction, ended before the response.
            options.AddEventHandler(LimitTokenRequests.Descriptor);
            options.AddEventHandler(BeginTokenTransaction.Descriptor);
            options.AddEventHandler(RefuseTokenTargets.Descriptor);
            options.AddEventHandler(SignInClient.Descriptor);
            options.AddEventHandler(ReportAccessTokenLifetime.Descriptor);
            options.AddEventHandler(EndTokenTransaction.Descriptor);
            options.AddEventHandler(AnswerRateLimited.Descriptor);

            // Client authentication is Gatekeep's, against Directory (AD-8); OpenIddict's check, which
            // reads a secret column Gatekeep keeps empty, is gone.
            options.RemoveEventHandler(OpenIddictServerHandlers.ValidateClientSecret.Descriptor);
            options.AddEventHandler(AuthenticateGatekeepClient.Descriptor);

            // TLS ends at Caddy, so every request reaches Host.Hosted over plain HTTP, and no
            // forwarded scheme is believed (AD-6): the stored https issuer is what clients see.
            options.UseAspNetCore().DisableTransportSecurityRequirement();
        });
    }

    /// <summary>
    /// Whether <paramref name="path"/> may be one of the server's endpoints, matched the way
    /// OpenIddict matches them: ignoring case and a trailing slash. A miss isn't an OpenIddict
    /// request, so no Tenant runtime is built for it; <see cref="RequireTenantOptions"/> refuses
    /// anything this lets past wrongly.
    /// </summary>
    public static bool IsEndpointPath(OpenIddictServerOptions options, PathString path)
    {
        var requested = (path.Value ?? string.Empty).Trim('/');

        return EndpointUris(options).Any(uri =>
            string.Equals(
                (uri.IsAbsoluteUri ? uri.AbsolutePath : uri.OriginalString).Trim('/'),
                requested,
                StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<Uri> EndpointUris(OpenIddictServerOptions options) =>
    [
        .. options.AuthorizationEndpointUris,
        .. options.ConfigurationEndpointUris,
        .. options.DeviceAuthorizationEndpointUris,
        .. options.EndSessionEndpointUris,
        .. options.EndUserVerificationEndpointUris,
        .. options.IntrospectionEndpointUris,
        .. options.JsonWebKeySetEndpointUris,
        .. options.PushedAuthorizationEndpointUris,
        .. options.RevocationEndpointUris,
        .. options.TokenEndpointUris,
        .. options.UserInfoEndpointUris,
    ];
}

/// <summary>
/// The first Gatekeep handler on every OpenIddict request (AD-8): <see cref="ProcessRequestContext"/>
/// at order <see cref="int.MinValue"/>. It takes the <see cref="ResolvedTenant"/> Tenancy's middleware
/// set, the only Tenant source on Host.Hosted (AD-4), sets <c>BaseUri</c> and the request URI from
/// that Tenant's stored issuer (OpenIddict's <c>ResolveRequestUri</c> is removed, so no
/// <c>Host</c>, forwarded header, scheme or port changes them), and swaps in the Tenant's options.
/// It opens no transaction: discovery and JWKS only read, in the runtime's own short scope, and only
/// the token endpoint opens one, once it has counted the request (Story 2.5). A
/// runtime that can't be built answers the one fixed 503, logging only the error's type.
/// </summary>
internal sealed class SelectTenantOptions(TenantRuntimes runtimes, ILoggerFactory? loggers = null)
    : IOpenIddictServerHandler<ProcessRequestContext>
{
    private readonly ILogger? _logger = loggers?.CreateLogger("Gatekeep.Protocol");

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
            .UseSingletonHandler<SelectTenantOptions>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Transaction.GetHttpRequest()
            ?? throw new InvalidOperationException("No HTTP request.");

        // Tenancy answers an unknown host before OpenIddict runs, so this is only a backstop.
        if (request.HttpContext.Features.Get<ResolvedTenant>() is not { } tenant)
        {
            request.HttpContext.Response.StatusCode = StatusCodes.Status404NotFound;
            context.HandleRequest();
            return;
        }

        Uri issuer;
        try
        {
            issuer = ProtocolIssuer.Parse(tenant.Issuer);
        }
        catch (InvalidOperationException e)
        {
            Unavailable(context, request, e);
            return;
        }

        context.BaseUri = issuer;
        context.RequestUri = new Uri(UriHelper.BuildAbsolute(
            issuer.Scheme, new HostString(issuer.Authority), request.PathBase, request.Path, request.QueryString));

        // Not an endpoint: OpenIddict passes it through, so no keys are needed for it.
        if (!ProtocolServer.IsEndpointPath(context.Options, request.Path))
        {
            return;
        }

        TenantRuntime runtime;
        try
        {
            runtime = await runtimes.GetRuntimeAsync(tenant, context.CancellationToken);
        }
        catch (Exception e) when (!context.CancellationToken.IsCancellationRequested)
        {
            // Whatever failed, custody, the database, a malformed key or issuer: the one fixed 503.
            Unavailable(context, request, e);
            return;
        }

        context.Transaction.Options = runtime.Options;
        context.Transaction.SetProperty(TenantRuntime.Property, runtime);
    }

    private void Unavailable(ProcessRequestContext context, HttpRequest request, Exception e)
    {
        // The type only: a message can name a key, and the host is never logged.
        _logger?.LogWarning("Tenant protocol runtime failed on {ErrorType}.", e.GetType().Name);
        request.HttpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        request.HttpContext.Response.Headers.CacheControl = "no-store";
        context.HandleRequest();
    }
}

/// <summary>
/// The backstop for <see cref="SelectTenantOptions"/>: once OpenIddict has matched an endpoint, the
/// request must carry a Tenant's options. If it still holds the global ones, it gets the fixed 404,
/// so the inert credentials never reach a response.
/// </summary>
internal sealed class RequireTenantOptions : IOpenIddictServerHandler<ProcessRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
            .UseSingletonHandler<RequireTenantOptions>()
            .SetOrder(OpenIddictServerHandlers.InferEndpointType.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType != OpenIddictServerEndpointType.Unknown
            && (context.Options.SigningCredentials.Any(c => InertCredentials.IsInert(c.Key))
                || context.Options.EncryptionCredentials.Any(c => InertCredentials.IsInert(c.Key))))
        {
            if (context.Transaction.GetHttpRequest() is { } request)
            {
                request.HttpContext.Response.StatusCode = StatusCodes.Status404NotFound;
            }

            context.HandleRequest();
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Lets relying parties cache a Tenant's JWKS for 15 minutes (AD-11): <c>Cache-Control: public,
/// max-age=900</c> on a successful response that holds a key. An empty one, from a Tenant not yet
/// given its keys, is <c>no-store</c>, so no one keeps it once keys appear. Set after the status
/// code and before the body is written.
/// </summary>
internal sealed class CacheJsonWebKeySet : IOpenIddictServerHandler<ApplyJsonWebKeySetResponseContext>
{
    private static readonly string CacheControl = string.Create(
        CultureInfo.InvariantCulture, $"public, max-age={(int)SecurityLimits.JwksMaxAge.TotalSeconds}");

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyJsonWebKeySetResponseContext>()
            .UseSingletonHandler<CacheJsonWebKeySet>()
            .SetOrder(OpenIddictServerAspNetCoreHandlers.AttachHttpResponseCode<ApplyJsonWebKeySetResponseContext>.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyJsonWebKeySetResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (string.IsNullOrEmpty(context.Error) && context.Transaction.GetHttpRequest() is { } request)
        {
            // JWKS publishes exactly the Tenant's signing credentials, so none means an empty set.
            request.HttpContext.Response.Headers.CacheControl = context.Options.SigningCredentials.Count == 0 ? "no-store" : CacheControl;
            request.HttpContext.Response.Headers.Remove("Pragma");
        }

        return ValueTask.CompletedTask;
    }
}
