using System.Globalization;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Protocol.Contracts;
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
/// The OpenIddict server registration (Story 2.3, AD-8). Degraded mode is off, and no store is
/// registered yet: discovery and JWKS need none, and the token endpoint is refused before any
/// handler that would.
/// </summary>
internal static class ProtocolServer
{
    public static void Add(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<TenantRuntimes>();
        services.AddSingleton<ITenantServerOptions>(provider => provider.GetRequiredService<TenantRuntimes>());

        var inert = new InertCredentials();

        services.AddOpenIddict().AddServer(options =>
        {
            options.SetConfigurationEndpointUris(ProtocolContract.ConfigurationPath[1..])
                .SetJsonWebKeySetEndpointUris(ProtocolContract.JsonWebKeySetPath[1..])
                .SetTokenEndpointUris(ProtocolContract.TokenPath[1..]);

            // OpenIddict refuses to start without a flow (ID0076/ID0079), and the flow needs the
            // token endpoint. RefuseTokenRequests keeps both inert until Story 2.5.
            options.AllowClientCredentialsFlow();

            // Access tokens are JWS, unencrypted (AD-8).
            options.DisableAccessTokenEncryption();

            options.AddSigningCredentials(inert.Signing);
            options.AddEncryptionCredentials(inert.Encrypting);

            // The built-in handler would set BaseUri from the Host header after Gatekeep's (Story 2.1).
            options.RemoveEventHandler(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri.Descriptor);
            options.AddEventHandler(SelectTenantOptions.Descriptor);
            options.AddEventHandler(RequireTenantOptions.Descriptor);
            options.AddEventHandler(RefuseTokenRequests.Descriptor);
            options.AddEventHandler(TrimDiscovery.Descriptor);
            options.AddEventHandler(CacheJsonWebKeySet.Descriptor);

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
/// It opens no transaction: discovery and JWKS only read, in the runtime's own short scope. A
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
/// Refuses every token request with <c>unsupported_grant_type</c> until Story 2.5 replaces it. It
/// runs first on extraction, before OpenIddict reads the request, validates it or reaches any
/// store or key, so the endpoint is inert whatever the request holds.
/// </summary>
internal sealed class RefuseTokenRequests : IOpenIddictServerHandler<ExtractTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractTokenRequestContext>()
            .UseSingletonHandler<RefuseTokenRequests>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ExtractTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Reject(Errors.UnsupportedGrantType, "No grant type is enabled on this server yet.");
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Takes the token endpoint and every grant type out of discovery until Story 2.5 enables one,
/// so no client tries the refused endpoint. It runs after every built-in discovery handler.
/// </summary>
internal sealed class TrimDiscovery : IOpenIddictServerHandler<HandleConfigurationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
            .UseSingletonHandler<TrimDiscovery>()
            .SetOrder(int.MaxValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleConfigurationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.TokenEndpoint = null;
        context.MtlsTokenEndpointAlias = null;
        context.GrantTypes.Clear();
        context.TokenEndpointAuthenticationMethods.Clear();
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
