using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>
/// The spike build: OpenIddict 7.7.2 in degraded mode on a TestServer, serving two Tenants on
/// two hosts. Its global options hold only <see cref="InertCredentials"/>; the first Gatekeep
/// handler swaps in the Tenant's options and sets <c>BaseUri</c> from the stored issuer.
/// </summary>
public sealed class SpikeServer : IAsyncDisposable
{
    public const string AuthorizePath = "/connect/authorize";
    public const string TokenPath = "/connect/token";
    public const string DiscoveryPath = "/.well-known/openid-configuration";
    public const string JwksPath = "/.well-known/jwks";
    public const string Subject = "spike-subject";

    private readonly WebApplication _app;

    private SpikeServer(WebApplication app, SpikeTenants tenants, InertCredentials inert, TenantRuntimes runtimes)
    {
        _app = app;
        Tenants = tenants;
        Inert = inert;
        Runtimes = runtimes;
        Client = app.GetTestClient();
    }

    public SpikeTenants Tenants { get; }

    public InertCredentials Inert { get; }

    public TenantRuntimes Runtimes { get; }

    public HttpClient Client { get; }

    /// <summary>The options OpenIddict builds at startup: the ones no Tenant request may use.</summary>
    public OpenIddictServerOptions GlobalOptions =>
        _app.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

    public static async Task<SpikeServer> StartAsync(OpenBaoFixture bao, CancellationToken cancellationToken)
    {
        var tenants = await SpikeTenants.CreateAsync(bao, cancellationToken);
        var inert = new InertCredentials();

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();

        // Nothing logs, so no token or code can reach test output.
        builder.Logging.ClearProviders();

        // Request-time custody is Host.Hosted's only.
        builder.Services.AddSingleton(_ => new HostedCustody(bao.Custody(OpenBaoFixture.Hosted)));
        builder.Services.AddSingleton(tenants);
        builder.Services.AddSingleton<TenantRuntimes>();

        builder.Services.AddOpenIddict().AddServer(options =>
        {
            options.EnableDegradedMode();

            options.SetAuthorizationEndpointUris(AuthorizePath[1..])
                .SetTokenEndpointUris(TokenPath[1..])
                .SetConfigurationEndpointUris(DiscoveryPath[1..])
                .SetJsonWebKeySetEndpointUris(JwksPath[1..]);

            options.AllowClientCredentialsFlow()
                .AllowAuthorizationCodeFlow()
                .RequireProofKeyForCodeExchange();

            options.Configure(o => o.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));

            // Access tokens are JWS, unencrypted (AD-8).
            options.DisableAccessTokenEncryption();

            options.AddSigningCredentials(inert.Signing);
            options.AddEncryptionCredentials(inert.Encrypting);

            // The built-in handler would set BaseUri from the Host header after Gatekeep's.
            options.RemoveEventHandler(OpenIddictServerAspNetCoreHandlers.ResolveRequestUri.Descriptor);
            options.AddEventHandler(SelectTenantOptions.Descriptor);
            options.AddEventHandler(ValidateSpikeAuthorizationRequest.Descriptor);
            options.AddEventHandler(ValidateSpikeTokenRequest.Descriptor);
            options.AddEventHandler(SignInClientCredentials.Descriptor);

            options.UseAspNetCore().EnableAuthorizationEndpointPassthrough();
        });

        var app = builder.Build();
        app.UseAuthentication();

        // The passthrough authorization endpoint: one fixed test subject, no sign-in screen.
        app.MapMethods(AuthorizePath, [HttpMethods.Get, HttpMethods.Post], (HttpContext http) =>
        {
            var request = http.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("Not an OpenIddict request.");

            var identity = new ClaimsIdentity(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
            identity.SetClaim(Claims.Subject, Subject);
            identity.SetScopes(request.GetScopes());
            identity.SetDestinations(static _ => [Destinations.AccessToken, Destinations.IdentityToken]);

            return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });

        await app.StartAsync(cancellationToken);
        return new SpikeServer(app, tenants, inert, app.Services.GetRequiredService<TenantRuntimes>());
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>The Hosted custody login, held apart so nothing mistakes it for Worker's.</summary>
public sealed class HostedCustody(OpenBaoKeyCustody custody) : IDisposable
{
    public IKeyCustody Custody => custody;

    public void Dispose() => custody.Dispose();
}

/// <summary>A Tenant's OpenIddict options and the keys behind them.</summary>
public sealed record TenantRuntime(
    SpikeTenant Tenant,
    OpenIddictServerOptions Options,
    TransitSigning Signing,
    SymmetricSecurityKey TokenProtection);

/// <summary>
/// Builds each Tenant's options on its first request, as <c>Host.Hosted</c> would: the public
/// half from Transit and the token protection key unwrapped, both with the Hosted login. The
/// copy comes from the same options pipeline as the global options, then gets the Tenant's
/// issuer and credentials in place of the inert ones.
/// </summary>
public sealed class TenantRuntimes(
    SpikeTenants tenants,
    HostedCustody hosted,
    IOptionsFactory<OpenIddictServerOptions> factory)
{
    private readonly ConcurrentDictionary<Guid, Lazy<Task<TenantRuntime>>> _runtimes = new();

    public async ValueTask<TenantRuntime?> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        if (!tenants.TryResolve(host, out var tenant))
        {
            return null;
        }

        return await _runtimes.GetOrAdd(tenant.Id, _ => new(() => BuildAsync(tenant, CancellationToken.None))).Value
            .WaitAsync(cancellationToken);
    }

    /// <summary>The runtime a request already built, for tests that look inside.</summary>
    public TenantRuntime Built(SpikeTenant tenant) =>
        _runtimes.TryGetValue(tenant.Id, out var runtime) && runtime.Value.IsCompletedSuccessfully
            ? runtime.Value.Result
            : throw new InvalidOperationException("No request has reached this Tenant yet.");

    private async Task<TenantRuntime> BuildAsync(SpikeTenant tenant, CancellationToken cancellationToken)
    {
        var custody = hosted.Custody;
        var versions = await custody.GetPublicKeysAsync(tenant.SigningKey, cancellationToken);
        var signing = new TransitSigning(custody, tenant.SigningKey, versions.MaxBy(v => v.KeyVersion)!);

        var unwrapped = await custody.DecryptAsync(
            tenant.TokenProtectionKey, tenant.Id, tenant.WrappedTokenProtectionKey, cancellationToken);
        var protection = unwrapped.Use(bytes => new SymmetricSecurityKey(bytes.ToArray())
        {
            KeyId = tenant.TokenProtectionKey.Value,
        });

        var options = factory.Create(Options.DefaultName);
        options.Issuer = tenant.Issuer;

        options.SigningCredentials.Clear();
        options.SigningCredentials.Add(signing.Credentials);

        options.EncryptionCredentials.Clear();
        options.EncryptionCredentials.Add(new EncryptingCredentials(
            protection, SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));

        options.TokenValidationParameters.IssuerSigningKeys = [signing.SecurityKey];
        options.TokenValidationParameters.TokenDecryptionKeys = [protection];

        return new TenantRuntime(tenant, options, signing, protection);
    }
}

/// <summary>
/// The first Gatekeep handler on every OpenIddict request. It resolves the Tenant from the host,
/// replaces the transaction's options with that Tenant's, and sets <c>BaseUri</c> and the
/// request URI from the stored issuer. An unmapped host gets 404 before any other handler runs.
/// </summary>
public sealed class SelectTenantOptions(TenantRuntimes runtimes) : IOpenIddictServerHandler<ProcessRequestContext>
{
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

        var runtime = await runtimes.ResolveAsync(request.Host.Host, context.CancellationToken);
        if (runtime is null)
        {
            request.HttpContext.Response.StatusCode = StatusCodes.Status404NotFound;
            context.HandleRequest();
            return;
        }

        context.Transaction.Options = runtime.Options;

        var issuer = runtime.Tenant.Issuer;
        context.BaseUri = issuer;
        context.RequestUri = new Uri(UriHelper.BuildAbsolute(
            issuer.Scheme, new HostString(issuer.Authority), request.PathBase, request.Path, request.QueryString));
    }
}

/// <summary>The spike's two clients. Degraded mode has no Application store until Story 2.2.</summary>
public static class SpikeClients
{
    public const string Confidential = "spike-service";
    public const string Public = "spike-web";
    public const string RedirectUri = "https://client.spike.test/callback";

    /// <summary>Random per run, so no secret value is written down anywhere.</summary>
    public static string ConfidentialSecret { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
}

/// <summary>Degraded mode needs the client and redirect URI checked by hand, and so does PKCE S256.</summary>
public sealed class ValidateSpikeAuthorizationRequest : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseSingletonHandler<ValidateSpikeAuthorizationRequest>()
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ClientId != SpikeClients.Public || context.RedirectUri != SpikeClients.RedirectUri)
        {
            context.Reject(Errors.InvalidClient);
        }
        else if (string.IsNullOrEmpty(context.Request.CodeChallenge)
            || context.Request.CodeChallengeMethod != CodeChallengeMethods.Sha256)
        {
            context.Reject(Errors.InvalidRequest);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>Checks the client by hand, as degraded mode requires.</summary>
public sealed class ValidateSpikeTokenRequest : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<ValidateSpikeTokenRequest>()
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Request.IsClientCredentialsGrantType())
        {
            if (context.ClientId != SpikeClients.Confidential || !SecretMatches(context.ClientSecret))
            {
                context.Reject(Errors.InvalidClient);
            }
        }
        else if (context.Request.IsAuthorizationCodeGrantType())
        {
            if (context.ClientId != SpikeClients.Public)
            {
                context.Reject(Errors.InvalidClient);
            }
        }
        else
        {
            context.Reject(Errors.UnsupportedGrantType);
        }

        return ValueTask.CompletedTask;
    }

    private static bool SecretMatches(string? secret) =>
        secret is not null && CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(secret),
            System.Text.Encoding.UTF8.GetBytes(SpikeClients.ConfidentialSecret));
}

/// <summary>Client Credentials has no code to take a principal from, so the client signs in as itself.</summary>
public sealed class SignInClientCredentials : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
            .UseSingletonHandler<SignInClientCredentials>()
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsClientCredentialsGrantType())
        {
            return ValueTask.CompletedTask;
        }

        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, context.ClientId);
        identity.SetDestinations(static _ => [Destinations.AccessToken]);
        context.SignIn(new ClaimsPrincipal(identity));

        return ValueTask.CompletedTask;
    }
}
