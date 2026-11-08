using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Protocol.Adapters;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>What the token endpoint's handlers share: its connections, counters, Directory, audit and limits.</summary>
internal sealed class TokenEndpointServices(
    HostedDataSource database,
    IRateLimiter limiter,
    IDirectory directory,
    IAuditAppender audit,
    TokenRequestLimits limits,
    ILoggerFactory? loggers = null)
{
    public HostedDataSource Database { get; } = database;

    public IRateLimiter Limiter { get; } = limiter;

    public IDirectory Directory { get; } = directory;

    public IAuditAppender Audit { get; } = audit;

    public TokenRequestLimits Limits { get; } = limits;

    public ILogger? Logger { get; } = loggers?.CreateLogger("Gatekeep.Protocol");
}

/// <summary>The token endpoint's shared pieces: the request's Tenant and source, and the one refusal every bad client gets.</summary>
internal static class TokenEndpoint
{
    /// <summary>Where <see cref="LimitTokenRequests"/> leaves a refusal's wait, for <see cref="AnswerRateLimited"/>.</summary>
    public const string RetryAfterProperty = ".gatekeep_retry_after";

    /// <summary>The subject a request with no remote address is counted under: all such requests share it.</summary>
    public const string UnknownSource = "unknown";

    /// <summary>The one description every refused client gets, whatever was wrong (Story 2.5).</summary>
    public const string InvalidClientDescription = "The client credentials are invalid.";

    public static HttpContext Http(BaseContext context) =>
        context.Transaction.GetHttpRequest()?.HttpContext ?? throw new InvalidOperationException("No HTTP request.");

    public static ResolvedTenant Tenant(BaseContext context) =>
        Http(context).Features.Get<ResolvedTenant>() ?? throw new InvalidOperationException("No resolved Tenant.");

    /// <summary>
    /// The source a token request is counted by, after any forwarding Caddy did
    /// (<c>UseGatekeepForwardedClient</c>): an IPv4 address, or an IPv6 client's /64, which one host
    /// can hold all of. With no address, the one <see cref="UnknownSource"/>.
    /// </summary>
    public static string Source(HttpContext http)
    {
        var address = http.Connection.RemoteIpAddress;
        if (address is null)
        {
            return UnknownSource;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4().ToString();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            Array.Clear(bytes, 8, 8);
            return $"{new IPAddress(bytes)}/64";
        }

        return address.ToString();
    }

    public static void RejectClient(BaseValidatingContext context) =>
        context.Reject(Errors.InvalidClient, InvalidClientDescription);
}

/// <summary>
/// Counts every token request, per Tenant and per source, in its own short committed scope, before
/// OpenIddict reads the request or authenticates its client (AD-14, the Admin sign-in pattern). Past
/// either limit the request is refused here, and answered 429 with <c>Retry-After</c> by
/// <see cref="AnswerRateLimited"/>; no request transaction is opened for it.
/// </summary>
internal sealed class LimitTokenRequests(TokenEndpointServices services) : IOpenIddictServerHandler<ExtractTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractTokenRequestContext>()
            .UseSingletonHandler<LimitTokenRequests>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ExtractTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenant = TokenEndpoint.Tenant(context);
        var source = TokenEndpoint.Source(TokenEndpoint.Http(context));

        RateLimitDecision perTenant;
        RateLimitDecision perSource;
        await using (var scope = await TenantScope.BeginAsync(services.Database.Source, tenant.TenantId, context.CancellationToken))
        {
            var count = scope.CreateCommandContext();
            perTenant = await services.Limiter.AttemptAsync(count, services.Limits.Tenant, AuthenticationContract.TenantSubject, context.CancellationToken);
            perSource = await services.Limiter.AttemptAsync(count, services.Limits.Source, source, context.CancellationToken);
            await scope.CommitAsync(context.CancellationToken);
        }

        if (perTenant.Allowed && perSource.Allowed)
        {
            return;
        }

        var retryAfter = TimeSpan.FromTicks(Math.Max(perTenant.RetryAfter.Ticks, perSource.RetryAfter.Ticks));
        var policy = perTenant.Allowed ? services.Limits.Source : services.Limits.Tenant;
        services.Logger?.LogInformation("A token request was refused under {Policy}.", policy.Code);

        context.Transaction.Properties[TokenEndpoint.RetryAfterProperty] = retryAfter;
        context.Reject(Errors.TemporarilyUnavailable, "Too many token requests. Retry later.");
    }
}

/// <summary>
/// Opens the token request's one transaction, once it is counted and after Tenant selection (AD-8,
/// AD-13). Discovery and JWKS never reach it.
/// </summary>
internal sealed class BeginTokenTransaction(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ExtractTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractTokenRequestContext>()
            .UseScopedHandler<BeginTokenTransaction>()
            .SetOrder(int.MinValue + 1)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ExtractTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var runtime = context.Transaction.GetProperty<TenantRuntime>(TenantRuntime.Property)
            ?? throw new InvalidOperationException("The token endpoint runs only on a Tenant runtime.");

        await transaction.BeginAsync(services.Database.Source, runtime.TenantId, context.CancellationToken);
    }
}

/// <summary>
/// No audience or resource may be requested at a Tenant's token endpoint (Story 2.5), so the
/// Management API audience can never be minted here: either is refused with <c>invalid_target</c>,
/// before OpenIddict reads it. No scope is known yet either, so one is refused with
/// <c>invalid_scope</c>. Story 3.7 replaces both with real APIs.
/// </summary>
internal sealed class RefuseTokenTargets : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<RefuseTokenTargets>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateGrantType.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Request.Resources is { IsDefaultOrEmpty: false } || context.Request.Audiences is { IsDefaultOrEmpty: false })
        {
            context.Reject(Errors.InvalidTarget, "No audience or resource may be requested here.");
        }
        else if (!context.Request.GetScopes().IsDefaultOrEmpty)
        {
            context.Reject(Errors.InvalidScope, "No scope may be requested here.");
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Gatekeep's client authentication (AD-8, AD-9), in place of OpenIddict's <c>ValidateClientSecret</c>,
/// and before its <c>ValidateClientId</c>, so an unknown client and a wrong secret get the one same
/// <c>invalid_client</c>. A secret whose <c>{tenantPublicId}.</c> prefix isn't this Tenant's is refused
/// before anything is looked up here, then classified: when the prefix names another Tenant and the
/// credential verifies there, read-only, the attempt is authenticated and always writes
/// <c>protocol.client.cross_tenant_rejected</c> to this Tenant's Log; otherwise it is only counted per
/// source, and logged at most once per source per hour. Both commit after the request's rollback.
/// </summary>
internal sealed class AuthenticateGatekeepClient(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseScopedHandler<AuthenticateGatekeepClient>()
            .SetOrder(OpenIddictServerHandlers.ValidateClientId.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Every endpoint that authenticates clients must be covered here before it is enabled (Story 2.2).
        if (context.EndpointType is not OpenIddictServerEndpointType.Token)
        {
            return;
        }

        if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
        {
            TokenEndpoint.RejectClient(context);
            return;
        }

        var tenant = TokenEndpoint.Tenant(context);
        var secret = new Secret<string>(context.ClientSecret);
        var dot = context.ClientSecret.IndexOf('.', StringComparison.Ordinal);
        var prefix = dot > 0 ? context.ClientSecret[..dot] : null;

        if (prefix == PublicId.Format(PublicIdType.Tenant, tenant.TenantId))
        {
            if (!await services.Directory.VerifyClientSecretAsync(transaction.Context, context.ClientId, secret, context.CancellationToken))
            {
                TokenEndpoint.RejectClient(context);
            }

            return;
        }

        // Another Tenant's, or no Tenant's at all: refused before any lookup in this Tenant.
        var other = PublicId.TryParse(PublicIdType.Tenant, prefix, out var otherId) && otherId != tenant.TenantId ? otherId : (Guid?)null;
        var authenticated = other is { } id && await VerifiesAtAsync(id, context.ClientId, secret, context.CancellationToken);
        var rejected = new AuditEvent(ProtocolEvents.ClientCrossTenantRejected.Code, Actor.Anonymous);

        if (authenticated)
        {
            transaction.KeepOnFailure((log, cancellationToken) => services.Audit.AppendAsync(log, rejected, detail: null, cancellationToken));
        }
        else
        {
            var source = TokenEndpoint.Source(TokenEndpoint.Http(context));
            transaction.KeepOnFailure(async (log, cancellationToken) =>
            {
                await services.Limiter.AttemptAsync(log, AuthenticationContract.CrossTenantMismatchPolicy, source, cancellationToken);
                var first = await services.Limiter.AttemptAsync(log, AuthenticationContract.CrossTenantMismatchLogPolicy, source, cancellationToken);
                if (first.Allowed)
                {
                    await services.Audit.AppendAsync(log, rejected, detail: null, cancellationToken);
                }
            });
        }

        // Nothing of the other Tenant, nor the presented values, is logged.
        services.Logger?.LogInformation(
            "A client credential not issued by this Tenant was refused, {Classification}.",
            authenticated ? "authenticated" : "unauthenticated");
        TokenEndpoint.RejectClient(context);
    }

    /// <summary>Whether the credential verifies in <paramref name="tenantId"/>, in its own read-only scope that writes nothing.</summary>
    private async Task<bool> VerifiesAtAsync(Guid tenantId, string clientId, Secret<string> secret, CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Database.Source, tenantId, cancellationToken);
            var context = scope.CreateCommandContext();
            await using (var command = context.CreateCommand())
            {
                command.CommandText = "SET TRANSACTION READ ONLY";
                await command.ExecuteNonQueryAsync(cancellationToken);
            }

            // Never committed: disposing it rolls back, and nothing was written to roll back.
            return await services.Directory.VerifyClientSecretAsync(context, clientId, secret, cancellationToken);
        }
        catch (Exception e) when (!cancellationToken.IsCancellationRequested)
        {
            // Unclassified is counted as unauthenticated; the type only, since a message could name the Tenant.
            services.Logger?.LogWarning("A cross-Tenant credential couldn't be classified, on {ErrorType}.", e.GetType().Name);
            return false;
        }
    }
}

/// <summary>
/// Client Credentials has no user, so the client signs in as itself (Story 2.5): <c>sub</c> is its
/// <c>client_id</c>, and <c>aud</c> its Application's audiences, or <see cref="ProtocolContract.PlaceholderAudience"/>
/// while it has none (Story 3.7 replaces it). The access token is its only destination. A Tenant with
/// no <c>current</c> Signing Key can't sign, so its authenticated client is refused here with
/// <c>server_error</c>, before any token or row is made, and the runtime it was built from stays whole.
/// </summary>
internal sealed class SignInClient(IOpenIddictApplicationManager applications, TokenEndpointServices services)
    : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
            .UseScopedHandler<SignInClient>()
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsClientCredentialsGrantType())
        {
            return;
        }

        var runtime = context.Transaction.GetProperty<TenantRuntime>(TenantRuntime.Property)
            ?? throw new InvalidOperationException("The token endpoint runs only on a Tenant runtime.");
        if (!runtime.SigningKeys.Any(k => k.CanSign))
        {
            services.Logger?.LogWarning("A token request was refused: the Tenant has no current Signing Key.");
            context.Reject(Errors.ServerError, "The token endpoint can't issue tokens now.");
            return;
        }

        var application = await applications.FindByClientIdAsync(context.ClientId!, context.CancellationToken) as DirectoryApplication
            ?? throw new InvalidOperationException("The authenticated client has no Application.");

        string[] audiences = application.Audiences.IsDefaultOrEmpty ? [ProtocolContract.PlaceholderAudience] : [.. application.Audiences];

        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, application.ClientId);
        identity.SetAudiences(audiences);
        identity.SetDestinations(static _ => [Destinations.AccessToken]);
        context.SignIn(new ClaimsPrincipal(identity));
    }
}

/// <summary>
/// Endpoint end (AD-5): a token response with no error commits the request's transaction, before the
/// response is written; any error rolls it back, committing what a refused request keeps, such as a
/// cross-Tenant event, through <see cref="FailureContext"/>. A request refused before its transaction
/// opened, such as a rate-limited one, has nothing to end.
/// </summary>
internal sealed class EndTokenTransaction(TokenRequestTransaction transaction) : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
            .UseScopedHandler<EndTokenTransaction>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!transaction.IsOpen)
        {
            return;
        }

        if (string.IsNullOrEmpty(context.Transaction.Response?.Error))
        {
            await transaction.CommitAsync(context.CancellationToken);
        }
        else
        {
            await transaction.FailAsync();
        }
    }
}

/// <summary>A rate-limited token request is answered 429 with <c>Retry-After</c>, its OAuth error body unchanged.</summary>
internal sealed class AnswerRateLimited : IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>()
            .UseSingletonHandler<AnswerRateLimited>()
            .SetOrder(OpenIddictServerAspNetCoreHandlers.AttachHttpResponseCode<ApplyTokenResponseContext>.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyTokenResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Transaction.Properties.TryGetValue(TokenEndpoint.RetryAfterProperty, out var value) && value is TimeSpan retryAfter)
        {
            var response = TokenEndpoint.Http(context).Response;
            response.StatusCode = StatusCodes.Status429TooManyRequests;
            response.Headers.RetryAfter = Math.Max(1, (long)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// <c>expires_in</c> is the access token's own lifetime, from its <c>iat</c> to its <c>exp</c> (Story 2.5):
/// 900 for the §5.2 default, however long signing took. OpenIddict's counts from the response's own
/// clock, so a slow Transit signature would report 899.
/// </summary>
internal sealed class ReportAccessTokenLifetime : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<ReportAccessTokenLifetime>()
            .SetOrder(OpenIddictServerHandlers.AttachSignInParameters.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is OpenIddictServerEndpointType.Token
            && context.Response.ExpiresIn is not null
            && context.AccessTokenPrincipal?.GetCreationDate() is { } issued
            && context.AccessTokenPrincipal.GetExpirationDate() is { } expires)
        {
            context.Response.ExpiresIn = (long)Math.Round((expires - issued).TotalSeconds);
        }

        return ValueTask.CompletedTask;
    }
}
