using System.Collections.Immutable;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>The host's browser-page headers (AD-21), set on the one page the authorization endpoint shows itself.</summary>
internal sealed record ProtocolPageHeaders(Action<IHeaderDictionary> Apply);

/// <summary>The authorization endpoint's shared pieces (Story 2.9).</summary>
internal static class AuthorizeEndpoint
{
    /// <summary>Where <see cref="TrustRedirectTarget"/> leaves the client's exact registered redirect URI.</summary>
    public const string TrustedRedirectProperty = ".gatekeep_trusted_redirect_uri";

    /// <summary>The <c>sid</c> claim: the Session the sign-in started (OpenID Connect Front-Channel Logout).</summary>
    public const string SessionIdClaim = "sid";

    /// <summary>
    /// The request parameters a sign-in transaction keeps, for the sign-in to honour (Story 4.2 reads
    /// <c>prompt</c> and <c>max_age</c>). Anything else a request carries is left out, so no unknown
    /// value is stored.
    /// </summary>
    public static readonly IReadOnlySet<string> KeptParameters = new HashSet<string>(StringComparer.Ordinal)
    {
        Parameters.ClientId,
        Parameters.RedirectUri,
        Parameters.ResponseType,
        Parameters.ResponseMode,
        Parameters.Scope,
        Parameters.State,
        Parameters.Nonce,
        Parameters.CodeChallenge,
        Parameters.CodeChallengeMethod,
        Parameters.Prompt,
        Parameters.MaxAge,
        Parameters.LoginHint,
        Parameters.UiLocales,
    };

    /// <summary>
    /// The fixed page for an authorization request that can't be sent back to a client: an unknown
    /// client, or a redirect URI that is missing, malformed or not registered (Story 2.9, the Generic
    /// error page). It never echoes a request value. Story 4.1 replaces it.
    /// </summary>
    public const string InvalidRequestPage =
        """
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Something went wrong</title>
        </head>
        <body>
        <main>
        <h1>Something went wrong</h1>
        <p>This sign-in link isn't valid. Go back to the app and try again.</p>
        </main>
        </body>
        </html>
        """;
}

/// <summary>
/// Opens the authorization request's one transaction, first on extraction and after Tenant selection
/// (AD-8, AD-13): OpenIddict's client and redirect URI checks read Applications through it, and the
/// sign-in writes through it. <see cref="EndAuthorizeTransaction"/> ends it.
/// </summary>
internal sealed class BeginAuthorizeTransaction(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
            .UseScopedHandler<BeginAuthorizeTransaction>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var runtime = context.Transaction.GetProperty<TenantRuntime>(TenantRuntime.Property)
            ?? throw new InvalidOperationException("The authorization endpoint runs only on a Tenant runtime.");

        await transaction.BeginAsync(services.Database.Source, runtime.TenantId, context.CancellationToken);
    }
}

/// <summary>
/// Trusts a redirect target only once the client is known and the request's <c>redirect_uri</c> is one it
/// registered, exactly (Story 2.9, RFC 9700 §4.1): right after OpenIddict's own form checks of the
/// parameter, and before every other check, so that from here on every error, a missing PKCE challenge
/// included, is sent back to that URI with <c>iss</c>. A missing redirect URI or one not registered is
/// refused with <c>invalid_request</c>, and answered by <see cref="AnswerInvalidRequestPage"/>, never
/// by a redirect.
/// </summary>
internal sealed class TrustRedirectTarget(IOpenIddictApplicationManager applications)
    : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<TrustRedirectTarget>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateRedirectUriParameter.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var redirectUri = context.Request.RedirectUri;
        if (string.IsNullOrEmpty(redirectUri))
        {
            context.Reject(Errors.InvalidRequest, "The redirect_uri parameter is required.");
            return;
        }

        if (string.IsNullOrEmpty(context.ClientId)
            || await applications.FindByClientIdAsync(context.ClientId, context.CancellationToken) is not { } application)
        {
            context.Reject(Errors.InvalidClient, "The client is unknown.");
            return;
        }

        if (!await applications.ValidateRedirectUriAsync(application, redirectUri, context.CancellationToken))
        {
            context.Reject(Errors.InvalidRequest, "The redirect_uri isn't registered for this client.");
            return;
        }

        context.Transaction.SetProperty(AuthorizeEndpoint.TrustedRedirectProperty, redirectUri);
    }
}

/// <summary>
/// Gatekeep's own authorization request rules (Story 2.9), where OpenIddict's scope check would run
/// (it needs a scope store, which there is none of): <c>openid</c> is required and is the only scope
/// accepted, so any other is <c>invalid_scope</c>; and no sign-in can complete without the User, so
/// <c>prompt=none</c> is <c>login_required</c>. <c>prompt=login</c> and <c>max_age</c> pass to the
/// sign-in; Story 4.2 honours them.
/// </summary>
internal sealed class ValidateGatekeepAuthorizationRequest : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseSingletonHandler<ValidateGatekeepAuthorizationRequest>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateScopes.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var scopes = context.Request.GetScopes();
        if (!scopes.Contains(Scopes.OpenId, StringComparer.Ordinal) || scopes.Any(s => s != Scopes.OpenId))
        {
            context.Reject(Errors.InvalidScope, "openid is required, and is the only scope accepted.");
        }
        else if (context.Request.HasPromptValue(PromptValues.None))
        {
            context.Reject(Errors.LoginRequired, "The User must sign in.");
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Endpoint end for the authorization endpoint (AD-5), before the response is written: a response with
/// no error, a code issued, commits the request's transaction; any error rolls it back, so a refused
/// request leaves no sign-in transaction, Session or authorization behind.
/// </summary>
internal sealed class EndAuthorizeTransaction(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseScopedHandler<EndAuthorizeTransaction>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        await RequestEnd.EndAsync(transaction, context, services.Logger);
    }
}

/// <summary>
/// OpenIddict sends a validation error back to no client at all. Once <see cref="TrustRedirectTarget"/>
/// has trusted the client's registered redirect URI, it is safe to (RFC 6749 §4.1.2.1), so every later
/// error goes there, and OpenIddict then attaches <c>state</c> and <c>iss</c> to it.
/// </summary>
internal sealed class RedirectTrustedErrors : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<RedirectTrustedErrors>()
            .SetOrder(OpenIddictServerHandlers.Authentication.AttachRedirectUri.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (string.IsNullOrEmpty(context.RedirectUri)
            && !string.IsNullOrEmpty(context.Error)
            && context.Transaction.GetProperty<string>(AuthorizeEndpoint.TrustedRedirectProperty) is { Length: > 0 } trusted)
        {
            context.RedirectUri = trusted;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// A response goes back by query or form_post only (RFC 9700): an error for a request that asked for
/// another mode, such as an implicit <c>response_type</c>'s fragment, goes by query.
/// </summary>
internal sealed class KeepResponseModes : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<KeepResponseModes>()
            .SetOrder(OpenIddictServerHandlers.Authentication.InferResponseMode.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!string.IsNullOrEmpty(context.RedirectUri) && context.ResponseMode is not (ResponseModes.Query or ResponseModes.FormPost))
        {
            context.ResponseMode = ResponseModes.Query;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// An authorization request that can't be sent back to a client, an unknown client or a redirect URI
/// that isn't registered exactly, gets the one fixed page (Story 2.9): 400, <c>no-store</c> and the
/// host's AD-21 headers, the Hosted CSP among them. It never redirects and echoes nothing of the
/// request. It runs after every redirecting response and before OpenIddict's plain-text error.
/// </summary>
internal sealed class AnswerInvalidRequestPage(ProtocolPageHeaders headers) : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
{
    private static readonly byte[] Page = Encoding.UTF8.GetBytes(AuthorizeEndpoint.InvalidRequestPage);

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
            .UseSingletonHandler<AnswerInvalidRequestPage>()
            .SetOrder(OpenIddictServerAspNetCoreHandlers.Authentication.ProcessFragmentResponse.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!string.IsNullOrEmpty(context.RedirectUri) || string.IsNullOrEmpty(context.Error))
        {
            return;
        }

        var response = TokenEndpoint.Http(context).Response;
        response.StatusCode = StatusCodes.Status400BadRequest;
        response.Headers.Location = default;
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        headers.Apply(response.Headers);
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength = Page.Length;
        await response.Body.WriteAsync(Page, context.CancellationToken);
        context.HandleRequest();
    }
}

/// <summary>
/// The authorization endpoint's passthrough (Story 2.9, AD-8): a request OpenIddict has validated, client,
/// exact redirect URI, <c>response_type=code</c>, S256 PKCE and Gatekeep's scope and prompt rules, reaches
/// it in the request's open transaction. It begins the sign-in with <c>IAuthentication.BeginAsync</c>,
/// then asks the host's <see cref="IAuthorizationSignIn"/> to complete it. A result signs the User in: the
/// claims are <c>sub</c> (the User's <c>usr_</c> ID), <c>sid</c>, <c>auth_time</c> and <c>amr</c>, the ID
/// token gets those and the <c>nonce</c>, and the access token <c>sub</c> and its audience; one ad-hoc
/// authorization, the Token Family, is anchored to the result's Session, and OpenIddict issues the code.
/// No result is <c>temporarily_unavailable</c>. Either way OpenIddict's response, with <c>iss</c>, ends
/// the transaction. No refresh token is issued (Story 2.10).
/// </summary>
internal static class AuthorizePassthrough
{
    public static async Task InvokeAsync(HttpContext http, RequestDelegate next)
    {
        var transaction = http.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
        if (transaction is not { EndpointType: OpenIddictServerEndpointType.Authorization, Request: { } request } || http.Response.HasStarted)
        {
            await next(http);
            return;
        }

        var services = http.RequestServices.GetRequiredService<TokenEndpointServices>();
        var requestTransaction = http.RequestServices.GetRequiredService<TokenRequestTransaction>();
        var cancellationToken = http.RequestAborted;

        var runtime = transaction.GetProperty<TenantRuntime>(TenantRuntime.Property)
            ?? throw new InvalidOperationException("The authorization endpoint runs only on a Tenant runtime.");
        if (!runtime.SigningKeys.Any(k => k.CanSign))
        {
            services.Logger?.LogWarning("An authorization request was refused: the Tenant has no current Signing Key.");
            await RefuseAsync(http, Errors.ServerError, "The authorization endpoint can't issue codes now.");
            return;
        }

        var applications = http.RequestServices.GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(request.ClientId!, cancellationToken) as DirectoryApplication
            ?? throw new InvalidOperationException("The validated client has no Application.");

        StartedSignIn started;
        try
        {
            started = await services.Authentication.BeginAsync(
                requestTransaction.Context, new SignInRequest(application.Id, KeptParameters(request)), cancellationToken);
        }
        catch (ArgumentException)
        {
            // A parameter too large or holding a NUL character: nothing was written.
            await RefuseAsync(http, Errors.InvalidRequest, "The authorization request can't be kept.");
            return;
        }

        var signIn = http.RequestServices.GetRequiredService<IAuthorizationSignIn>();
        var result = await signIn.CompleteAsync(requestTransaction.Context, started, http, cancellationToken);
        if (result is null)
        {
            await RefuseAsync(http, Errors.TemporarilyUnavailable, "Sign-in isn't available. Try again later.");
            return;
        }

        var subject = PublicId.Format(PublicIdType.User, result.UserId);
        string[] audiences = application.Audiences.IsDefaultOrEmpty ? [ProtocolContract.PlaceholderAudience] : [.. application.Audiences];

        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, subject);
        identity.SetClaim(AuthorizeEndpoint.SessionIdClaim, result.SessionId.ToString());
        identity.SetClaim(Claims.AuthenticationTime, (long?)result.AuthTime.ToUnixTimeSeconds());
        identity.SetClaims(Claims.AuthenticationMethodReference, ImmutableArray.CreateRange(result.Amr));
        identity.SetScopes(ImmutableArray.Create(Scopes.OpenId));
        identity.SetAudiences(audiences);
        identity.SetDestinations(static claim => claim.Type switch
        {
            Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
            AuthorizeEndpoint.SessionIdClaim or Claims.AuthenticationTime or Claims.AuthenticationMethodReference => [Destinations.IdentityToken],
            _ => [],
        });

        var principal = new ClaimsPrincipal(identity);

        // The Token Family (AD-13): one ad-hoc authorization, anchored to the Session the sign-in started.
        var authorizations = http.RequestServices.GetRequiredService<IOpenIddictAuthorizationManager>();
        var descriptor = new OpenIddictAuthorizationDescriptor
        {
            ApplicationId = application.Id.ToString(),
            CreationDate = services.Time.GetUtcNow(),
            Principal = principal,
            Status = Statuses.Valid,
            Subject = subject,
            Type = AuthorizationTypes.AdHoc,
        };
        descriptor.Scopes.Add(Scopes.OpenId);
        descriptor.Properties[SessionsContract.SessionAnchorProperty] = JsonSerializer.SerializeToElement(result.SessionId.ToString());

        var authorization = await authorizations.CreateAsync(descriptor, cancellationToken);
        identity.SetAuthorizationId(await authorizations.GetIdAsync(authorization, cancellationToken));

        await http.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
    }

    /// <summary>The kept parameters, each as its text.</summary>
    private static Dictionary<string, string> KeptParameters(OpenIddictRequest request)
    {
        var kept = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, value) in request.GetParameters())
        {
            if (AuthorizeEndpoint.KeptParameters.Contains(name) && value.ToString() is { } text)
            {
                kept[name] = text;
            }
        }

        return kept;
    }

    /// <summary>Refuses the request with <paramref name="error"/>, sent back to the client's redirect URI with <c>iss</c>.</summary>
    private static Task RefuseAsync(HttpContext http, string error, string description) =>
        http.ForbidAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }));
}
