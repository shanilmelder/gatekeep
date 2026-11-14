using System.Collections.Immutable;
using System.Globalization;
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

    /// <summary>The <c>sid</c> claim: the Session the sign-in started, as its <c>ses_</c> public ID (OpenID Connect Front-Channel Logout).</summary>
    public const string SessionIdClaim = "sid";

    /// <summary>
    /// The only scopes an authorization grants (Stories 2.9 and 2.10): <c>openid</c>, always, and
    /// <c>offline_access</c>, for a refresh token. A User holds no API Permission until Epic 5 (Story 3.7).
    /// </summary>
    public static readonly IReadOnlySet<string> GrantableScopes = new HashSet<string>(StringComparer.Ordinal)
    {
        Scopes.OpenId,
        Scopes.OfflineAccess,
    };

    /// <summary>
    /// Sets a signed-in User's claims and their destinations (Stories 2.9 and 2.10): <c>sub</c> (the User's
    /// <c>usr_</c> ID) for both tokens, and <c>sid</c>, <c>auth_time</c> and <c>amr</c> for the ID token
    /// only, from the Session the sign-in started. A code flow and every refresh of its family set them
    /// the same way, a refresh from the family's anchored Session as it stands.
    /// </summary>
    public static void SetUserClaims(ClaimsIdentity identity, Guid userId, Guid sessionId, DateTimeOffset authTime, IEnumerable<string> amr)
    {
        identity.SetClaim(Claims.Subject, PublicId.Format(PublicIdType.User, userId));
        identity.SetClaim(SessionIdClaim, PublicId.Format(PublicIdType.Session, sessionId));
        identity.SetClaim(Claims.AuthenticationTime, (long?)authTime.ToUnixTimeSeconds());
        identity.SetClaims(Claims.AuthenticationMethodReference, ImmutableArray.CreateRange(amr));
        identity.SetDestinations(static claim => claim.Type switch
        {
            Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
            SessionIdClaim or Claims.AuthenticationTime or Claims.AuthenticationMethodReference => [Destinations.IdentityToken],
            _ => [],
        });
    }

    /// <summary>
    /// The request's <c>max_age</c> (Story 2.11, OIDC Core §3.1.2.1): null when it names none; false when
    /// it isn't a non-negative integer of seconds, which is <c>invalid_request</c>. One too large for a
    /// <see cref="long"/> is <see cref="long.MaxValue"/>, which demands nothing any sign-in doesn't meet.
    /// </summary>
    public static bool TryReadMaxAge(OpenIddictRequest request, out long? maxAge)
    {
        maxAge = null;
        if (request.GetParameter(Parameters.MaxAge) is not { } parameter)
        {
            return true;
        }

        var text = parameter.ToString();
        if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
        {
            if (string.IsNullOrEmpty(text) || !text.All(char.IsAsciiDigit))
            {
                return false;
            }

            seconds = long.MaxValue;
        }

        maxAge = seconds;
        return true;
    }

    /// <summary>
    /// The time the sign-in must be at or after (Story 2.11, OIDC Core §3.1.2.1), for a request that started
    /// at <paramref name="started"/>: from <c>prompt=login</c>, the request's start; from <c>max_age=N</c>,
    /// N seconds before it, so <c>max_age=0</c> is the same as <c>prompt=login</c>; with both, the later;
    /// with neither, null. A <c>max_age</c> reaching back past the Unix epoch demands nothing. The request's
    /// <c>max_age</c> is already known to be well formed.
    /// </summary>
    public static DateTimeOffset? AuthenticatedSince(OpenIddictRequest request, DateTimeOffset started)
    {
        DateTimeOffset? since = request.HasPromptValue(PromptValues.Login) ? started : null;

        if (TryReadMaxAge(request, out var maxAge) && maxAge is { } seconds)
        {
            var bound = seconds >= (started - DateTimeOffset.UnixEpoch).TotalSeconds
                ? DateTimeOffset.UnixEpoch
                : started.AddSeconds(-seconds);
            since = since is { } login && login > bound ? login : bound;
        }

        return since;
    }

    /// <summary>
    /// Whether a sign-in at <paramref name="authTime"/> is fresh enough for <paramref name="since"/>. With
    /// <c>prompt=login</c> (<paramref name="exact"/>) the bound is the request's start, which no authentication
    /// before it meets, so it is compared exactly; a <c>max_age</c> bound alone is compared in whole seconds,
    /// its unit (OIDC Core §2). With <c>prompt=login</c> the bound is always the request's start, since a
    /// <c>max_age</c> bound is never later.
    /// </summary>
    public static bool IsFreshEnough(DateTimeOffset authTime, DateTimeOffset? since, bool exact) =>
        since is not { } required
        || (exact ? authTime >= required : authTime.ToUnixTimeSeconds() >= required.ToUnixTimeSeconds());

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
/// Trusts a redirect target only once the client is known, may use this endpoint, and the request's
/// <c>redirect_uri</c> is one it registered (Story 2.9, RFC 9700 §4.1): right after OpenIddict's own form
/// checks of the parameter, and before every other check, so that from here on every error, a missing PKCE
/// challenge included, is sent back to that URI with <c>iss</c>. The match is exact, string for string, but
/// for a <c>native</c> client's loopback port (Story 3.2, RFC 8252 §7.3, <see cref="DirectoryContract.MatchesRedirectUri"/>),
/// and this is the only redirect URI check: OpenIddict's own, which would apply its own native rule, is
/// removed. A missing redirect URI, one not registered, and a client without the authorization endpoint
/// (a <c>machine</c> client, or one whose <c>authorization_code</c> grant is off, Story 3.2) are refused, and
/// answered by <see cref="AnswerInvalidRequestPage"/>, never by a redirect.
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
            || await applications.FindByClientIdAsync(context.ClientId, context.CancellationToken) is not DirectoryApplication application)
        {
            context.Reject(Errors.InvalidClient, "The client is unknown.");
            return;
        }

        // A grant turned off is refused here, before any redirect is trusted (Story 3.2).
        if (!await applications.HasPermissionAsync(application, Permissions.Endpoints.Authorization, context.CancellationToken))
        {
            context.Reject(Errors.UnauthorizedClient, "The client may not use the authorization endpoint.");
            return;
        }

        if (!DirectoryContract.MatchesRedirectUri(application, redirectUri))
        {
            context.Reject(Errors.InvalidRequest, "The redirect_uri isn't registered for this client.");
            return;
        }

        context.Transaction.SetProperty(AuthorizeEndpoint.TrustedRedirectProperty, redirectUri);
    }
}

/// <summary>
/// Gatekeep's own authorization request rules (Stories 2.9 and 2.10), where OpenIddict's scope check
/// would run (it needs a scope store, which there is none of). From Story 3.7 the request may name one API with
/// <c>resource</c> or <c>audience</c> (<see cref="ApiTargets"/>): more than one, or one that isn't available, is
/// <c>invalid_target</c>, and the authorization keeps it as its tokens' audience. <c>openid</c> is required, and the only
/// other scope granted is <c>offline_access</c>, for an Application allowed the <c>refresh_token</c>
/// grant. Without an API, any other scope is <c>invalid_scope</c>; with one, another scope is one of its Permissions,
/// which a User can't hold until Epic 5, and is dropped silently. <c>offline_access</c> for any other Application is
/// <c>invalid_scope</c>; a
/// <c>max_age</c> that isn't a non-negative integer is <c>invalid_request</c> (Story 2.11); and no sign-in
/// can complete without the User, so <c>prompt=none</c> is <c>login_required</c>. <c>prompt=login</c> and
/// <c>max_age</c> are enforced against the sign-in's <c>auth_time</c> by <see cref="AuthorizePassthrough"/>.
/// </summary>
internal sealed class ValidateGatekeepAuthorizationRequest(
    IOpenIddictApplicationManager applications, TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseScopedHandler<ValidateGatekeepAuthorizationRequest>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateScopes.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Story 3.7: the one API the request names, if any, decided once the redirect target is trusted.
        var named = context.Transaction.GetProperty<ApiTargets.Named>(ApiTargets.NamedProperty) ?? new ApiTargets.Named(false, null);
        DirectoryApiTarget? api = null;
        if (named.Many)
        {
            context.Reject(Errors.InvalidTarget, ApiTargets.OneApiDescription);
            return;
        }

        if (named.Identifier is { } identifier)
        {
            api = await ApiTargets.ResolveAsync(services.Directory, transaction.Context, identifier, context.CancellationToken);
            if (api is null)
            {
                context.Reject(Errors.InvalidTarget, ApiTargets.UnavailableDescription);
                return;
            }

            context.Transaction.SetProperty(ApiTargets.ApiProperty, api);
        }

        var scopes = context.Request.GetScopes();
        if (api is not null && scopes.Any(s => !AuthorizeEndpoint.GrantableScopes.Contains(s)))
        {
            // Dropped before OpenIddict's own scope permission check, which would refuse them: they are the API's
            // Permissions, which a User can't hold until Epic 5, and an ungranted scope is never an error (FR-16).
            context.Request.Scope = string.Join(' ', scopes.Where(AuthorizeEndpoint.GrantableScopes.Contains));
            scopes = context.Request.GetScopes();
        }

        if (!scopes.Contains(Scopes.OpenId, StringComparer.Ordinal)
            || (api is null && scopes.Any(s => !AuthorizeEndpoint.GrantableScopes.Contains(s))))
        {
            context.Reject(Errors.InvalidScope, "openid is required, and the only other scope accepted is offline_access.");
        }
        else if (scopes.Contains(Scopes.OfflineAccess, StringComparer.Ordinal) && !await MayRefreshAsync(context))
        {
            context.Reject(Errors.InvalidScope, "offline_access isn't allowed for this client.");
        }
        else if (!AuthorizeEndpoint.TryReadMaxAge(context.Request, out _))
        {
            context.Reject(Errors.InvalidRequest, "max_age must be a non-negative integer of seconds.");
        }
        else if (context.Request.HasPromptValue(PromptValues.None))
        {
            context.Reject(Errors.LoginRequired, "The User must sign in.");
        }
    }

    /// <summary>Whether the client, which <see cref="TrustRedirectTarget"/> already found, is allowed the refresh grant.</summary>
    private async Task<bool> MayRefreshAsync(ValidateAuthorizationRequestContext context) =>
        !string.IsNullOrEmpty(context.ClientId)
        && await applications.FindByClientIdAsync(context.ClientId, context.CancellationToken) is { } application
        && await applications.HasPermissionAsync(application, Permissions.GrantTypes.RefreshToken, context.CancellationToken);
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
/// then asks the host's <see cref="IAuthorizationSignIn"/> to complete it, passing the freshness
/// <c>prompt=login</c> and <c>max_age</c> demand (Story 2.11). A result older than that is refused with
/// <c>login_required</c>, so no code is issued and nothing is committed; Story 4.2 replaces the refusal
/// with a new sign-in. A result fresh enough signs the User in: the
/// claims are <c>sub</c> (the User's <c>usr_</c> ID), <c>sid</c>, <c>auth_time</c> and <c>amr</c>, the ID
/// token gets those and the <c>nonce</c>, and the access token <c>sub</c> and, from Story 3.7, the named API as its
/// audience, or none; one ad-hoc
/// authorization, the Token Family, is anchored to the result's Session, and OpenIddict issues the code.
/// No result is <c>temporarily_unavailable</c>. Either way OpenIddict's response, with <c>iss</c>, ends
/// the transaction. The authorization grants <c>openid</c>, and <c>offline_access</c> when it was asked
/// for (Story 2.10), so that the code's exchange also returns a refresh token.
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

        // The freshness prompt=login and max_age demand (Story 2.11), measured from the request's start here.
        var authenticatedSince = AuthorizeEndpoint.AuthenticatedSince(request, services.Time.GetUtcNow());

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
        var result = await signIn.CompleteAsync(requestTransaction.Context, started, authenticatedSince, http, cancellationToken);
        if (result is null)
        {
            await RefuseAsync(http, Errors.TemporarilyUnavailable, "Sign-in isn't available. Try again later.");
            return;
        }

        // An authentication older than prompt=login or max_age allows gets no code (OIDC Core §3.1.2.1): refused,
        // not re-prompted, until Story 4.2. The refusal rolls back the sign-in's Session with the rest.
        if (!AuthorizeEndpoint.IsFreshEnough(result.AuthTime, authenticatedSince, request.HasPromptValue(PromptValues.Login)))
        {
            await RefuseAsync(http, Errors.LoginRequired, "The User must sign in again.");
            return;
        }

        var subject = PublicId.Format(PublicIdType.User, result.UserId);

        // Story 3.7: the API the request named, kept as the authorization's audience; with none, no aud at all.
        var api = transaction.GetProperty<DirectoryApiTarget>(ApiTargets.ApiProperty);

        // openid, and offline_access when it was asked for and allowed (Story 2.10): what the family grants.
        var scopes = request.GetScopes().Where(AuthorizeEndpoint.GrantableScopes.Contains).Distinct(StringComparer.Ordinal).ToImmutableArray();

        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetScopes(scopes);
        if (api is not null)
        {
            identity.SetAudiences(api.Identifier);

            // Kept on the code and the family's refresh tokens, so each exchange and refresh reads the API again by it.
            identity.SetClaim(ApiTargets.ApiClaim, api.Identifier);
        }

        AuthorizeEndpoint.SetUserClaims(identity, result.UserId, result.SessionId, result.AuthTime, result.Amr);

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
        descriptor.Scopes.UnionWith(scopes);
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
