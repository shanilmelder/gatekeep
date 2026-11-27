using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The logout confirmation's CSRF token (Story 4.13): <c>base64url(SHA-256("gatekeep-logout-csrf\0" || SHA-256(session)))</c>,
/// the inner hash being the <c>__Host-gk_session</c> value's SHA-256, as the Session is stored. The confirmation has no
/// transaction, so its token is bound to the Session the browser presents: only a page this host served to that browser can
/// post "Log out". Derived, never stored, and compared in constant time.
/// </summary>
internal static class LogoutCsrf
{
    private static ReadOnlySpan<byte> Label => "gatekeep-logout-csrf\0"u8;

    public static string Derive(Secret<string> session) => session.Use(Derive);

    public static bool Matches(Secret<string> session, string? presented) =>
        !string.IsNullOrEmpty(presented)
        && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Derive(session)), Encoding.UTF8.GetBytes(presented));

    private static string Derive(string session)
    {
        var value = Encoding.ASCII.GetBytes(session);
        var hash = SHA256.HashData(value);
        var input = new byte[Label.Length + hash.Length];
        try
        {
            Label.CopyTo(input);
            hash.CopyTo(input.AsSpan(Label.Length));
            return Base64Url.EncodeToString(SHA256.HashData(input));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(value);
        }
    }
}

/// <summary>
/// An end-session request's parameters (Story 4.13, RP-Initiated Logout §2), as sent: each a non-empty string within
/// <see cref="MaxLength"/>, or null. Nothing here is trusted: <see cref="LogoutRedirect"/> decides what they come to.
/// </summary>
internal sealed record EndSessionParameters(string? IdTokenHint, string? PostLogoutRedirectUri, string? State, string? ClientId)
{
    /// <summary>The longest value kept, 8 KiB: ample for an ID token, a logout URL and a <c>state</c>. A longer one is dropped.</summary>
    public const int MaxLength = 8 * 1024;

    public static EndSessionParameters None { get; } = new(null, null, null, null);

    public static EndSessionParameters Of(string? idTokenHint, string? postLogoutRedirectUri, string? state, string? clientId) =>
        new(Kept(idTokenHint), Kept(postLogoutRedirectUri), Kept(state), Kept(clientId));

    /// <summary>The parameters of OpenIddict's extracted end-session request, a query or a form alike.</summary>
    public static EndSessionParameters From(OpenIddictRequest? request) =>
        request is null ? None : Of(request.IdTokenHint, request.PostLogoutRedirectUri, request.State, request.ClientId);

    private static string? Kept(string? value) => string.IsNullOrEmpty(value) || value.Length > MaxLength ? null : value;
}

/// <summary>
/// Where a logout goes back to (Story 4.13): the one decision, a function of the request's parameters and the Tenant's
/// keys and Applications alone, made again on the confirmation's POST, so no logout request is stored. A redirect target
/// exists only when every check holds:
/// <list type="number">
/// <item><c>id_token_hint</c> is an ID token this Tenant issued: RS256 under one of its published Signing Keys, with its
/// issuer, and never an access token (<c>at+jwt</c>). It may have expired.</item>
/// <item>Its one <c>aud</c> is one of the Tenant's live Applications, never the hidden system one or a deleted one.</item>
/// <item><c>client_id</c>, when given, is that Application.</item>
/// <item><c>post_logout_redirect_uri</c> is exactly one of its Allowed Logout URLs, but for a <c>native</c> Application's
/// loopback port (RFC 8252 §7.3).</item>
/// </list>
/// The target is that URL with <c>state</c> appended when one was given; otherwise there is none, and nothing tells which
/// check failed. The hint never selects a Session: only the browser's own cookie does.
/// </summary>
internal static class LogoutRedirect
{
    /// <summary>The <c>typ</c> OpenIddict's ID tokens carry; any other type it signs (access tokens, codes) is refused.</summary>
    private const string IdTokenType = "JWT";

    /// <summary>
    /// The redirect target, or null. Any failure but cancellation, of the Tenant's keys, the hint's validation or the
    /// Application's lookup, is no target: the logout itself is already complete. Only the error's type is logged.
    /// </summary>
    public static async Task<string?> DecideAsync(
        HttpContext http, TokenEndpointServices services, CommandContext context, ResolvedTenant tenant, EndSessionParameters parameters, CancellationToken cancellationToken)
    {
        try
        {
            return await DecideCheckedAsync(http, services, context, tenant, parameters, cancellationToken);
        }
        catch (Exception e) when (!cancellationToken.IsCancellationRequested)
        {
            services.Logger?.LogWarning("A logout's redirect wasn't decided: it failed on {ErrorType}.", e.GetType().Name);
            return null;
        }
    }

    private static async Task<string?> DecideCheckedAsync(
        HttpContext http, TokenEndpointServices services, CommandContext context, ResolvedTenant tenant, EndSessionParameters parameters, CancellationToken cancellationToken)
    {
        if (parameters is not { IdTokenHint: { } hint, PostLogoutRedirectUri: { } target })
        {
            return null;
        }

        var runtime = await http.RequestServices.GetRequiredService<TenantRuntimes>().GetRuntimeAsync(tenant, cancellationToken);
        if (await VerifiedAudienceAsync(hint, runtime) is not { } audience
            || (parameters.ClientId is { } clientId && !string.Equals(clientId, audience, StringComparison.Ordinal))
            || !PublicId.TryParse(PublicIdType.Application, audience, out var applicationId)
            || await services.Directory.FindApplicationAsync(context, applicationId, cancellationToken) is not { } application
            || !string.Equals(application.ClientId, audience, StringComparison.Ordinal)
            || !DirectoryContract.MatchesPostLogoutRedirectUri(application, target))
        {
            return null;
        }

        // A registered logout URL has no fragment, so the query helper appends state to its query as it stands.
        return parameters.State is { } state ? QueryHelpers.AddQueryString(target, "state", state) : target;
    }

    /// <summary>The hint's one audience when it is an ID token this Tenant signed and issued, expired or not; else null.</summary>
    private static async Task<string?> VerifiedAudienceAsync(string hint, TenantRuntime runtime)
    {
        var handler = new JsonWebTokenHandler();
        if (runtime.SigningKeys.Count == 0 || !handler.CanReadToken(hint))
        {
            return null;
        }

        var result = await handler.ValidateTokenAsync(hint, new TokenValidationParameters
            {
                IssuerSigningKeys = [.. runtime.SigningKeys.Select(k => k.VerificationKey())],
                ValidIssuer = runtime.Issuer.AbsoluteUri,
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = false,
                RequireExpirationTime = false,
                RequireSignedTokens = true,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            });

        // Only an ID token's own type, or none: an access token (at+jwt) or any other token type the Tenant signs is refused.
        if (!result.IsValid
            || result.SecurityToken is not JsonWebToken token
            || !(string.IsNullOrEmpty(token.Typ) || string.Equals(token.Typ, IdTokenType, StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var audiences = token.Audiences.ToList();
        return audiences.Count == 1 && !string.IsNullOrEmpty(audiences[0]) ? audiences[0] : null;
    }
}

/// <summary>
/// The end-session endpoint's passthrough (Story 4.13): an end-session request OpenIddict has extracted, a GET's query or
/// a POST's form, reaches it with OpenIddict's own checks removed, and gets the logout page
/// (<see cref="LoginEndpoints.EndSessionPageAsync"/>).
/// </summary>
internal static class EndSessionPassthrough
{
    public static async Task InvokeAsync(HttpContext http, RequestDelegate next)
    {
        var transaction = http.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
        if (transaction is not { EndpointType: OpenIddictServerEndpointType.EndSession } || http.Response.HasStarted)
        {
            await next(http);
            return;
        }

        await LoginEndpoints.EndSessionPageAsync(http, EndSessionParameters.From(transaction.Request));
    }
}

/// <summary>
/// OpenIddict never answers an end-session request itself (Story 4.13): whatever it would send, an error for a request it
/// couldn't read included, is replaced by the logout page for no parameters at all, so it never redirects. It runs first,
/// before OpenIddict attaches a redirect URI or writes its plain-text error. Only the error's code is logged.
/// </summary>
internal sealed class AnswerEndSessionWithLogoutPage(ILoggerFactory? loggers = null) : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
{
    private readonly ILogger? _logger = loggers?.CreateLogger("Gatekeep.Protocol");

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
            .UseSingletonHandler<AnswerEndSessionWithLogoutPage>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ApplyEndSessionResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var http = TokenEndpoint.Http(context);
        if (http.Response.HasStarted)
        {
            context.HandleRequest();
            return;
        }

        _logger?.LogInformation("An end-session request OpenIddict answered with {Error} got the logout page.", context.Error ?? "no error");
        http.Response.StatusCode = StatusCodes.Status200OK;
        http.Response.Headers.Location = default;
        await LoginEndpoints.EndSessionPageAsync(http, EndSessionParameters.None);
        context.HandleRequest();
    }
}

/// <summary>Hosted Login's logout (Story 4.13, FR-24): the end-session page and its confirmation.</summary>
internal static partial class LoginEndpoints
{
    /// <summary>
    /// The end-session page (Story 4.13): with a live Session cookie in this Tenant, the logout confirmation, carrying the
    /// request's parameters and the Session-bound logout CSRF token. With none there is nothing to end: the cookie is cleared
    /// and the logout is complete, <c>logged_out</c> with the decided target or none. It writes nothing.
    /// </summary>
    internal static async Task EndSessionPageAsync(HttpContext http, EndSessionParameters parameters)
    {
        var login = Login.Of(http);
        var presented = SignInCookies.Read(http, ProtocolContract.SessionCookie);

        // The Session cookie is SameSite=Lax, so a relying party's cross-site form POST arrives without it: the same request
        // as a top-level GET, which carries it, decides whether there is a Session to end.
        if (presented is null && HttpMethods.IsPost(http.Request.Method))
        {
            http.Response.StatusCode = StatusCodes.Status303SeeOther;
            http.Response.Headers.Location = EndSessionGet(parameters);
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers.Pragma = "no-cache";
            return;
        }

        StepResponse step;
        await using (var scope = await TenantScope.BeginAsync(login.Services.Database.Source, login.Tenant.TenantId, login.Cancellation))
        {
            var context = scope.CreateCommandContext();
            if (presented is not null && await login.Services.Sessions.FindLiveAsync(context, presented, login.Cancellation) is not null)
            {
                step = StepResponse.Logout(
                    login.Tenant.Name,
                    LogoutCsrf.Derive(presented),
                    new LogoutData(login.Tenant.Name, parameters.IdTokenHint, parameters.PostLogoutRedirectUri, parameters.State, parameters.ClientId));
            }
            else
            {
                var target = await LogoutRedirect.DecideAsync(http, login.Services, context, login.Tenant, parameters, login.Cancellation);
                SignInCookies.Clear(http, ProtocolContract.SessionCookie);
                step = StepResponse.LoggedOut(login.Tenant.Name, target);
            }
        }

        await login.Pages.WriteAsync(http, StatusCodes.Status200OK, step, login.Cancellation);
    }

    /// <summary>The end-session endpoint's GET form, its query the kept parameters.</summary>
    private static string EndSessionGet(EndSessionParameters parameters)
    {
        var query = new List<KeyValuePair<string, string?>>();
        foreach (var (name, value) in new[]
        {
            ("id_token_hint", parameters.IdTokenHint),
            ("post_logout_redirect_uri", parameters.PostLogoutRedirectUri),
            ("state", parameters.State),
            ("client_id", parameters.ClientId),
        })
        {
            if (value is not null)
            {
                query.Add(new(name, value));
            }
        }

        return ProtocolContract.EndSessionPath + QueryString.Create(query);
    }

    /// <summary>
    /// The largest "Log out" body read: four parameters of <see cref="EndSessionParameters.MaxLength"/> characters, each
    /// written entirely in six-byte <c>\uXXXX</c> escapes at worst, and 1 KiB for the names and the braces.
    /// </summary>
    internal const int MaxLogoutBodyBytes = (4 * EndSessionParameters.MaxLength * 6) + 1024;

    /// <summary>
    /// "Log out" (Story 4.13): the exact-host <c>Origin</c>, then the logout CSRF token against the Session cookie presented,
    /// are checked before anything is read; a failure is 403 and ends nothing. With no Session cookie at all there is nothing
    /// to end and no token to check. A live Session in this Tenant then ends, committed before the redirect is decided, with
    /// every Token Family anchored to it, through the one revocation path, by its User. Only the browser's own Session ends:
    /// the hint selects the redirect, never a Session. The cookie is cleared, and the answer is <c>logged_out</c> with the
    /// target decided again from the posted parameters, or none.
    /// </summary>
    private static async Task LogoutAsync(HttpContext http)
    {
        var login = Login.Of(http);
        if (!await login.CheckOriginAsync())
        {
            return;
        }

        // With no Session cookie at all (expired, or logged out in another tab) there is nothing to end, so no CSRF token is
        // needed: the logout is complete. A cookie with the wrong token is refused.
        var presented = SignInCookies.Read(http, ProtocolContract.SessionCookie);
        if (presented is not null && !LogoutCsrf.Matches(presented, Login.SingleHeader(http, ProtocolContract.CsrfHeader)))
        {
            await login.RefuseChecksAsync(SignInStepResponses.CsrfMismatch);
            return;
        }

        using var body = await ReadBodyAsync(http, login.Cancellation, MaxLogoutBodyBytes);
        if (body is null)
        {
            await login.InvalidRequestAsync();
            return;
        }

        var parameters = EndSessionParameters.Of(Text(body, "idTokenHint"), Text(body, "postLogoutRedirectUri"), Text(body, "state"), Text(body, "clientId"));

        // The logout is committed and the cookie cleared first, so nothing in the redirect's decision can undo it.
        if (presented is not null)
        {
            await using var scope = await TenantScope.BeginAsync(login.Services.Database.Source, login.Tenant.TenantId, login.Cancellation);
            var context = scope.CreateCommandContext();
            if (await login.Services.Sessions.FindLiveAsync(context, presented, login.Cancellation) is { } live)
            {
                await login.Services.Sessions.RevokeAccessAsync(
                    context,
                    new RevocationScope.Session(live.SessionId),
                    exceptSessionId: null,
                    RevocationReason.Logout,
                    Actor.User(live.UserId),
                    login.Cancellation);
                await scope.CommitAsync(login.Cancellation);
            }
        }

        SignInCookies.Clear(http, ProtocolContract.SessionCookie);

        string? target;
        await using (var read = await TenantScope.BeginAsync(login.Services.Database.Source, login.Tenant.TenantId, login.Cancellation))
        {
            target = await LogoutRedirect.DecideAsync(http, login.Services, read.CreateCommandContext(), login.Tenant, parameters, login.Cancellation);
        }

        await login.AnswerAsync(StatusCodes.Status200OK, StepResponse.LoggedOut(login.Tenant.Name, target));
    }
}
