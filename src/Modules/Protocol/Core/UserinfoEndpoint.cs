using Gatekeep.Kernel.Identifiers;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// Userinfo takes its bearer token from the <c>Authorization</c> header only (Story 2.11, RFC 6750 §2.1): an
/// <c>access_token</c> in the query or the form is dropped before OpenIddict reads the header, so a request
/// with no header has no token, whatever else it carries. A request with both a bearer header and an
/// <c>access_token</c> uses more than one method, which RFC 6750 §2 forbids: <c>invalid_request</c>.
/// </summary>
internal sealed class TakeUserinfoBearerFromHeaderOnly : IOpenIddictServerHandler<ExtractUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractUserInfoRequestContext>()
            .UseSingletonHandler<TakeUserinfoBearerFromHeaderOnly>()
            .SetOrder(OpenIddictServerAspNetCoreHandlers.ExtractAccessToken<ExtractUserInfoRequestContext>.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ExtractUserInfoRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Transaction.Request is { } request)
        {
            var header = TokenEndpoint.Http(context).Request.Headers.Authorization.ToString();
            if (!string.IsNullOrEmpty(request.AccessToken) && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                context.Reject(Errors.InvalidRequest, "Send the access token by one method only.");
                return ValueTask.CompletedTask;
            }

            request.AccessToken = null;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Userinfo reads its access token from the token alone (Story 2.11, AD-13): it opens no transaction, reads no
/// Session or token row and writes nothing, so a valid unexpired access token works until it expires, even
/// after its family was revoked. A value that isn't a JWT can't be one of this Tenant's access tokens, so it
/// is <c>invalid_token</c> here, before OpenIddict would look it up as a reference token.
/// </summary>
internal sealed class RefuseUserinfoReferenceTokens : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<RefuseUserinfoReferenceTokens>()
            .SetOrder(OpenIddictServerHandlers.Protection.ValidateReferenceTokenIdentifier.Descriptor.Order - 400)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is OpenIddictServerEndpointType.UserInfo
            && (string.IsNullOrEmpty(context.Token) || !context.SecurityTokenHandler.CanReadToken(context.Token)))
        {
            context.Reject(Errors.InvalidToken, "The access token isn't valid.");
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// The other half of <see cref="RefuseUserinfoReferenceTokens"/>: once OpenIddict has verified a userinfo access
/// token's signature, issuer and type, its token and authorization entry IDs are dropped from the principal, so
/// OpenIddict never reads the token's row, its status or its family's. The token's own expiry still applies.
/// </summary>
internal sealed class ReadUserinfoTokensStatelessly : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<ReadUserinfoTokensStatelessly>()
            .SetOrder(OpenIddictServerHandlers.Protection.RestoreTokenEntryProperties.Descriptor.Order - 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is OpenIddictServerEndpointType.UserInfo && context.Principal is { } principal)
        {
            principal.RemoveClaims(Claims.Private.TokenId).RemoveClaims(Claims.Private.AuthorizationId);
            context.TokenId = null;
            context.AuthorizationId = null;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Userinfo answers only for a User (Story 2.11, OIDC Core §5.3): the verified access token's <c>sub</c> must be a
/// <c>usr_</c> ID, so a Client Credentials token, whose subject is its client, is <c>invalid_token</c>; and its
/// scopes must include <c>openid</c>, or it is <c>insufficient_scope</c> (403).
/// </summary>
internal sealed class RequireUserinfoUserAndOpenId : IOpenIddictServerHandler<ValidateUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateUserInfoRequestContext>()
            .UseSingletonHandler<RequireUserinfoUserAndOpenId>()
            .SetOrder(OpenIddictServerHandlers.UserInfo.ValidateAuthentication.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateUserInfoRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var principal = context.AccessTokenPrincipal;
        if (principal is null || !PublicId.TryParse(PublicIdType.User, principal.GetClaim(Claims.Subject), out _))
        {
            context.Reject(Errors.InvalidToken, "The access token isn't valid.");
        }
        else if (!principal.HasScope(Scopes.OpenId))
        {
            context.Reject(Errors.InsufficientScope, "The access token wasn't granted openid.");
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Every userinfo response, a User's <c>sub</c> or an error, is <c>Cache-Control: no-store</c> (Story 2.11, OIDC
/// Core §5.3.2 via RFC 6749 §5.1): OpenIddict sets no cache header on this endpoint.
/// </summary>
internal sealed class AnswerUserinfoNoStore : IOpenIddictServerHandler<ApplyUserInfoResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyUserInfoResponseContext>()
            .UseSingletonHandler<AnswerUserinfoNoStore>()
            .SetOrder(OpenIddictServerAspNetCoreHandlers.AttachHttpResponseCode<ApplyUserInfoResponseContext>.Descriptor.Order + 600)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyUserInfoResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var response = TokenEndpoint.Http(context).Response;
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// The userinfo response is exactly <c>{"sub": "usr_…"}</c> (Story 2.11), in place of OpenIddict's
/// <c>AttachAudiences</c> and <c>AttachClaims</c>, which add <c>iss</c>, <c>aud</c> and scope-bound claims: no
/// other claim exists for any scope yet (profile and email come with Epics 5 and 6).
/// </summary>
internal sealed class AttachUserinfoSubject : IOpenIddictServerHandler<HandleUserInfoRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleUserInfoRequestContext>()
            .UseSingletonHandler<AttachUserinfoSubject>()
            .SetOrder(OpenIddictServerHandlers.UserInfo.AttachClaims.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(HandleUserInfoRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Subject = context.AccessTokenPrincipal.GetClaim(Claims.Subject);
        return ValueTask.CompletedTask;
    }
}
