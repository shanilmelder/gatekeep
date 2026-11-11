using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The revocation endpoint's client authentication (Story 2.11, RFC 7009 §2.1): Gatekeep's own, the token
/// endpoint's <see cref="AuthenticateGatekeepClient.AuthenticateAsync"/>, before anything else in the
/// request is validated, so a missing, unknown or wrong secret gets the one same <c>invalid_client</c>, and
/// a cross-Tenant credential is classified and logged exactly as at the token endpoint (Story 2.2: every
/// endpoint that authenticates clients is covered before it is enabled).
/// </summary>
internal sealed class AuthenticateGatekeepRevocationClient(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ValidateRevocationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateRevocationRequestContext>()
            .UseScopedHandler<AuthenticateGatekeepRevocationClient>()
            .SetOrder(OpenIddictServerHandlers.Revocation.ValidateTokenParameter.Descriptor.Order - 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateRevocationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return AuthenticateGatekeepClient.AuthenticateAsync(context, transaction, services);
    }
}

/// <summary>
/// OpenIddict validates nothing of a revoked token itself (Story 2.11): its generic token validation would
/// look a reference token up by itself and, finding a rotated refresh token or a used code, revoke its whole
/// family as reuse, which a revocation of an already redeemed token must not do. Gatekeep's
/// <see cref="RevokeRefreshTokenFamily"/> reads the token instead.
/// </summary>
internal sealed class LeaveRevokedTokenToGatekeep : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .UseSingletonHandler<LeaveRevokedTokenToGatekeep>()
            .SetOrder(OpenIddictServerHandlers.EvaluateValidatedTokens.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is OpenIddictServerEndpointType.Revocation)
        {
            context.ExtractGenericToken = false;
            context.RequireGenericToken = false;
            context.ValidateGenericToken = false;
            context.RejectGenericToken = false;
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// The revocation itself (Story 2.11, RFC 7009 §2.2, AD-13), in place of OpenIddict's <c>RevokeToken</c>, in
/// the request's open transaction, after the client is authenticated. The <c>token_type_hint</c> is never
/// read, so a wrong hint changes nothing.
/// <list type="bullet">
/// <item>A <c>valid</c>, unexpired refresh token of this Tenant issued to the authenticated client: its whole Token
/// Family is revoked through <see cref="ISessions.RevokeAccessAsync"/> with <see cref="RevocationReason.ClientRevoke"/>,
/// by <see cref="Actor.Client"/> (the client's Application), which writes one <c>sessions.access.revoked</c>. The
/// request then commits and answers 200 with no body. A revocation that, once its statements ran, changed no
/// family and no token (another revocation, a logout or a reuse got there first) revokes nothing instead, so
/// its event rolls back and only one <c>sessions.access.revoked</c> is ever kept.</item>
/// <item>A JWT whose header <c>kid</c> is one of this Tenant's published Signing Keys, so an access or ID token of
/// this Tenant: <c>unsupported_token_type</c> (RFC 7009 §2.2.1). Neither is revocable (AD-13): an access token
/// stays valid until it expires. Its signature isn't checked: the answer revokes nothing either way.</item>
/// <item>Any other value without this Tenant's prefix, another Tenant's reference token or JWT, or a malformed
/// value: refused before any lookup, and counted as Story 2.5's unauthenticated cross-Tenant mismatch. Answered 200.</item>
/// <item>Anything else of this Tenant's prefix, an unknown, revoked, redeemed or expired refresh token, a code, or
/// another client's refresh token: <c>invalid_token</c>, which OpenIddict answers as an empty 200. Nothing is
/// revoked, and the request rolls back.</item>
/// </list>
/// </summary>
internal sealed class RevokeRefreshTokenFamily(
    IOpenIddictTokenManager tokens,
    IOpenIddictApplicationManager applications,
    TokenRequestTransaction transaction,
    TokenEndpointServices services)
    : IOpenIddictServerHandler<HandleRevocationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleRevocationRequestContext>()
            .UseScopedHandler<RevokeRefreshTokenFamily>()
            .SetOrder(OpenIddictServerHandlers.Revocation.RevokeToken.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleRevocationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var token = context.Request.Token ?? string.Empty;
        var prefix = PublicId.Format(PublicIdType.Tenant, TokenEndpoint.Tenant(context).TenantId) + ".";

        if (!token.StartsWith(prefix, StringComparison.Ordinal))
        {
            // Access and ID tokens are the only JWTs issued here, under this Tenant's keys; neither is revocable (AD-13).
            if (IsThisTenantsJwt(context, token))
            {
                context.Reject(Errors.UnsupportedTokenType, "Only refresh tokens can be revoked; an access token stays valid until it expires.");
                return;
            }

            // No other Tenant's token, and no value without a prefix, reaches this Tenant's store (AD-9). Counted, and
            // logged at most once per source per hour, by the mismatch itself.
            TokenEndpoint.KeepUnauthenticatedMismatch(context, transaction, services);
            RevokeNothing(context);
            return;
        }

        var entry = await tokens.FindByReferenceIdAsync(token, context.CancellationToken);
        if (entry is null
            || !await tokens.HasTypeAsync(entry, TokenTypeIdentifiers.RefreshToken, context.CancellationToken)
            || !await tokens.HasStatusAsync(entry, Statuses.Valid, context.CancellationToken)
            || await tokens.GetExpirationDateAsync(entry, context.CancellationToken) is not { } expires
            || expires <= services.Time.GetUtcNow()
            || !Guid.TryParse(await tokens.GetAuthorizationIdAsync(entry, context.CancellationToken), out var family)
            || family == Guid.Empty)
        {
            RevokeNothing(context);
            return;
        }

        // An Application deleted since its client was authenticated revokes nothing.
        if (await applications.FindByClientIdAsync(context.Request.ClientId!, context.CancellationToken) is not DirectoryApplication application)
        {
            RevokeNothing(context);
            return;
        }

        // Another client's refresh token is left alone (RFC 7009 §2.1), and told apart from no token at all by nothing.
        if (!Guid.TryParse(await tokens.GetApplicationIdAsync(entry, context.CancellationToken), out var owner) || owner != application.Id)
        {
            RevokeNothing(context);
            return;
        }

        var outcome = await services.Sessions.RevokeAccessAsync(
            transaction.Context,
            new RevocationScope.Authorization(family),
            exceptSessionId: null,
            RevocationReason.ClientRevoke,
            Actor.Client(application.Id),
            context.CancellationToken);

        // The status read above takes no lock: a concurrent revocation, a logout or a reuse may have revoked the
        // family first, and this request's statements, waiting on its row locks, then changed nothing. Its event
        // rolls back with it, so one revocation is recorded once.
        if (outcome.FamiliesRevoked == 0 && outcome.TokensRevoked == 0)
        {
            RevokeNothing(context);
        }
    }

    /// <summary>
    /// Whether <paramref name="token"/> reads as a JWT whose header names one of this Tenant's published Signing
    /// Keys as its <c>kid</c>. Nothing else of it is read.
    /// </summary>
    private static bool IsThisTenantsJwt(HandleRevocationRequestContext context, string token)
    {
        if (!context.Options.JsonWebTokenHandler.CanReadToken(token))
        {
            return false;
        }

        string? kid;
        try
        {
            kid = context.Options.JsonWebTokenHandler.ReadJsonWebToken(token).Kid;
        }
        catch (Exception e) when (e is ArgumentException or Microsoft.IdentityModel.Tokens.SecurityTokenException or System.Text.Json.JsonException or FormatException)
        {
            // A malformed header: not one of this Tenant's tokens.
            return false;
        }

        return !string.IsNullOrEmpty(kid)
            && context.Options.SigningCredentials.Any(c => string.Equals(c.Key.KeyId, kid, StringComparison.Ordinal));
    }

    /// <summary>Nothing is revoked: OpenIddict answers <c>invalid_token</c> as an empty 200 (RFC 7009 §2.2), and the request rolls back.</summary>
    private static void RevokeNothing(HandleRevocationRequestContext context) =>
        context.Reject(Errors.InvalidToken, "The token isn't valid.");
}

/// <summary>
/// A successful revocation, or one that revoked nothing, is a 200 with an empty body (RFC 7009 §2.2), and
/// <c>no-store</c> as OpenIddict sets it; OpenIddict's own would be an empty JSON object. An error, such as
/// <c>unsupported_token_type</c>, <c>invalid_client</c> or a rate limit's, keeps its OAuth error body.
/// </summary>
internal sealed class AnswerRevocationWithNoBody : IOpenIddictServerHandler<ApplyRevocationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyRevocationResponseContext>()
            .UseSingletonHandler<AnswerRevocationWithNoBody>()
            .SetOrder(OpenIddictServerAspNetCoreHandlers.ProcessJsonResponse<ApplyRevocationResponseContext>.Descriptor.Order - 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ApplyRevocationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (string.IsNullOrEmpty(context.Transaction.Response?.Error))
        {
            TokenEndpoint.Http(context).Response.ContentLength = 0;
            context.HandleRequest();
        }

        return ValueTask.CompletedTask;
    }
}
