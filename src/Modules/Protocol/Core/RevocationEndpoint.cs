using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Directory.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Microsoft.Extensions.Logging;
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
/// request then commits and answers 200 with no body.</item>
/// <item>A value with another Tenant's prefix, or a malformed one, that isn't a JWT: refused before any lookup, and
/// counted as Story 2.5's unauthenticated cross-Tenant mismatch. Answered 200.</item>
/// <item>Anything else of this Tenant's prefix, an unknown, revoked, redeemed or expired refresh token, a code, or
/// another client's refresh token: <c>invalid_token</c>, which OpenIddict answers as an empty 200. Nothing is
/// revoked, and the request rolls back.</item>
/// <item>A JWT, which is an access or ID token: <c>unsupported_token_type</c> (RFC 7009 §2.2.1). Neither is
/// revocable (AD-13): an access token stays valid until it expires.</item>
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
            // Access and ID tokens are the only JWTs issued here; neither is revocable (AD-13).
            if (context.Options.JsonWebTokenHandler.CanReadToken(token))
            {
                context.Reject(Errors.UnsupportedTokenType, "Only refresh tokens can be revoked; an access token stays valid until it expires.");
                return;
            }

            // No other Tenant's reference token, and no value without a prefix, reaches this Tenant's store (AD-9).
            TokenEndpoint.KeepUnauthenticatedMismatch(context, transaction, services);
            services.Logger?.LogInformation("A token not issued by this Tenant was presented for revocation.");
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

        var application = await applications.FindByClientIdAsync(context.Request.ClientId!, context.CancellationToken) as DirectoryApplication
            ?? throw new InvalidOperationException("The authenticated client has no Application.");

        // Another client's refresh token is left alone (RFC 7009 §2.1), and told apart from no token at all by nothing.
        if (!Guid.TryParse(await tokens.GetApplicationIdAsync(entry, context.CancellationToken), out var owner) || owner != application.Id)
        {
            RevokeNothing(context);
            return;
        }

        await services.Sessions.RevokeAccessAsync(
            transaction.Context,
            new RevocationScope.Authorization(family),
            exceptSessionId: null,
            RevocationReason.ClientRevoke,
            Actor.Client(application.Id),
            context.CancellationToken);
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
