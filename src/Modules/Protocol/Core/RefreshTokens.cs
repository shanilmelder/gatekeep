using System.Security.Claims;
using Gatekeep.Kernel.Limits;
using Gatekeep.Modules.Sessions.Contracts;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The refresh grant's shared pieces (Story 2.10, FR-15, AD-13).
/// <list type="bullet">
/// <item>A refresh token is a <c>{tenantPublicId}.{random}</c> reference token, stored only as its hash.</item>
/// <item>A code exchange whose authorization granted <c>offline_access</c> issues it.</item>
/// <item>It rotates on every use, with no leeway.</item>
/// <item>A rotated token presented again revokes its whole Token Family: OpenIddict's <c>ValidateTokenEntry</c>
/// calls the token store, which calls <c>ISessions.RevokeAccessAsync</c>.</item>
/// </list>
/// Two limits apply. Each refresh token expires <see cref="SecurityLimits.RefreshTokenInactivityLifetime"/>
/// after its issue. None of a family outlives the family's creation plus
/// <see cref="SecurityLimits.RefreshTokenAbsoluteLifetime"/>.
/// <para>
/// <b>A refresh naming scopes</b> gets only those, from what its family was granted. One that leaves out
/// <c>offline_access</c>, such as <c>scope=openid</c>, gets new access and ID tokens and no new refresh
/// token. Its presented token is still redeemed. That is the client's choice to end its offline access.
/// </para>
/// <para>
/// <b>Concurrent refreshes and revocations.</b> <see cref="SignInRefresh"/> reads the family before the
/// redemption, and that read share-locks the authorization row until the request ends
/// (<c>ISessions.FindFamilyAsync</c>). A revocation therefore either finishes first, and the refresh reads
/// <c>revoked</c>, or waits for the refresh to commit and then revokes its new tokens. Two refreshes of one
/// token both pass that read. OpenIddict ignores a failed refresh redemption, so the token store reports
/// each request's own successful redemption on the request. <see cref="RefuseLateRefreshes"/> refuses the
/// request that lost with <c>invalid_grant</c>. Its store has already recorded the family's
/// <c>token_reuse</c> revocation, so nothing it issued survives.
/// </para>
/// <para>
/// <b>Late refusals that burn the presented token.</b> OpenIddict marks the presented refresh token
/// <c>redeemed</c> before it makes the new tokens (<c>RedeemTokenEntry</c>), and a refused request rolls that
/// back. A refusal after that point must not leave the token usable, so <see cref="RefuseLateRefreshes"/>
/// commits its burn through <c>FailureContext</c>. The only such refusal is a family found revoked after the
/// redemption. With the share lock, <c>RevokeAccessAsync</c> can't revoke it there, so this stays a
/// defensive refusal. Epic 5's blocked User belongs there too. A lost race needs no burn, since its
/// revocation is kept. Any other failure after the redemption, such as a Transit or database outage, is not
/// a refusal of the token: it rolls back, and the token stays usable.
/// </para>
/// </summary>
internal static class RefreshTokens
{
    /// <summary>Where <see cref="SignInRefresh"/> leaves the presented token's <see cref="TokenFamily"/>.</summary>
    public const string FamilyProperty = ".gatekeep_token_family";

    public const string NoLongerValidDescription = "The refresh token is no longer valid.";

    /// <summary>When no refresh token of <paramref name="family"/> may be valid any more.</summary>
    public static DateTimeOffset AbsoluteEnd(TokenFamily family) => family.CreatedAt + SecurityLimits.RefreshTokenAbsoluteLifetime;

    public static Guid? AuthorizationId(ClaimsPrincipal? principal) =>
        Guid.TryParse(principal?.GetAuthorizationId(), out var id) && id != Guid.Empty ? id : null;
}

/// <summary>
/// A refresh may name only scopes its family was granted (Story 2.10, RFC 6749 §6): any other is
/// <c>invalid_scope</c>. It runs once OpenIddict has read the refresh token, before its scope permission and
/// granted-scope checks, which would answer <c>invalid_request</c> or <c>invalid_grant</c>.
/// </summary>
internal sealed class RefuseUngrantedRefreshScopes : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<RefuseUngrantedRefreshScopes>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateAuthentication.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsRefreshTokenGrantType() || string.IsNullOrEmpty(context.Request.Scope))
        {
            return ValueTask.CompletedTask;
        }

        var granted = context.RefreshTokenPrincipal?.GetScopes() ?? [];
        if (context.Request.GetScopes().Any(scope => !granted.Contains(scope, StringComparer.Ordinal)))
        {
            context.Reject(Errors.InvalidScope, "A refresh may name only scopes its authorization granted.");
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Signs a refresh in (Story 2.10, AD-13), before OpenIddict redeems the presented token.
/// <list type="bullet">
/// <item>Reading the family share-locks its authorization until the request ends (see <see cref="RefreshTokens"/>).</item>
/// <item>The family must still be valid.</item>
/// <item>It must be within its absolute limit, the family's creation plus
/// <see cref="SecurityLimits.RefreshTokenAbsoluteLifetime"/>. Past it the refresh is <c>invalid_grant</c>,
/// whatever the presented token's own expiry says, and nothing is revoked or burnt.</item>
/// <item>A Tenant with no <c>current</c> Signing Key is <c>server_error</c>, as for Client Credentials, and
/// nothing is redeemed.</item>
/// </list>
/// The principal is the refresh token's, changed in three ways:
/// <list type="bullet">
/// <item><c>sub</c>, <c>sid</c>, <c>auth_time</c> and <c>amr</c> are set again from the family's anchored
/// Session, so the new ID token says what that Session says.</item>
/// <item>A requested <c>scope</c> narrows its scopes.</item>
/// <item>It carries no <c>nonce</c>, so the new ID token has none (OIDC Core §12.2).</item>
/// </list>
/// </summary>
internal sealed class SignInRefresh(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
            .UseScopedHandler<SignInRefresh>()
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 1_500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsRefreshTokenGrantType())
        {
            return;
        }

        var runtime = context.Transaction.GetProperty<TenantRuntime>(TenantRuntime.Property)
            ?? throw new InvalidOperationException("The token endpoint runs only on a Tenant runtime.");
        if (!runtime.SigningKeys.Any(k => k.CanSign))
        {
            services.Logger?.LogWarning("A refresh was refused: the Tenant has no current Signing Key.");
            context.Reject(Errors.ServerError, "The token endpoint can't issue tokens now.");
            return;
        }

        var presented = context.Principal ?? throw new InvalidOperationException("A refresh has the refresh token's principal.");
        var family = RefreshTokens.AuthorizationId(presented) is { } authorizationId
            ? await services.Sessions.FindFamilyAsync(transaction.Context, authorizationId, context.CancellationToken)
            : null;

        if (family is not { IsValid: true })
        {
            context.Reject(Errors.InvalidGrant, RefreshTokens.NoLongerValidDescription);
            return;
        }

        if (services.Time.GetUtcNow() >= RefreshTokens.AbsoluteEnd(family))
        {
            services.Logger?.LogInformation("A refresh was refused: its Token Family is past its absolute lifetime.");
            context.Reject(Errors.InvalidGrant, RefreshTokens.NoLongerValidDescription);
            return;
        }

        context.Transaction.SetProperty(RefreshTokens.FamilyProperty, family);

        var principal = presented.Clone(static claim => claim.Type != Claims.Private.Nonce);
        var identity = principal.Identity as ClaimsIdentity
            ?? throw new InvalidOperationException("A refresh token's principal has a claims identity.");
        AuthorizeEndpoint.SetUserClaims(identity, family.UserId, family.SessionId, family.AuthTime, family.Amr);

        // Only the scopes asked for, all of them granted (RefuseUngrantedRefreshScopes). Without
        // offline_access, no new refresh token is made.
        if (!string.IsNullOrEmpty(context.Request.Scope))
        {
            principal.SetScopes(context.Request.GetScopes().Intersect(presented.GetScopes(), StringComparer.Ordinal));
        }

        context.SignIn(principal);
    }
}

/// <summary>
/// The late refusals of a refresh (Story 2.10), right after OpenIddict's <c>RedeemTokenEntry</c>, which
/// ignores a failed redemption of a refresh token.
/// <list type="bullet">
/// <item>The token store must have reported this request's own redemption of the presented token as
/// successful. If it didn't, a concurrent refresh redeemed it first, and the token store has recorded the
/// family's <c>token_reuse</c> revocation. Under READ COMMITTED the row reads <c>redeemed</c> for the loser
/// too, which is why the request's own report is used. This request is <c>invalid_grant</c>, so exactly one
/// of them succeeds.</item>
/// <item>Its family must still be valid. If it reads revoked, the refresh is <c>invalid_grant</c>, and the
/// presented token's burn is committed after the rollback, so the token stays redeemed. With
/// <see cref="SignInRefresh"/>'s share lock, <c>RevokeAccessAsync</c> can't get here, so this is defensive
/// (see <see cref="RefreshTokens"/>).</item>
/// </list>
/// </summary>
internal sealed class RefuseLateRefreshes(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .AddFilter<RequireDegradedModeDisabled>()
            .AddFilter<RequireTokenStorageEnabled>()
            .UseScopedHandler<RefuseLateRefreshes>()
            .SetOrder(OpenIddictServerHandlers.RedeemTokenEntry.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is not OpenIddictServerEndpointType.Token || !context.Request.IsRefreshTokenGrantType())
        {
            return;
        }

        var authentication = context.Transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!)
            ?? throw new InvalidOperationException("A refresh is authenticated before it signs in.");
        var presented = authentication.RefreshTokenPrincipal
            ?? throw new InvalidOperationException("A refresh carries its refresh token's principal.");

        if (!Guid.TryParse(presented.GetTokenId(), out var tokenId) || !transaction.HasRedeemed(tokenId))
        {
            // A concurrent refresh redeemed it first; the token store recorded the family's revocation.
            services.Logger?.LogInformation("A refresh was refused: a concurrent refresh redeemed its token first.");
            context.Reject(Errors.InvalidGrant, RefreshTokens.NoLongerValidDescription);
            return;
        }

        var family = RefreshTokens.AuthorizationId(presented) is { } authorizationId
            ? await services.Sessions.FindFamilyAsync(transaction.Context, authorizationId, context.CancellationToken)
            : null;
        if (family is { IsValid: true })
        {
            return;
        }

        // Redeemed, then refused: the burn is kept, so the token can't be used again (Story 2.2's carry-over).
        transaction.KeepOnFailure((log, cancellationToken) => services.Sessions.BurnRefreshTokenAsync(log, tokenId, cancellationToken));
        services.Logger?.LogInformation("A refresh was refused: its Token Family was revoked while it ran.");
        context.Reject(Errors.InvalidGrant, RefreshTokens.NoLongerValidDescription);
    }
}

/// <summary>
/// Prepares every new refresh token of a family (Story 2.10, AD-13), on a code exchange or a refresh alike,
/// right after OpenIddict's <c>PrepareRefreshTokenPrincipal</c>.
/// <list type="bullet">
/// <item>OpenIddict sets its expiry to <see cref="SecurityLimits.RefreshTokenInactivityLifetime"/> from now.
/// This cuts it to the family's creation plus <see cref="SecurityLimits.RefreshTokenAbsoluteLifetime"/> if
/// that comes first. So no refresh token of a family outlives the family's absolute end, however often it
/// rotates; OpenIddict has no family-wide lifetime of its own.</item>
/// <item>The absolute end bounds refresh tokens only. Access and ID tokens issued near it keep their full
/// §5.2 lifetime, <see cref="SecurityLimits.DefaultAccessTokenLifetime"/>, and can outlive it by that
/// much.</item>
/// <item>It drops the code's <c>nonce</c>, which OpenIddict would otherwise carry into every refresh token
/// and every refreshed ID token. A refreshed ID token has no <c>nonce</c> (OIDC Core §12.2).</item>
/// </list>
/// </summary>
internal sealed class CapRefreshTokenLifetime(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .AddFilter<RequireRefreshTokenGenerated>()
            .UseScopedHandler<CapRefreshTokenLifetime>()
            .SetOrder(OpenIddictServerHandlers.PrepareRefreshTokenPrincipal.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var principal = context.RefreshTokenPrincipal
            ?? throw new InvalidOperationException("A refresh token is made from its principal.");

        var family = context.Transaction.GetProperty<TokenFamily>(RefreshTokens.FamilyProperty)
            ?? (RefreshTokens.AuthorizationId(principal) is { } authorizationId
                ? await services.Sessions.FindFamilyAsync(transaction.Context, authorizationId, context.CancellationToken)
                : null)
            ?? throw new InvalidOperationException("A refresh token is issued only in a Token Family.");

        var end = RefreshTokens.AbsoluteEnd(family);
        if (principal.GetExpirationDate() is not { } expires || expires > end)
        {
            principal.SetExpirationDate(end);
        }

        principal.SetClaim(Claims.Private.Nonce, (string?)null);
    }
}
