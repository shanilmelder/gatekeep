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
/// The refresh grant's shared pieces (Story 2.10, FR-15, AD-13). A refresh token is a
/// <c>{tenantPublicId}.{random}</c> reference token, stored only as its hash, issued by a code exchange
/// whose authorization granted <c>offline_access</c>, and rotated on every use with no leeway. A rotated
/// one presented again revokes its whole Token Family (OpenIddict's <c>ValidateTokenEntry</c>, through
/// the token store, into <c>ISessions.RevokeAccessAsync</c>). Two limits apply: each refresh token
/// expires <see cref="SecurityLimits.RefreshTokenInactivityLifetime"/> after its issue, and none of a
/// family outlives the family's creation plus <see cref="SecurityLimits.RefreshTokenAbsoluteLifetime"/>.
/// <para>
/// <b>Late refusals that burn the presented token.</b> OpenIddict marks the presented refresh token
/// <c>redeemed</c> before the new tokens are made (<c>RedeemTokenEntry</c>), and a refused request rolls
/// that back. A refusal after that point must not leave the token usable, so <see cref="RefuseLateRefreshes"/>
/// commits its burn through <c>FailureContext</c>. Today the only such refusal is a family revoked while
/// the refresh ran. A redemption lost to a concurrent refresh is refused there too, and needs no burn:
/// the token store has already recorded the family's <c>token_reuse</c> revocation. Epic 5 adds a blocked
/// User, refused there the same way. Any other failure after the redemption, a Transit or database outage,
/// is not a refusal of the token: it rolls back, and the token stays usable.
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
/// Signs a refresh in (Story 2.10, AD-13), before OpenIddict redeems the presented token. The family must
/// still be valid and within its absolute limit, the family's creation plus
/// <see cref="SecurityLimits.RefreshTokenAbsoluteLifetime"/>: past it the refresh is <c>invalid_grant</c>,
/// whatever the presented token's own expiry says, and nothing is revoked or burnt. A Tenant with no
/// <c>current</c> Signing Key is <c>server_error</c>, as for Client Credentials. The principal is the
/// refresh token's, with <c>sub</c>, <c>sid</c>, <c>auth_time</c> and <c>amr</c> set again from the
/// family's anchored Session, so the new ID token says what that Session says.
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

        var principal = presented.Clone(static _ => true);
        var identity = principal.Identity as ClaimsIdentity
            ?? throw new InvalidOperationException("A refresh token's principal has a claims identity.");
        AuthorizeEndpoint.SetUserClaims(identity, family.UserId, family.SessionId, family.AuthTime, family.Amr);
        context.SignIn(principal);
    }
}

/// <summary>
/// The late refusals of a refresh (Story 2.10), right after OpenIddict's <c>RedeemTokenEntry</c>, which for
/// a refresh token ignores a failed redemption. The presented token must now be <c>redeemed</c> by this
/// request: if it isn't, a concurrent refresh of it won, the token store has recorded the family's
/// <c>token_reuse</c> revocation, and this one is <c>invalid_grant</c>, so exactly one of them succeeds.
/// Its family must still be valid: if it was revoked while the refresh ran, the refresh is
/// <c>invalid_grant</c>, and the presented token's burn is committed after the rollback, so it stays
/// redeemed (see <see cref="RefreshTokens"/>).
/// </summary>
internal sealed class RefuseLateRefreshes(IOpenIddictTokenManager tokens, TokenRequestTransaction transaction, TokenEndpointServices services)
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

        var tokenId = presented.GetTokenId();
        var token = string.IsNullOrEmpty(tokenId) ? null : await tokens.FindByIdAsync(tokenId, context.CancellationToken);
        if (token is null || !await tokens.HasStatusAsync(token, Statuses.Redeemed, context.CancellationToken))
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
        var id = Guid.Parse(tokenId!);
        transaction.KeepOnFailure((log, cancellationToken) => services.Sessions.BurnRefreshTokenAsync(log, id, cancellationToken));
        services.Logger?.LogInformation("A refresh was refused: its Token Family was revoked while it ran.");
        context.Reject(Errors.InvalidGrant, RefreshTokens.NoLongerValidDescription);
    }
}

/// <summary>
/// The absolute limit on a new refresh token (Story 2.10, AD-13): right after OpenIddict sets its expiry
/// to <see cref="SecurityLimits.RefreshTokenInactivityLifetime"/> from now, it is cut to the family's
/// creation plus <see cref="SecurityLimits.RefreshTokenAbsoluteLifetime"/> if that comes first. So no
/// refresh token of a family, however often it rotates, outlives the family's absolute end, and OpenIddict
/// has no family-wide lifetime of its own. On a code exchange or a refresh alike.
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
    }
}
