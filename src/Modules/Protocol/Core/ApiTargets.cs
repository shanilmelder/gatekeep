using System.Collections.Immutable;
using System.Security.Claims;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Contracts;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// The API a request's tokens are for (Story 3.7, FR-16, RFC 8707, AD-33).
/// <list type="bullet">
/// <item>A request names it with <c>resource</c> or <c>audience</c>: exactly one value across both. Two values, or both
/// parameters, is <c>invalid_target</c>.</item>
/// <item>The value must be the identifier of one of the Tenant's APIs, compared exactly, and never the built-in
/// Management API's (<c>urn:gatekeep:management</c>), whose tokens come only from <c>Host.Admin</c> (Epic 17). Anything
/// else is <c>invalid_target</c>.</item>
/// <item>Gatekeep decides all of this, and the parameters are then removed from the request, so none of OpenIddict's own
/// audience, resource or scope checks, which would need scope or audience permissions (AD-8), ever reads them.</item>
/// <item>The API's identifier is the access token's only <c>aud</c>. With no API, an access token has none.</item>
/// </list>
/// </summary>
internal static class ApiTargets
{
    /// <summary>Where the token endpoint leaves the API the request named, resolved, before any token is read.</summary>
    public const string RequestedProperty = ".gatekeep_requested_api";

    /// <summary>
    /// Where a sign-in leaves the API its tokens are for, read as it stands now: the lifetime lookup takes it (FR-15), and
    /// at the authorization endpoint the passthrough sets the audience from it.
    /// </summary>
    public const string ApiProperty = ".gatekeep_token_api";

    /// <summary>Where the token endpoint leaves a Client Credentials request's <c>scope</c> values, once removed from the request.</summary>
    public const string RequestedScopesProperty = ".gatekeep_requested_scopes";

    /// <summary>Where the authorization endpoint leaves what the request named, once removed from it, for its own validation.</summary>
    public const string NamedProperty = ".gatekeep_named_api";

    /// <summary>
    /// The private claim an authorization keeps its API's identifier in, on its code and every refresh token of its family,
    /// and on no access or ID token: OpenIddict doesn't hand a code's or refresh token's audiences back as audiences.
    /// </summary>
    public const string ApiClaim = "gk_api";

    /// <summary>The access token claim listing the Permissions it carries, a JSON array, in the same order as <c>scope</c>.</summary>
    public const string PermissionsClaim = "permissions";

    public const string OneApiDescription = "Name one API, with resource or audience.";

    public const string UnavailableDescription = "The requested API isn't available.";

    public const string MissingDescription = "Name an API with resource or audience.";

    public const string OtherApiDescription = "The requested API isn't the one this grant is for.";

    public const string GoneDescription = "The API this grant is for is no longer available.";

    /// <summary>What a request named: <see cref="Many"/> when it named more than one value, else its one identifier or none.</summary>
    public sealed record Named(bool Many, string? Identifier);

    /// <summary>
    /// Takes the request's <c>resource</c> and <c>audience</c> values out of it: the parameters are removed, whatever they
    /// held, and what they named is returned.
    /// </summary>
    public static Named Take(OpenIddictRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var values = new List<string>();
        if (request.Resources is { IsDefaultOrEmpty: false } resources)
        {
            values.AddRange(resources);
        }

        if (request.Audiences is { IsDefaultOrEmpty: false } audiences)
        {
            values.AddRange(audiences);
        }

        var both = request.GetParameter(Parameters.Resource) is not null && request.GetParameter(Parameters.Audience) is not null;
        request.RemoveParameter(Parameters.Resource);
        request.RemoveParameter(Parameters.Audience);

        return both || values.Count > 1 ? new Named(true, null) : new Named(false, values.Count == 1 ? values[0] : null);
    }

    /// <summary>
    /// The Tenant's API by <paramref name="identifier"/>, exactly, or null when it has none or it is the built-in Management
    /// API, which is never available here (AD-33).
    /// </summary>
    public static async Task<DirectoryApiTarget?> ResolveAsync(
        IDirectory directory, CommandContext database, string identifier, CancellationToken cancellationToken) =>
        await directory.FindApiByIdentifierAsync(database, identifier, cancellationToken) is { BuiltIn: false } api ? api : null;

    /// <summary>The API this request's tokens are for, once a sign-in has decided it; null for none.</summary>
    public static DirectoryApiTarget? Of(OpenIddictServerTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        return transaction.GetProperty<DirectoryApiTarget>(ApiProperty);
    }

    /// <summary>
    /// A code exchange's or refresh's API (Story 3.7): the one its authorization kept as the presented token's audience,
    /// read again by its identifier as it stands now. A request may repeat it or name none; naming another is
    /// <c>invalid_target</c>. An API since removed is <c>invalid_grant</c>. When valid, the API is left for the lifetime
    /// lookup.
    /// </summary>
    public static async Task<(bool Valid, DirectoryApiTarget? Api)> ReadAgainAsync(
        HandleTokenRequestContext context, ClaimsPrincipal presented, CommandContext database, IDirectory directory)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(presented);

        var identifier = presented.GetClaim(ApiClaim);

        if (context.Transaction.GetProperty<DirectoryApiTarget>(RequestedProperty) is { } named
            && !string.Equals(named.Identifier, identifier, StringComparison.Ordinal))
        {
            context.Reject(Errors.InvalidTarget, OtherApiDescription);
            return (false, null);
        }

        if (identifier is null)
        {
            return (true, null);
        }

        if (await ResolveAsync(directory, database, identifier, context.CancellationToken) is not { } api)
        {
            context.Reject(Errors.InvalidGrant, GoneDescription);
            return (false, null);
        }

        context.Transaction.SetProperty(ApiProperty, api);
        return (true, api);
    }

    /// <summary>
    /// The offline access rule (Story 3.7): a principal for an API whose offline access is off loses <c>offline_access</c>,
    /// so no refresh token is issued with its tokens.
    /// </summary>
    public static void KeepOfflineAccessRule(ClaimsPrincipal principal, DirectoryApiTarget? api)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (api is { OfflineAccess: false } && principal.HasScope(Scopes.OfflineAccess))
        {
            principal.SetScopes(principal.GetScopes().Where(scope => scope != Scopes.OfflineAccess));
        }
    }
}

/// <summary>
/// The token endpoint's target rules (Story 3.7, replacing Story 2.5's blanket refusal), right after client authentication
/// and before OpenIddict reads any parameter they cover.
/// <list type="bullet">
/// <item>The API the request names, if any, is resolved (<see cref="ApiTargets"/>); one that isn't available is
/// <c>invalid_target</c>, and the parameters are removed.</item>
/// <item>Client Credentials must name one: with none it is <c>invalid_target</c>. Its <c>scope</c> may name any values:
/// they narrow the granted Permissions, and one not granted is dropped silently, never an error (FR-16). They are kept
/// for <see cref="SignInClient"/> and removed from the request.</item>
/// <item>A code exchange may name only <c>openid</c>, the one scope a code is ever granted (Story 2.9), which is then
/// dropped, since it adds nothing to the code; any other is <c>invalid_scope</c>.</item>
/// <item>A refresh's scope is checked against what its family was granted, once its token is read, by
/// <see cref="RefuseUngrantedRefreshScopes"/> (Story 2.10).</item>
/// </list>
/// </summary>
internal sealed class ResolveTokenTarget(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseScopedHandler<ResolveTokenTarget>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateGrantType.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var named = ApiTargets.Take(context.Request);
        if (named.Many)
        {
            context.Reject(Errors.InvalidTarget, ApiTargets.OneApiDescription);
            return;
        }

        if (named.Identifier is { } identifier)
        {
            if (await ApiTargets.ResolveAsync(services.Directory, transaction.Context, identifier, context.CancellationToken) is not { } api)
            {
                context.Reject(Errors.InvalidTarget, ApiTargets.UnavailableDescription);
                return;
            }

            context.Transaction.SetProperty(ApiTargets.RequestedProperty, api);
        }

        if (context.Request.IsClientCredentialsGrantType())
        {
            if (named.Identifier is null)
            {
                context.Reject(Errors.InvalidTarget, ApiTargets.MissingDescription);
                return;
            }

            context.Transaction.SetProperty(ApiTargets.RequestedScopesProperty, context.Request.GetScopes().ToArray());
            context.Request.Scope = null;
        }
        else if (context.Request.IsAuthorizationCodeGrantType())
        {
            if (context.Request.GetScopes().Any(s => s != Scopes.OpenId))
            {
                context.Reject(Errors.InvalidScope, "No scope may be requested here but openid, on a code exchange.");
                return;
            }

            // openid alone names nothing the code doesn't already carry; OpenIddict refuses any scope on a code
            // exchange, so it is dropped before OpenIddict reads the request.
            context.Request.Scope = null;
        }
    }
}

/// <summary>
/// A code exchange's API (Story 3.7): the one the authorization kept as the code's audience, read again as it stands
/// now (<see cref="ApiTargets.ReadAgainAsync"/>). When its offline access is off, the exchange issues no refresh token,
/// whatever the authorization granted. Users hold no Permissions until Epic 5, so no other scope is added.
/// </summary>
internal sealed class SignInCode(TokenRequestTransaction transaction, TokenEndpointServices services)
    : IOpenIddictServerHandler<HandleTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<HandleTokenRequestContext>()
            .UseScopedHandler<SignInCode>()
            .SetOrder(OpenIddictServerHandlers.Exchange.AttachPrincipal.Descriptor.Order + 1_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(HandleTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.IsAuthorizationCodeGrantType())
        {
            return;
        }

        var presented = context.Principal ?? throw new InvalidOperationException("A code exchange has the code's principal.");
        var target = await ApiTargets.ReadAgainAsync(context, presented, transaction.Context, services.Directory);
        if (!target.Valid || target.Api is not { OfflineAccess: false } || !presented.HasScope(Scopes.OfflineAccess))
        {
            return;
        }

        var principal = presented.Clone(static _ => true);
        ApiTargets.KeepOfflineAccessRule(principal, target.Api);
        context.SignIn(principal);
    }
}

/// <summary>
/// The authorization endpoint's target (Story 3.7), taken out of the request before any of OpenIddict's own checks reads
/// it, and kept for <see cref="ValidateGatekeepAuthorizationRequest"/>, which decides it once the redirect target is
/// trusted, so its <c>invalid_target</c> goes back to the client.
/// </summary>
internal sealed class TakeAuthorizationTarget : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseSingletonHandler<TakeAuthorizationTarget>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Transaction.SetProperty(ApiTargets.NamedProperty, ApiTargets.Take(context.Request));
        return ValueTask.CompletedTask;
    }
}
