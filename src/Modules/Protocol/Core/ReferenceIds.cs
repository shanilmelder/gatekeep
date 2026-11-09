using System.Security.Cryptography;
using Gatekeep.Kernel.Identifiers;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;

namespace Gatekeep.Modules.Protocol.Core;

/// <summary>
/// In place of OpenIddict's <c>AttachTokenPayload</c> (Story 2.9, AD-9, the Story 2.2 spike): the same
/// steps, but a reference token, a code, is <c>{tenantPublicId}.{base64url of 32 random bytes}</c>. The
/// payload is the token OpenIddict made, encrypted with the Tenant's token protection key. The token
/// manager hashes the whole value before the store sees it, so only that hash is stored. Nothing here
/// logs the value.
/// </summary>
internal sealed class AttachTenantReferenceId(IOpenIddictTokenManager tokens) : IOpenIddictServerHandler<GenerateTokenContext>
{
    /// <summary>The random part of a reference ID: 32 bytes, 256 bits.</summary>
    public const int RandomBytes = 32;

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
            .AddFilter<RequireDegradedModeDisabled>()
            .AddFilter<RequireTokenStorageEnabled>()
            .AddFilter<RequireTokenPayloadPersisted>()
            .UseScopedHandler<AttachTenantReferenceId>()
            .SetOrder(OpenIddictServerHandlers.Protection.AttachTokenPayload.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(GenerateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var identifier = context.Principal.GetTokenId();
        if (string.IsNullOrEmpty(identifier))
        {
            throw new InvalidOperationException("The token has no entry.");
        }

        var token = await tokens.FindByIdAsync(identifier, context.CancellationToken)
            ?? throw new InvalidOperationException("The token entry is missing.");

        var descriptor = new OpenIddictTokenDescriptor();
        await tokens.PopulateAsync(descriptor, token, context.CancellationToken);
        descriptor.Payload = context.Token;
        descriptor.Principal = context.Principal;

        if (context.IsReferenceToken)
        {
            var tenant = TokenEndpoint.Tenant(context);
            var random = RandomNumberGenerator.GetBytes(RandomBytes);
            try
            {
                descriptor.ReferenceId = PublicId.Format(PublicIdType.Tenant, tenant.TenantId) + "." + Base64UrlEncoder.Encode(random);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(random);
            }
        }

        await tokens.UpdateAsync(token, descriptor, context.CancellationToken);

        if (context.IsReferenceToken)
        {
            context.Token = descriptor.ReferenceId;
        }
    }
}

/// <summary>
/// A presented code (or, from Story 2.10, refresh token) whose prefix isn't the serving Tenant's public
/// ID is refused here with <c>invalid_token</c>, which the token endpoint answers as <c>invalid_grant</c>,
/// before OpenIddict's <c>ValidateReferenceTokenIdentifier</c> looks anything up (AD-9): no other Tenant's
/// artifact, and no value with no prefix, ever reaches this Tenant's store.
/// </summary>
internal sealed class RejectForeignReferenceIds : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseSingletonHandler<RejectForeignReferenceIds>()
            .SetOrder(OpenIddictServerHandlers.Protection.RemoveDisallowedCharacters.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateTokenContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var referenceTypes = context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.AuthorizationCode)
            || context.ValidTokenTypes.Contains(TokenTypeIdentifiers.RefreshToken);
        if (!referenceTypes)
        {
            return ValueTask.CompletedTask;
        }

        var prefix = PublicId.Format(PublicIdType.Tenant, TokenEndpoint.Tenant(context).TenantId) + ".";
        if (string.IsNullOrEmpty(context.Token) || !context.Token.StartsWith(prefix, StringComparison.Ordinal))
        {
            context.Reject(Errors.InvalidToken, "The token isn't valid.");
        }

        return ValueTask.CompletedTask;
    }
}
