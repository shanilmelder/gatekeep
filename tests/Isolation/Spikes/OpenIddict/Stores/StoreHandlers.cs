using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;

/// <summary>The Gatekeep handlers that stores mode adds, and the built-in ones it replaces.</summary>
public static class StoreHandlers
{
    /// <summary>The only scopes the spike knows. There's no scope store (AD-8).</summary>
    public static readonly IReadOnlySet<string> KnownScopes = new HashSet<string>(StringComparer.Ordinal)
    {
        Scopes.OpenId,
        Scopes.OfflineAccess,
    };

    public static void Configure(OpenIddictServerBuilder options)
    {
        options.AllowRefreshTokenFlow();

        // Codes are always reference tokens with storage on; refresh tokens are made so.
        options.UseReferenceRefreshTokens();

        // Rolling refresh tokens stay on (the default). Reuse has no leeway at all (AD-8).
        options.SetRefreshTokenReuseLeeway(null);

        // The scope store is unused, so OpenIddict's scope check (which needs it) is off.
        options.DisableScopeValidation();
        options.RegisterScopes([.. KnownScopes]);
        options.AddEventHandler(ValidateGatekeepScopes.AuthorizationDescriptor);
        options.AddEventHandler(ValidateGatekeepScopes.TokenDescriptor);

        // Client authentication is Gatekeep's; OpenIddict's secret column stays null.
        options.RemoveEventHandler(OpenIddictServerHandlers.ValidateClientSecret.Descriptor);
        options.AddEventHandler(ValidateGatekeepClientSecret.Descriptor);

        // {tenantPublicId}.{random} reference IDs, and the prefix check before any lookup.
        options.RemoveEventHandler(OpenIddictServerHandlers.Protection.AttachTokenPayload.Descriptor);
        options.AddEventHandler(AttachTenantReferenceId.Descriptor);
        options.AddEventHandler(RejectForeignReferenceIds.Descriptor);

        // Endpoint end: commit, roll back, or roll back and commit the revocation.
        options.AddEventHandler(EndRequestTransaction<ApplyAuthorizationResponseContext>.Descriptor);
        options.AddEventHandler(EndRequestTransaction<ApplyTokenResponseContext>.Descriptor);

        options.AddEventHandler(RejectSignInAfterWrites.Descriptor);
    }
}

/// <summary>Refuses any scope the spike doesn't know, on both endpoints, without a scope store.</summary>
public sealed class ValidateGatekeepScopes :
    IOpenIddictServerHandler<ValidateAuthorizationRequestContext>,
    IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    public static OpenIddictServerHandlerDescriptor AuthorizationDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
            .UseSingletonHandler<ValidateGatekeepScopes>()
            .SetOrder(OpenIddictServerHandlers.Authentication.ValidateScopes.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public static OpenIddictServerHandlerDescriptor TokenDescriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenRequestContext>()
            .UseSingletonHandler<ValidateGatekeepScopes>()
            .SetOrder(OpenIddictServerHandlers.Exchange.ValidateScopes.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.GetScopes().All(StoreHandlers.KnownScopes.Contains))
        {
            context.Reject(Errors.InvalidScope);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask HandleAsync(ValidateTokenRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.GetScopes().All(StoreHandlers.KnownScopes.Contains))
        {
            context.Reject(Errors.InvalidScope);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Replaces <c>ValidateClientSecret</c>, which fails on an empty stored secret. It checks the
/// spike's secret where Gatekeep will call Directory's contract against <c>client_secret</c>.
/// </summary>
public sealed class ValidateGatekeepClientSecret(IOpenIddictApplicationManager applications)
    : IOpenIddictServerHandler<ProcessAuthenticationContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
            .AddFilter<RequireClientIdParameter>()
            .AddFilter<RequireClientSecretParameter>()
            .UseScopedHandler<ValidateGatekeepClientSecret>()
            .SetOrder(OpenIddictServerHandlers.ValidateClientSecret.Descriptor.Order)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(ProcessAuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.EndpointType is not OpenIddictServerEndpointType.Token)
        {
            return;
        }

        var application = await applications.FindByClientIdAsync(context.ClientId!, context.CancellationToken)
            ?? throw new InvalidOperationException("ValidateClientId runs first and refuses an unknown client.");

        // A public client sending a secret was already refused by ValidateClientType.
        if (await applications.HasClientTypeAsync(application, ClientTypes.Public, context.CancellationToken))
        {
            return;
        }

        if (context.ClientId != SpikeClients.Confidential || !Matches(context.ClientSecret!, SpikeClients.ConfidentialSecret))
        {
            context.Reject(Errors.InvalidClient);
        }
    }

    private static bool Matches(string presented, string expected) =>
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(presented)),
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
}

/// <summary>
/// Replaces <c>AttachTokenPayload</c>: the same steps, but a reference ID is
/// <c>{tenantPublicId}.{random}</c> with 256 random bits. The manager still hashes the whole
/// value before the store sees it.
/// </summary>
public sealed class AttachTenantReferenceId(IOpenIddictTokenManager tokens, SpikeRequestTransaction transaction)
    : IOpenIddictServerHandler<GenerateTokenContext>
{
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
            var tenant = transaction.Tenant ?? throw new InvalidOperationException("No Tenant on the request.");
            descriptor.ReferenceId = tenant.PublicId + "." + Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(RandomBytes));
        }

        await tokens.UpdateAsync(token, descriptor, context.CancellationToken);

        if (context.IsReferenceToken)
        {
            context.Token = descriptor.ReferenceId;
        }
    }
}

/// <summary>
/// A code or refresh token whose prefix isn't this Tenant's public ID is refused here, before
/// <c>ValidateReferenceTokenIdentifier</c> looks anything up.
/// </summary>
public sealed class RejectForeignReferenceIds(SpikeRequestTransaction transaction) : IOpenIddictServerHandler<ValidateTokenContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
            .UseScopedHandler<RejectForeignReferenceIds>()
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

        var tenant = transaction.Tenant ?? throw new InvalidOperationException("No Tenant on the request.");
        if (!context.Token.StartsWith(tenant.PublicId + ".", StringComparison.Ordinal))
        {
            context.Reject(Errors.InvalidToken);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// Endpoint end for the endpoints that write. A success commits the request's transaction. A
/// rejection rolls it back; if a store revoked a Token Family on the way, the revocation and one
/// audit event are committed again through <see cref="FailureContext"/> (AD-5, AD-13).
/// </summary>
public sealed class EndRequestTransaction<TContext>(SpikeRequestTransaction transaction, SpikeStoreProbe probe)
    : IOpenIddictServerHandler<TContext>
    where TContext : BaseRequestContext
{
    private static readonly IAuditAppender Appender = AuditContract.CreateAppender();

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
            .UseScopedHandler<EndRequestTransaction<TContext>>()
            .SetOrder(int.MinValue)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public async ValueTask HandleAsync(TContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!transaction.IsOpen)
        {
            return;
        }

        if (string.IsNullOrEmpty(context.Transaction.Response?.Error))
        {
            await transaction.CommitAsync(context.CancellationToken);
            probe.Outcomes.Enqueue(SpikeRequestOutcome.Committed);
            return;
        }

        var families = transaction.RevokedFamilies.Select(Guid.Parse).ToList();
        if (families.Count == 0)
        {
            await transaction.RollBackAsync();
            probe.Outcomes.Enqueue(SpikeRequestOutcome.RolledBack);
            return;
        }

        if (!probe.CommitRevocationAfterRollback)
        {
            await transaction.RollBackAsync();
            probe.Outcomes.Enqueue(SpikeRequestOutcome.RolledBackLosingRevocation);
            return;
        }

        await transaction.CommitAfterRollbackAsync(async (command, cancellationToken) =>
        {
            foreach (var family in families)
            {
                await SpikeTokenStore.RevokeFamilyAsync(command, family, cancellationToken);

                var application = (await SpikeSql.QueryAsync(
                    command,
                    "SELECT application_id FROM spike_authorization WHERE id = @id",
                    reader => SpikeSql.Uuid(reader, "application_id"),
                    cancellationToken,
                    ("id", family))).SingleOrDefault();

                var auditEvent = application is { } id
                    ? new AuditEvent(new AuditTypeCode(SpikeDatabase.AuditTypeCode), Actor.Anonymous, AuditTargetKind.Client, id)
                    : new AuditEvent(new AuditTypeCode(SpikeDatabase.AuditTypeCode), Actor.Anonymous);
                await Appender.AppendAsync(command, auditEvent, null, cancellationToken);
            }
        });

        probe.Outcomes.Enqueue(SpikeRequestOutcome.RevocationCommittedAfterRollback);
    }
}

/// <summary>
/// A test switch: rejects a token request's sign-in after OpenIddict has redeemed the presented
/// token and written the new ones, so a test can show the rollback takes them all back.
/// </summary>
public sealed class RejectSignInAfterWrites(SpikeStoreProbe probe) : IOpenIddictServerHandler<ProcessSignInContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
            .UseSingletonHandler<RejectSignInAfterWrites>()
            // After every token is generated and stored, before the response (500_000).
            .SetOrder(400_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    public ValueTask HandleAsync(ProcessSignInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (probe.RejectSignInAfterWrites && context.EndpointType is OpenIddictServerEndpointType.Token)
        {
            context.Reject(Errors.InvalidGrant);
        }

        return ValueTask.CompletedTask;
    }
}
