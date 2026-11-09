using System.Collections.Immutable;
using System.Text.Json;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>
/// One <c>token</c> row as OpenIddict's token store hands it over (AD-8, AD-13). Only Sessions reads
/// or writes its values: OpenIddict reaches them through the store alone. An access or ID token's row
/// holds no token value (its payload stays empty), and any reference ID only as OpenIddict's hash.
/// </summary>
public sealed class SessionsToken
{
    internal SessionsToken(Guid id) => Id = id;

    internal Guid Id { get; }

    internal Guid? ApplicationId { get; set; }

    internal Guid? AuthorizationId { get; set; }

    internal string? Subject { get; set; }

    internal string? Type { get; set; }

    internal string? Status { get; set; }

    internal string? ReferenceId { get; set; }

    internal string? Payload { get; set; }

    internal DateTimeOffset? CreationDate { get; set; }

    internal DateTimeOffset? ExpirationDate { get; set; }

    internal DateTimeOffset? RedemptionDate { get; set; }

    internal ImmutableDictionary<string, JsonElement> Properties { get; set; } = ImmutableDictionary<string, JsonElement>.Empty;

    /// <summary>The row's optimistic concurrency token as last read or written (Story 2.9).</summary>
    internal Guid ConcurrencyToken { get; set; }

    /// <summary>
    /// What the row held, as stored, in the columns an update never changes (Story 2.9). Null until
    /// the row exists.
    /// </summary>
    internal string? Stored { get; set; }
}

/// <summary>
/// An <c>authorization</c> row, a Token Family (AD-13), as OpenIddict's authorization store hands it
/// over (Story 2.9). Each completed code flow makes one ad-hoc authorization, anchored to the
/// <c>user_session</c> its sign-in started.
/// </summary>
public sealed class SessionsAuthorization
{
    internal SessionsAuthorization(Guid id) => Id = id;

    internal Guid Id { get; }

    internal Guid? ApplicationId { get; set; }

    /// <summary>The Session the family is anchored to. Set from the create's anchor property.</summary>
    internal Guid? UserSessionId { get; set; }

    internal string? Subject { get; set; }

    internal string? Status { get; set; }

    internal string? Type { get; set; }

    internal ImmutableArray<string> Scopes { get; set; } = [];

    internal DateTimeOffset? CreationDate { get; set; }

    internal ImmutableDictionary<string, JsonElement> Properties { get; set; } = ImmutableDictionary<string, JsonElement>.Empty;

    internal Guid ConcurrencyToken { get; set; }
}

/// <summary>
/// The request an OpenIddict store runs in (Story 2.9, AD-5, AD-13): its Tenant context, a way to
/// keep an effect the request must keep even when it is refused (a revocation on code replay),
/// and a way to mark the request failed when a statement fails, since OpenIddict swallows some
/// store failures and PostgreSQL then leaves the transaction aborted.
/// </summary>
/// <param name="Context">The request's own Tenant context. Throws when no transaction is open.</param>
/// <param name="KeepOnFailure">Records an effect the request keeps, durably, even if it is refused.</param>
/// <param name="MarkFailed">Marks the request's transaction failed, so it never reports success.</param>
/// <param name="MarkRedeemed">
/// Records that this request's own redemption of a token (its ID) succeeded (Story 2.10). OpenIddict ignores
/// a failed refresh redemption, so the request needs to know whether it won it.
/// </param>
public sealed record StoreRequest(
    Func<Gatekeep.Kernel.Persistence.CommandContext> Context,
    Action<Func<Gatekeep.Kernel.Persistence.CommandContext, CancellationToken, Task>> KeepOnFailure,
    Action MarkFailed,
    Action<Guid>? MarkRedeemed = null);
