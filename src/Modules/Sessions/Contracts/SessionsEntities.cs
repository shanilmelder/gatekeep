using System.Collections.Immutable;
using System.Text.Json;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>
/// One <c>token</c> row as OpenIddict's token store hands it over (AD-8, AD-13). Only Sessions reads
/// or writes its values: OpenIddict reaches them through the store alone. An access token's row
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
}

/// <summary>
/// An <c>authorization</c> row, a Token Family (AD-13), as OpenIddict would see it. Client Credentials
/// creates none, so until Story 2.9 its store refuses every call and no instance is ever made.
/// </summary>
public sealed class SessionsAuthorization
{
    private SessionsAuthorization()
    {
    }
}
