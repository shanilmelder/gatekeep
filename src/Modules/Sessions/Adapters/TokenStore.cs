using System.Collections.Immutable;
using System.Data.Common;
using System.Text.Json;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Contracts;
using OpenIddict.Abstractions;

namespace Gatekeep.Modules.Sessions.Adapters;

/// <summary>
/// OpenIddict's token store (AD-8, AD-13), minimal for Client Credentials (Story 2.5): OpenIddict
/// makes an entity, fills it and creates its row, in the request's own Tenant context. Every other
/// call, a lookup, an update, a revocation, a prune or a query, throws: Client Credentials makes none,
/// and Story 2.9 builds them, revocation through <c>ISessions.RevokeAccessAsync</c> only.
/// </summary>
internal sealed class TokenStore(Func<CommandContext> context) : IOpenIddictTokenStore<SessionsToken>
{
    private const string Insert =
        """
        INSERT INTO token (tenant_id, id, application_id, authorization_id, subject, type, status, reference_id, payload,
                           creation_date, expiration_date, redemption_date, properties, concurrency_token)
        VALUES (@tenant_id, @id, @application_id, @authorization_id, @subject, @type, @status, @reference_id, @payload,
                @creation_date, @expiration_date, @redemption_date, @properties::jsonb, @concurrency_token)
        """;

    public ValueTask<SessionsToken> InstantiateAsync(CancellationToken cancellationToken) =>
        new(new SessionsToken(Guid.CreateVersion7()));

    public async ValueTask CreateAsync(SessionsToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        var command = context();
        var tenantId = command.TenantId
            ?? throw new InvalidOperationException("Tokens are written only in a Tenant context.");

        await using var insert = command.CreateCommand();
        insert.CommandText = Insert;
        Add(insert, "tenant_id", tenantId);
        Add(insert, "id", token.Id);
        Add(insert, "application_id", token.ApplicationId);
        Add(insert, "authorization_id", token.AuthorizationId);
        Add(insert, "subject", token.Subject);
        Add(insert, "type", token.Type);
        Add(insert, "status", token.Status);
        Add(insert, "reference_id", token.ReferenceId);
        Add(insert, "payload", token.Payload);
        Add(insert, "creation_date", token.CreationDate);
        Add(insert, "expiration_date", token.ExpirationDate);
        Add(insert, "redemption_date", token.RedemptionDate);
        Add(insert, "properties", JsonSerializer.Serialize(token.Properties));
        Add(insert, "concurrency_token", Guid.NewGuid());
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    public ValueTask<string?> GetIdAsync(SessionsToken token, CancellationToken cancellationToken) => new(Checked(token).Id.ToString());

    public ValueTask<string?> GetApplicationIdAsync(SessionsToken token, CancellationToken cancellationToken) =>
        new(Checked(token).ApplicationId?.ToString());

    public ValueTask<string?> GetAuthorizationIdAsync(SessionsToken token, CancellationToken cancellationToken) =>
        new(Checked(token).AuthorizationId?.ToString());

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(SessionsToken token, CancellationToken cancellationToken) =>
        new(Checked(token).CreationDate);

    public ValueTask<DateTimeOffset?> GetExpirationDateAsync(SessionsToken token, CancellationToken cancellationToken) =>
        new(Checked(token).ExpirationDate);

    public ValueTask<string?> GetPayloadAsync(SessionsToken token, CancellationToken cancellationToken) => new(Checked(token).Payload);

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(SessionsToken token, CancellationToken cancellationToken) =>
        new(Checked(token).Properties);

    public ValueTask<DateTimeOffset?> GetRedemptionDateAsync(SessionsToken token, CancellationToken cancellationToken) =>
        new(Checked(token).RedemptionDate);

    public ValueTask<string?> GetReferenceIdAsync(SessionsToken token, CancellationToken cancellationToken) => new(Checked(token).ReferenceId);

    public ValueTask<string?> GetStatusAsync(SessionsToken token, CancellationToken cancellationToken) => new(Checked(token).Status);

    public ValueTask<string?> GetSubjectAsync(SessionsToken token, CancellationToken cancellationToken) => new(Checked(token).Subject);

    public ValueTask<string?> GetTypeAsync(SessionsToken token, CancellationToken cancellationToken) => new(Checked(token).Type);

    public ValueTask SetApplicationIdAsync(SessionsToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => Checked(token).ApplicationId = Id(identifier));

    public ValueTask SetAuthorizationIdAsync(SessionsToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => Checked(token).AuthorizationId = Id(identifier));

    public ValueTask SetCreationDateAsync(SessionsToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(token).CreationDate = date);

    public ValueTask SetExpirationDateAsync(SessionsToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(token).ExpirationDate = date);

    public ValueTask SetPayloadAsync(SessionsToken token, string? payload, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Payload = payload);

    public ValueTask SetPropertiesAsync(SessionsToken token, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Properties = properties ?? ImmutableDictionary<string, JsonElement>.Empty);

    public ValueTask SetRedemptionDateAsync(SessionsToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(token).RedemptionDate = date);

    public ValueTask SetReferenceIdAsync(SessionsToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => Checked(token).ReferenceId = identifier);

    public ValueTask SetStatusAsync(SessionsToken token, string? status, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Status = status);

    public ValueTask SetSubjectAsync(SessionsToken token, string? subject, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Subject = subject);

    public ValueTask SetTypeAsync(SessionsToken token, string? type, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Type = type);

    public ValueTask<long> CountAsync(CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<SessionsToken>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask DeleteAsync(SessionsToken token, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsToken> FindAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<SessionsToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<SessionsToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<SessionsToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<SessionsToken>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<SessionsToken> ListAsync(int? count, int? offset, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<SessionsToken>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default) => throw Unsupported();

    public ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default) => throw Unsupported();

    public ValueTask UpdateAsync(SessionsToken token, CancellationToken cancellationToken) => throw Unsupported();

    private static SessionsToken Checked(SessionsToken token) => token ?? throw new ArgumentNullException(nameof(token));

    private static Guid? Id(string? identifier) =>
        string.IsNullOrEmpty(identifier) ? null
        : Guid.TryParse(identifier, out var id) && id != Guid.Empty ? id
        : throw new ArgumentException("An OpenIddict entity ID here is a UUID.", nameof(identifier));

    private static ValueTask Set(Action set)
    {
        set();
        return ValueTask.CompletedTask;
    }

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    private static NotSupportedException Unsupported() =>
        new("Client Credentials only creates tokens; Story 2.9 adds the rest of the token store.");
}

/// <summary>
/// OpenIddict's authorization store, registered so its manager can be built (AD-8), and nothing more:
/// Client Credentials creates no authorization, so every call throws until Story 2.9 builds it.
/// </summary>
internal sealed class AuthorizationStore : IOpenIddictAuthorizationStore<SessionsAuthorization>
{
    public ValueTask<long> CountAsync(CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<SessionsAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask CreateAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask DeleteAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> FindAsync(
        string? subject, string? client, string? status, string? type, ImmutableArray<string>? scopes, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<SessionsAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> FindBySubjectAsync(string subject, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<string?> GetApplicationIdAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<SessionsAuthorization>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<string?> GetIdAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<ImmutableArray<string>> GetScopesAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<string?> GetStatusAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<string?> GetSubjectAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<string?> GetTypeAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<SessionsAuthorization> InstantiateAsync(CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> ListAsync(int? count, int? offset, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<SessionsAuthorization>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask SetApplicationIdAsync(SessionsAuthorization authorization, string? identifier, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask SetCreationDateAsync(SessionsAuthorization authorization, DateTimeOffset? date, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask SetPropertiesAsync(
        SessionsAuthorization authorization, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask SetScopesAsync(SessionsAuthorization authorization, ImmutableArray<string> scopes, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask SetStatusAsync(SessionsAuthorization authorization, string? status, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask SetSubjectAsync(SessionsAuthorization authorization, string? subject, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask SetTypeAsync(SessionsAuthorization authorization, string? type, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask UpdateAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    private static NotSupportedException Unsupported() =>
        new("Client Credentials creates no authorization; Story 2.9 builds the authorization store.");
}
