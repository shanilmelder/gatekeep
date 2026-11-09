using System.Collections.Immutable;
using System.Data.Common;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Contracts;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Gatekeep.Modules.Sessions.Adapters;

/// <summary>
/// OpenIddict's token store (AD-8, AD-13), on the request's own Tenant context: exactly what Client
/// Credentials (Story 2.5), the authorization code grant (Story 2.9) and the refresh grant (Story 2.10)
/// call. It makes, finds and updates <c>token</c> rows; an update changes only a row's status (never to
/// revoked), payload, reference ID and redemption date, and refuses any other change. OpenIddict's family
/// revocation, on a replayed code or a reused refresh token, and a lost race to redeem either, go to
/// <see cref="ISessions.RevokeAccessAsync"/>, the one revocation path, and are
/// recorded on the request first, so it is committed even though the request is refused. Every other
/// call, a query, a listing, a prune, a delete or another revocation, throws. A failed statement marks
/// the request failed, since OpenIddict swallows some store failures.
/// </summary>
internal sealed class TokenStore(StoreRequest request, ISessions sessions) : IOpenIddictTokenStore<SessionsToken>
{
    private const string Insert =
        """
        INSERT INTO token (tenant_id, id, application_id, authorization_id, subject, type, status, reference_id, payload,
                           creation_date, expiration_date, redemption_date, properties, concurrency_token)
        VALUES (@tenant_id, @id, @application_id, @authorization_id, @subject, @type, @status, @reference_id, @payload,
                @creation_date, @expiration_date, @redemption_date, @properties::jsonb, @concurrency_token)
        """;

    private const string Columns =
        "id, application_id, authorization_id, subject, type, status, reference_id, payload, creation_date, "
        + "expiration_date, redemption_date, properties::text AS properties, concurrency_token";

    // Only the columns gk_hosted may update (Story 2.9), under the row's concurrency token.
    private const string Update =
        """
        UPDATE token
        SET status = @status, payload = @payload, reference_id = @reference_id, redemption_date = @redemption_date,
            concurrency_token = @next
        WHERE tenant_id = @tenant_id AND id = @id AND concurrency_token = @concurrency_token
        """;

    /// <summary>The statuses the store itself writes. A family's tokens become revoked only by the one revocation path.</summary>
    private static readonly IReadOnlySet<string> WritableStatuses = new HashSet<string>(StringComparer.Ordinal)
    {
        Statuses.Valid,
        Statuses.Redeemed,
    };

    /// <summary>The type of the last token presented by its reference ID in this request: a code or a refresh token.</summary>
    private string? _presentedType;

    public ValueTask<SessionsToken> InstantiateAsync(CancellationToken cancellationToken) =>
        new(new SessionsToken(Guid.CreateVersion7()));

    public async ValueTask CreateAsync(SessionsToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        RequireWritable(token.Status);

        var context = request.Context();
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Tokens are written only in a Tenant context.");

        var concurrency = Guid.NewGuid();
        await using (var insert = context.CreateCommand())
        {
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
            Add(insert, "concurrency_token", concurrency);
            await StoreSql.RunAsync(request, () => insert.ExecuteNonQueryAsync(cancellationToken));
        }

        token.ConcurrencyToken = concurrency;
        token.Stored = Stored(token);
    }

    public async ValueTask<SessionsToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken) =>
        Guid.TryParse(identifier, out var id) && id != Guid.Empty
            ? await FindAsync("id = @key", id, cancellationToken)
            : null;

    /// <summary>
    /// By OpenIddict's hash of a presented code or refresh token: the manager hashes the value before
    /// it reaches the store, so this is never the value itself.
    /// </summary>
    public async ValueTask<SessionsToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            return null;
        }

        var token = await FindAsync("reference_id = @key", identifier, cancellationToken);
        _presentedType = token?.Type;
        return token;
    }

    public async ValueTask UpdateAsync(SessionsToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        RequireWritable(token.Status);

        if (token.Stored is null || !string.Equals(token.Stored, Stored(token), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "A token row changes only in its status, payload, reference ID and redemption date.");
        }

        var context = request.Context();
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Tokens are written only in a Tenant context.");

        var next = Guid.NewGuid();
        int updated;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Update;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", token.Id);
            Add(command, "status", token.Status);
            Add(command, "payload", token.Payload);
            Add(command, "reference_id", token.ReferenceId);
            Add(command, "redemption_date", token.RedemptionDate);
            Add(command, "next", next);
            Add(command, "concurrency_token", token.ConcurrencyToken);
            updated = await StoreSql.RunAsync(request, () => command.ExecuteNonQueryAsync(cancellationToken));
        }

        if (updated == 0)
        {
            // Two exchanges of one code, or two refreshes of one refresh token (Story 2.10), raced, and
            // this one lost its redemption: the code was replayed, or the refresh token reused, so its
            // family is revoked as on any replay or reuse, then the redemption fails as OpenIddict expects.
            if (token.Status == Statuses.Redeemed && token.AuthorizationId is { } family)
            {
                if (token.Type == TokenTypeIdentifiers.Private.AuthorizationCode)
                {
                    await RevokeFamilyAsync(family, RevocationReason.CodeReplay, cancellationToken);
                }
                else if (token.Type == TokenTypeIdentifiers.RefreshToken)
                {
                    await RevokeFamilyAsync(family, RevocationReason.TokenReuse, cancellationToken);
                }
            }

            throw new OpenIddictExceptions.ConcurrencyException("The token changed or was revoked since it was read.");
        }

        token.ConcurrencyToken = next;
    }

    /// <summary>
    /// OpenIddict's revocation of a Token Family, on a replayed code (or, from Story 2.10, a reused
    /// refresh token): the family, its authorization and every token of it, through the one revocation
    /// path with an anonymous Actor. The call is recorded on the request before it runs, so the request
    /// commits it again after its rollback (AD-13).
    /// </summary>
    public async ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(identifier, out var authorizationId) || authorizationId == Guid.Empty)
        {
            throw new ArgumentException("An authorization ID here is a UUID.", nameof(identifier));
        }

        var reason = _presentedType == TokenTypeIdentifiers.RefreshToken ? RevocationReason.TokenReuse : RevocationReason.CodeReplay;
        return await RevokeFamilyAsync(authorizationId, reason, cancellationToken);
    }

    /// <summary>
    /// Revokes a Token Family through the one revocation path with an anonymous Actor, recorded on the
    /// request first, so the request commits it again after its rollback (AD-13).
    /// </summary>
    private async Task<long> RevokeFamilyAsync(Guid authorizationId, RevocationReason reason, CancellationToken cancellationToken)
    {
        var scope = new RevocationScope.Authorization(authorizationId);

        request.KeepOnFailure((context, token) => sessions.RevokeAccessAsync(context, scope, null, reason, Actor.Anonymous, token));

        var outcome = await StoreSql.RunAsync(
            request,
            () => sessions.RevokeAccessAsync(request.Context(), scope, null, reason, Actor.Anonymous, cancellationToken));
        return outcome.TokensRevoked;
    }

    /// <summary>Refused: no Session-free scope fits a subject, and the one revocation path ends access.</summary>
    public ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("A subject's tokens are revoked only through ISessions.RevokeAccessAsync.");

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
        Set(() => Checked(token).ApplicationId = StoreSql.Id(identifier));

    public ValueTask SetAuthorizationIdAsync(SessionsToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => Checked(token).AuthorizationId = StoreSql.Id(identifier));

    public ValueTask SetCreationDateAsync(SessionsToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(token).CreationDate = StoreSql.Stored(date));

    public ValueTask SetExpirationDateAsync(SessionsToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(token).ExpirationDate = StoreSql.Stored(date));

    public ValueTask SetPayloadAsync(SessionsToken token, string? payload, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Payload = payload);

    public ValueTask SetPropertiesAsync(SessionsToken token, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        Set(() => Checked(token).Properties = properties ?? ImmutableDictionary<string, JsonElement>.Empty);

    public ValueTask SetRedemptionDateAsync(SessionsToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(token).RedemptionDate = StoreSql.Stored(date));

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

    private async Task<SessionsToken?> FindAsync(string condition, object key, CancellationToken cancellationToken)
    {
        var context = request.Context();
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Tokens are read only in a Tenant context.");

        await using var command = context.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM token WHERE tenant_id = @tenant_id AND {condition}";
        Add(command, "tenant_id", tenantId);
        Add(command, "key", key);

        return await StoreSql.RunAsync(request, async () =>
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
        });
    }

    private static SessionsToken Read(DbDataReader reader)
    {
        var token = new SessionsToken(reader.GetGuid(0))
        {
            ApplicationId = StoreSql.Uuid(reader, 1),
            AuthorizationId = StoreSql.Uuid(reader, 2),
            Subject = StoreSql.Text(reader, 3),
            Type = StoreSql.Text(reader, 4),
            Status = StoreSql.Text(reader, 5),
            ReferenceId = StoreSql.Text(reader, 6),
            Payload = StoreSql.Text(reader, 7),
            CreationDate = StoreSql.Date(reader, 8),
            ExpirationDate = StoreSql.Date(reader, 9),
            RedemptionDate = StoreSql.Date(reader, 10),
            Properties = StoreSql.Properties(reader, 11),
            ConcurrencyToken = reader.GetGuid(12),
        };

        token.Stored = Stored(token);
        return token;
    }

    /// <summary>The columns an update never changes, as one comparable text.</summary>
    private static string Stored(SessionsToken token) =>
        string.Join(
            '\u001f',
            token.ApplicationId?.ToString() ?? "-",
            token.AuthorizationId?.ToString() ?? "-",
            token.Subject ?? "-",
            token.Type ?? "-",
            token.CreationDate?.UtcTicks.ToString(CultureInfo.InvariantCulture) ?? "-",
            token.ExpirationDate?.UtcTicks.ToString(CultureInfo.InvariantCulture) ?? "-",
            StoreSql.Json(token.Properties));

    private static void RequireWritable(string? status)
    {
        if (status is null || !WritableStatuses.Contains(status))
        {
            throw new InvalidOperationException(
                "The token store writes only a valid or redeemed status: a revocation goes through ISessions.RevokeAccessAsync.");
        }
    }

    private static SessionsToken Checked(SessionsToken token) => token ?? throw new ArgumentNullException(nameof(token));

    private static ValueTask Set(Action set)
    {
        set();
        return ValueTask.CompletedTask;
    }

    private static void Add(DbCommand command, string name, object? value) => StoreSql.Add(command, name, value);

    private static NotSupportedException Unsupported() =>
        new("The token store serves Client Credentials, the code grant and the refresh grant only (Stories 2.5, 2.9 and 2.10).");
}

/// <summary>
/// OpenIddict's authorization store (AD-8, AD-13, Story 2.9): exactly what the code grant calls. It makes
/// one ad-hoc authorization per completed code flow, a Token Family anchored to the <c>user_session</c>
/// named by <see cref="SessionsContract.SessionAnchorProperty"/>, and finds one by its ID. Only the one
/// revocation path changes an authorization, so an update, a revocation of any kind, a query, a
/// listing, a prune and a delete all throw. A failed statement marks the request failed.
/// </summary>
internal sealed class AuthorizationStore(StoreRequest request) : IOpenIddictAuthorizationStore<SessionsAuthorization>
{
    private const string Insert =
        """
        INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, subject, status, type, scopes,
                                     creation_date, properties, concurrency_token)
        VALUES (@tenant_id, @id, @application_id, @user_session_id, @subject, @status, @type, @scopes,
                @creation_date, @properties::jsonb, @concurrency_token)
        """;

    private const string Select =
        """
        SELECT id, application_id, user_session_id, subject, status, type, scopes, creation_date,
               properties::text AS properties, concurrency_token
        FROM "authorization"
        WHERE tenant_id = @tenant_id AND id = @id
        """;

    public ValueTask<SessionsAuthorization> InstantiateAsync(CancellationToken cancellationToken) =>
        new(new SessionsAuthorization(Guid.CreateVersion7()));

    public async ValueTask CreateAsync(SessionsAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        if (authorization.Status != Statuses.Valid)
        {
            throw new InvalidOperationException("An authorization is created valid; only ISessions.RevokeAccessAsync revokes one.");
        }

        if (!authorization.Properties.TryGetValue(SessionsContract.SessionAnchorProperty, out var anchor)
            || anchor.ValueKind != JsonValueKind.String
            || !Guid.TryParse(anchor.GetString(), out var sessionId)
            || sessionId == Guid.Empty)
        {
            throw new InvalidOperationException("An authorization is created only anchored to the Session its sign-in started.");
        }

        // The anchor is a column, not a property.
        authorization.UserSessionId = sessionId;
        authorization.Properties = authorization.Properties.Remove(SessionsContract.SessionAnchorProperty);

        var context = request.Context();
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Authorizations are written only in a Tenant context.");

        var concurrency = Guid.NewGuid();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Insert;
            StoreSql.Add(command, "tenant_id", tenantId);
            StoreSql.Add(command, "id", authorization.Id);
            StoreSql.Add(command, "application_id", authorization.ApplicationId);
            StoreSql.Add(command, "user_session_id", sessionId);
            StoreSql.Add(command, "subject", authorization.Subject);
            StoreSql.Add(command, "status", authorization.Status);
            StoreSql.Add(command, "type", authorization.Type);
            StoreSql.Add(command, "scopes", authorization.Scopes.IsDefault ? Array.Empty<string>() : authorization.Scopes.ToArray());
            StoreSql.Add(command, "creation_date", authorization.CreationDate);
            StoreSql.Add(command, "properties", StoreSql.Json(authorization.Properties));
            StoreSql.Add(command, "concurrency_token", concurrency);
            await StoreSql.RunAsync(request, () => command.ExecuteNonQueryAsync(cancellationToken));
        }

        authorization.ConcurrencyToken = concurrency;
    }

    public async ValueTask<SessionsAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(identifier, out var id) || id == Guid.Empty)
        {
            return null;
        }

        var context = request.Context();
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Authorizations are read only in a Tenant context.");

        await using var command = context.CreateCommand();
        command.CommandText = Select;
        StoreSql.Add(command, "tenant_id", tenantId);
        StoreSql.Add(command, "id", id);

        return await StoreSql.RunAsync(request, async () =>
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
        });
    }

    public ValueTask<string?> GetApplicationIdAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).ApplicationId?.ToString());

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).CreationDate);

    public ValueTask<string?> GetIdAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).Id.ToString());

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).Properties);

    public ValueTask<ImmutableArray<string>> GetScopesAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).Scopes.IsDefault ? ImmutableArray<string>.Empty : authorization.Scopes);

    public ValueTask<string?> GetStatusAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).Status);

    public ValueTask<string?> GetSubjectAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).Subject);

    public ValueTask<string?> GetTypeAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        new(Checked(authorization).Type);

    public ValueTask SetApplicationIdAsync(SessionsAuthorization authorization, string? identifier, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).ApplicationId = StoreSql.Id(identifier));

    public ValueTask SetCreationDateAsync(SessionsAuthorization authorization, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).CreationDate = StoreSql.Stored(date));

    public ValueTask SetPropertiesAsync(
        SessionsAuthorization authorization, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).Properties = properties ?? ImmutableDictionary<string, JsonElement>.Empty);

    public ValueTask SetScopesAsync(SessionsAuthorization authorization, ImmutableArray<string> scopes, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).Scopes = scopes.IsDefault ? ImmutableArray<string>.Empty : scopes);

    public ValueTask SetStatusAsync(SessionsAuthorization authorization, string? status, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).Status = status);

    public ValueTask SetSubjectAsync(SessionsAuthorization authorization, string? subject, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).Subject = subject);

    public ValueTask SetTypeAsync(SessionsAuthorization authorization, string? type, CancellationToken cancellationToken) =>
        Set(() => Checked(authorization).Type = type);

    /// <summary>Refused: only the one revocation path changes an authorization (AD-13).</summary>
    public ValueTask UpdateAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) =>
        throw new NotSupportedException("An authorization changes only through ISessions.RevokeAccessAsync.");

    /// <summary>Refused: no Session-free scope fits a subject, and the one revocation path ends access.</summary>
    public ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken) =>
        throw new NotSupportedException("A subject's authorizations are revoked only through ISessions.RevokeAccessAsync.");

    public ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> CountAsync(CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<SessionsAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask DeleteAsync(SessionsAuthorization authorization, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> FindAsync(
        string? subject, string? client, string? status, string? type, ImmutableArray<string>? scopes, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> FindBySubjectAsync(string subject, CancellationToken cancellationToken) => throw Unsupported();

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<SessionsAuthorization>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public IAsyncEnumerable<SessionsAuthorization> ListAsync(int? count, int? offset, CancellationToken cancellationToken) => throw Unsupported();

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<SessionsAuthorization>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken) => throw Unsupported();

    private static SessionsAuthorization Read(DbDataReader reader) => new(reader.GetGuid(0))
    {
        ApplicationId = StoreSql.Uuid(reader, 1),
        UserSessionId = StoreSql.Uuid(reader, 2),
        Subject = StoreSql.Text(reader, 3),
        Status = StoreSql.Text(reader, 4),
        Type = StoreSql.Text(reader, 5),
        Scopes = [.. reader.GetFieldValue<string[]>(6)],
        CreationDate = StoreSql.Date(reader, 7),
        Properties = StoreSql.Properties(reader, 8),
        ConcurrencyToken = reader.GetGuid(9),
    };

    private static SessionsAuthorization Checked(SessionsAuthorization authorization) =>
        authorization ?? throw new ArgumentNullException(nameof(authorization));

    private static ValueTask Set(Action set)
    {
        set();
        return ValueTask.CompletedTask;
    }

    private static NotSupportedException Unsupported() =>
        new("The authorization store serves the code and refresh grants only (Stories 2.9 and 2.10).");
}

/// <summary>What both stores share: parameters, readers, and marking the request failed on a failed statement.</summary>
internal static class StoreSql
{
    /// <summary>Runs one statement; a database failure or a cancellation marks the request failed before it propagates.</summary>
    public static async Task<T> RunAsync<T>(StoreRequest request, Func<Task<T>> statement)
    {
        try
        {
            return await statement();
        }
        catch (Exception e) when (e is DbException or OperationCanceledException)
        {
            // Either one leaves PostgreSQL's transaction aborted: a cancelled statement as much as a failed one.
            request.MarkFailed();
            throw;
        }
    }

    public static Guid? Id(string? identifier) =>
        string.IsNullOrEmpty(identifier) ? null
        : Guid.TryParse(identifier, out var id) && id != Guid.Empty ? id
        : throw new ArgumentException("An OpenIddict entity ID here is a UUID.", nameof(identifier));

    /// <summary>timestamptz holds microseconds, so a date is kept as the row will hold it.</summary>
    public static DateTimeOffset? Stored(DateTimeOffset? value) =>
        value is { } v ? new DateTimeOffset(v.UtcTicks - (v.UtcTicks % TimeSpan.TicksPerMicrosecond), TimeSpan.Zero) : null;

    public static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }

    public static Guid? Uuid(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetGuid(ordinal);

    public static string? Text(DbDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    public static DateTimeOffset? Date(DbDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetFieldValue<DateTimeOffset>(ordinal);

    public static ImmutableDictionary<string, JsonElement> Properties(DbDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return ImmutableDictionary<string, JsonElement>.Empty;
        }

        var parsed = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(reader.GetString(ordinal));
        return parsed is null ? ImmutableDictionary<string, JsonElement>.Empty : parsed.ToImmutableDictionary(StringComparer.Ordinal);
    }

    /// <summary>The properties as JSON, keys in ordinal order, so equal sets compare equal.</summary>
    public static string Json(ImmutableDictionary<string, JsonElement> properties) =>
        JsonSerializer.Serialize(new SortedDictionary<string, JsonElement>(
            properties ?? ImmutableDictionary<string, JsonElement>.Empty, StringComparer.Ordinal));
}
