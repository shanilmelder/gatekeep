using System.Collections.Immutable;
using System.Data.Common;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Gatekeep.Kernel.Persistence;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;

/// <summary>A <c>spike_token</c> row. The reference ID is the manager's hash of the value, never the value.</summary>
public sealed class SpikeToken
{
    public Guid Id { get; set; }

    public Guid? ApplicationId { get; set; }

    public Guid? AuthorizationId { get; set; }

    public string? Subject { get; set; }

    public string? Type { get; set; }

    public string? Status { get; set; }

    public string? ReferenceId { get; set; }

    public string? Payload { get; set; }

    public DateTimeOffset? CreationDate { get; set; }

    public DateTimeOffset? ExpirationDate { get; set; }

    public DateTimeOffset? RedemptionDate { get; set; }

    public ImmutableDictionary<string, JsonElement> Properties { get; set; } = ImmutableDictionary<string, JsonElement>.Empty;

    public Guid ConcurrencyToken { get; set; }
}

/// <summary>
/// Tokens on the request's transaction. A Token Family revocation is recorded on the request
/// before it runs, so the request can commit it again after a rollback (AD-13).
/// </summary>
public sealed class SpikeTokenStore(SpikeRequestTransaction transaction, SpikeStoreProbe probe) : IOpenIddictTokenStore<SpikeToken>
{
    private const string Columns =
        "id, application_id, authorization_id, subject, type, status, reference_id, payload, creation_date, "
        + "expiration_date, redemption_date, properties::text AS properties, concurrency_token";

    /// <summary>The revoke both the request and its failure effect run: every token in the family.</summary>
    public static async Task<int> RevokeFamilyAsync(CommandContext context, Guid authorizationId, CancellationToken cancellationToken) =>
        await SpikeSql.ExecuteAsync(
            context,
            """
            UPDATE spike_token SET status = @revoked, concurrency_token = gen_random_uuid()
            WHERE authorization_id = @authorization_id AND status <> @revoked
            """,
            cancellationToken,
            ("revoked", Statuses.Revoked),
            ("authorization_id", authorizationId));

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken) =>
        (await SpikeSql.QueryAsync(transaction.Context, "SELECT count(*) FROM spike_token", r => r.GetInt64(0), cancellationToken))[0];

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<SpikeToken>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public async ValueTask CreateAsync(SpikeToken token, CancellationToken cancellationToken)
    {
        probe.RecordWrite();
        token.ConcurrencyToken = Guid.NewGuid();

        await SpikeSql.ExecuteAsync(
            transaction.Context,
            """
            INSERT INTO spike_token
              (tenant_id, id, application_id, authorization_id, subject, type, status, reference_id, payload,
               creation_date, expiration_date, redemption_date, properties, concurrency_token)
            VALUES (current_setting('gatekeep.tenant_id')::uuid, @id, @application_id, @authorization_id, @subject, @type,
                    @status, @reference_id, @payload, @creation_date, @expiration_date, @redemption_date, @properties,
                    @concurrency_token)
            """,
            cancellationToken,
            Parameters(token, ("concurrency_token", token.ConcurrencyToken)));
    }

    public ValueTask DeleteAsync(SpikeToken token, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Pruning is a job, not OpenIddict's (AD-8).");

    public async IAsyncEnumerable<SpikeToken> FindAsync(
        string? subject, string? client, string? status, string? type, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var rows = await QueryAsync(
            """
            WHERE (@subject::text IS NULL OR subject = @subject)
              AND (@client::uuid IS NULL OR application_id = @client)
              AND (@status::text IS NULL OR status = @status)
              AND (@type::text IS NULL OR type = @type)
            """,
            cancellationToken,
            ("subject", subject),
            ("client", SpikeSql.ParseId(client)),
            ("status", status),
            ("type", type));

        foreach (var token in rows)
        {
            yield return token;
        }
    }

    public async IAsyncEnumerable<SpikeToken> FindByApplicationIdAsync(
        string identifier, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var token in await QueryAsync("WHERE application_id = @id", cancellationToken, ("id", SpikeSql.ParseId(identifier))))
        {
            yield return token;
        }
    }

    public async IAsyncEnumerable<SpikeToken> FindByAuthorizationIdAsync(
        string identifier, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var token in await QueryAsync("WHERE authorization_id = @id", cancellationToken, ("id", SpikeSql.ParseId(identifier))))
        {
            yield return token;
        }
    }

    public async ValueTask<SpikeToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken) =>
        SpikeSql.ParseId(identifier) is { } id
            ? (await QueryAsync("WHERE id = @id", cancellationToken, ("id", id))).SingleOrDefault()
            : null;

    public async ValueTask<SpikeToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
    {
        // The manager hashes the value first, so this is never the token itself.
        probe.ReferenceLookups.Enqueue((transaction.Tenant?.Id ?? Guid.Empty, identifier));
        return (await QueryAsync("WHERE reference_id = @reference_id", cancellationToken, ("reference_id", identifier))).SingleOrDefault();
    }

    public async IAsyncEnumerable<SpikeToken> FindBySubjectAsync(
        string subject, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var token in await QueryAsync("WHERE subject = @subject", cancellationToken, ("subject", subject)))
        {
            yield return token;
        }
    }

    public ValueTask<string?> GetApplicationIdAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.ApplicationId?.ToString());

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<SpikeToken>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<string?> GetAuthorizationIdAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.AuthorizationId?.ToString());

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.CreationDate);

    public ValueTask<DateTimeOffset?> GetExpirationDateAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.ExpirationDate);

    public ValueTask<string?> GetIdAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.Id.ToString());

    public ValueTask<string?> GetPayloadAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.Payload);

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.Properties);

    public ValueTask<DateTimeOffset?> GetRedemptionDateAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.RedemptionDate);

    public ValueTask<string?> GetReferenceIdAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.ReferenceId);

    public ValueTask<string?> GetStatusAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.Status);

    public ValueTask<string?> GetSubjectAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.Subject);

    public ValueTask<string?> GetTypeAsync(SpikeToken token, CancellationToken cancellationToken) =>
        new(token.Type);

    public ValueTask<SpikeToken> InstantiateAsync(CancellationToken cancellationToken) =>
        new(new SpikeToken { Id = Guid.CreateVersion7() });

    public async IAsyncEnumerable<SpikeToken> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var rows = await QueryAsync(
            "ORDER BY id LIMIT @count OFFSET @offset", cancellationToken, ("count", count ?? long.MaxValue), ("offset", (long)(offset ?? 0)));
        foreach (var token in rows)
        {
            yield return token;
        }
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<SpikeToken>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Pruning is a job, not OpenIddict's (AD-8).");

    public async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken) =>
        await SpikeSql.ExecuteAsync(
            transaction.Context,
            """
            UPDATE spike_token SET status = @revoked, concurrency_token = gen_random_uuid()
            WHERE (@subject::text IS NULL OR subject = @subject)
              AND (@client::uuid IS NULL OR application_id = @client)
              AND (@status::text IS NULL OR status = @status)
              AND (@type::text IS NULL OR type = @type)
            """,
            cancellationToken,
            ("revoked", Statuses.Revoked),
            ("subject", subject),
            ("client", SpikeSql.ParseId(client)),
            ("status", status),
            ("type", type));

    public ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken = default) =>
        RevokeAsync(null, identifier, null, null, cancellationToken);

    public async ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        var id = SpikeSql.ParseId(identifier) ?? throw new ArgumentException("Not an authorization ID.", nameof(identifier));

        // Recorded first: if the update fails, or the request rolls back, the family is still known.
        transaction.RecordFamilyRevoked(identifier);
        return await RevokeFamilyAsync(transaction.Context, id, cancellationToken);
    }

    public ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken = default) =>
        RevokeAsync(subject, null, null, null, cancellationToken);

    public ValueTask SetApplicationIdAsync(SpikeToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => token.ApplicationId = SpikeSql.ParseId(identifier));

    public ValueTask SetAuthorizationIdAsync(SpikeToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => token.AuthorizationId = SpikeSql.ParseId(identifier));

    public ValueTask SetCreationDateAsync(SpikeToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => token.CreationDate = date);

    public ValueTask SetExpirationDateAsync(SpikeToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => token.ExpirationDate = date);

    public ValueTask SetPayloadAsync(SpikeToken token, string? payload, CancellationToken cancellationToken) =>
        Set(() => token.Payload = payload);

    public ValueTask SetPropertiesAsync(SpikeToken token, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        Set(() => token.Properties = properties);

    public ValueTask SetRedemptionDateAsync(SpikeToken token, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => token.RedemptionDate = date);

    public ValueTask SetReferenceIdAsync(SpikeToken token, string? identifier, CancellationToken cancellationToken) =>
        Set(() => token.ReferenceId = identifier);

    public ValueTask SetStatusAsync(SpikeToken token, string? status, CancellationToken cancellationToken) =>
        Set(() => token.Status = status);

    public ValueTask SetSubjectAsync(SpikeToken token, string? subject, CancellationToken cancellationToken) =>
        Set(() => token.Subject = subject);

    public ValueTask SetTypeAsync(SpikeToken token, string? type, CancellationToken cancellationToken) =>
        Set(() => token.Type = type);

    public async ValueTask UpdateAsync(SpikeToken token, CancellationToken cancellationToken)
    {
        probe.RecordWrite();
        var next = Guid.NewGuid();
        var updated = await SpikeSql.ExecuteAsync(
            transaction.Context,
            """
            UPDATE spike_token
            SET application_id = @application_id, authorization_id = @authorization_id, subject = @subject, type = @type,
                status = @status, reference_id = @reference_id, payload = @payload, creation_date = @creation_date,
                expiration_date = @expiration_date, redemption_date = @redemption_date, properties = @properties,
                concurrency_token = @next
            WHERE id = @id AND concurrency_token = @concurrency_token
            """,
            cancellationToken,
            Parameters(token, ("next", next), ("concurrency_token", token.ConcurrencyToken)));

        if (updated == 0)
        {
            throw new OpenIddictExceptions.ConcurrencyException("The token changed or was removed since it was read.");
        }

        token.ConcurrencyToken = next;
    }

    private static (string, object?)[] Parameters(SpikeToken token, params (string, object?)[] extra) =>
    [
        ("id", token.Id),
        ("application_id", token.ApplicationId),
        ("authorization_id", token.AuthorizationId),
        ("subject", token.Subject),
        ("type", token.Type),
        ("status", token.Status),
        ("reference_id", token.ReferenceId),
        ("payload", token.Payload),
        ("creation_date", token.CreationDate),
        ("expiration_date", token.ExpirationDate),
        ("redemption_date", token.RedemptionDate),
        ("properties", SpikeSql.Json(token.Properties)),
        .. extra,
    ];

    private static ValueTask Set(Action set)
    {
        set();
        return ValueTask.CompletedTask;
    }

    private Task<List<SpikeToken>> QueryAsync(string where, CancellationToken cancellationToken, params (string, object?)[] parameters) =>
        SpikeSql.QueryAsync(transaction.Context, $"SELECT {Columns} FROM spike_token {where}", Map, cancellationToken, parameters);

    private static SpikeToken Map(DbDataReader reader) => new()
    {
        Id = reader.GetGuid(reader.GetOrdinal("id")),
        ApplicationId = SpikeSql.Uuid(reader, "application_id"),
        AuthorizationId = SpikeSql.Uuid(reader, "authorization_id"),
        Subject = SpikeSql.Text(reader, "subject"),
        Type = SpikeSql.Text(reader, "type"),
        Status = SpikeSql.Text(reader, "status"),
        ReferenceId = SpikeSql.Text(reader, "reference_id"),
        Payload = SpikeSql.Text(reader, "payload"),
        CreationDate = SpikeSql.Date(reader, "creation_date"),
        ExpirationDate = SpikeSql.Date(reader, "expiration_date"),
        RedemptionDate = SpikeSql.Date(reader, "redemption_date"),
        Properties = SpikeSql.Properties(reader, "properties"),
        ConcurrencyToken = reader.GetGuid(reader.GetOrdinal("concurrency_token")),
    };

    private static NotSupportedException Unsupported() =>
        new("The spike stores don't take LINQ queries.");
}
