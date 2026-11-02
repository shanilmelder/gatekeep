using System.Collections.Immutable;
using System.Data.Common;
using System.Runtime.CompilerServices;
using System.Text.Json;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;

/// <summary>A <c>spike_authorization</c> row: an ad-hoc one is a Token Family (AD-8). Sessions owns the real table.</summary>
public sealed class SpikeAuthorization
{
    public Guid Id { get; set; }

    public Guid? ApplicationId { get; set; }

    public string? Subject { get; set; }

    public string? Status { get; set; }

    public string? Type { get; set; }

    public ImmutableArray<string> Scopes { get; set; } = [];

    public DateTimeOffset? CreationDate { get; set; }

    public ImmutableDictionary<string, JsonElement> Properties { get; set; } = ImmutableDictionary<string, JsonElement>.Empty;

    public Guid ConcurrencyToken { get; set; }
}

/// <summary>Authorizations on the request's transaction, with an optimistic concurrency token.</summary>
public sealed class SpikeAuthorizationStore(SpikeRequestTransaction transaction) : IOpenIddictAuthorizationStore<SpikeAuthorization>
{
    private const string Columns =
        "id, application_id, subject, status, type, scopes, creation_date, properties::text AS properties, concurrency_token";

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken) =>
        (await SpikeSql.QueryAsync(transaction.Context, "SELECT count(*) FROM spike_authorization", r => r.GetInt64(0), cancellationToken))[0];

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<SpikeAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public async ValueTask CreateAsync(SpikeAuthorization authorization, CancellationToken cancellationToken)
    {
        authorization.ConcurrencyToken = Guid.NewGuid();

        await SpikeSql.ExecuteAsync(
            transaction.Context,
            """
            INSERT INTO spike_authorization
              (tenant_id, id, application_id, subject, status, type, scopes, creation_date, properties, concurrency_token)
            VALUES (current_setting('gatekeep.tenant_id')::uuid, @id, @application_id, @subject, @status, @type, @scopes,
                    @creation_date, @properties, @concurrency_token)
            """,
            cancellationToken,
            ("id", authorization.Id),
            ("application_id", authorization.ApplicationId),
            ("subject", authorization.Subject),
            ("status", authorization.Status),
            ("type", authorization.Type),
            ("scopes", authorization.Scopes.ToArray()),
            ("creation_date", authorization.CreationDate),
            ("properties", SpikeSql.Json(authorization.Properties)),
            ("concurrency_token", authorization.ConcurrencyToken));
    }

    public ValueTask DeleteAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Pruning is a job, not OpenIddict's (AD-8).");

    public async IAsyncEnumerable<SpikeAuthorization> FindAsync(
        string? subject, string? client, string? status, string? type, ImmutableArray<string>? scopes,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var rows = await QueryAsync(
            """
            WHERE (@subject::text IS NULL OR subject = @subject)
              AND (@client::uuid IS NULL OR application_id = @client)
              AND (@status::text IS NULL OR status = @status)
              AND (@type::text IS NULL OR type = @type)
              AND (@scopes::text[] IS NULL OR scopes @> @scopes::text[])
            """,
            cancellationToken,
            ("subject", subject),
            ("client", SpikeSql.ParseId(client)),
            ("status", status),
            ("type", type),
            ("scopes", scopes?.ToArray()));

        foreach (var authorization in rows)
        {
            yield return authorization;
        }
    }

    public async IAsyncEnumerable<SpikeAuthorization> FindByApplicationIdAsync(
        string identifier, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var authorization in await QueryAsync("WHERE application_id = @id", cancellationToken, ("id", SpikeSql.ParseId(identifier))))
        {
            yield return authorization;
        }
    }

    public async ValueTask<SpikeAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken) =>
        SpikeSql.ParseId(identifier) is { } id
            ? (await QueryAsync("WHERE id = @id", cancellationToken, ("id", id))).SingleOrDefault()
            : null;

    public async IAsyncEnumerable<SpikeAuthorization> FindBySubjectAsync(
        string subject, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var authorization in await QueryAsync("WHERE subject = @subject", cancellationToken, ("subject", subject)))
        {
            yield return authorization;
        }
    }

    public ValueTask<string?> GetApplicationIdAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.ApplicationId?.ToString());

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<SpikeAuthorization>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<DateTimeOffset?> GetCreationDateAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.CreationDate);

    public ValueTask<string?> GetIdAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.Id.ToString());

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.Properties);

    public ValueTask<ImmutableArray<string>> GetScopesAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.Scopes);

    public ValueTask<string?> GetStatusAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.Status);

    public ValueTask<string?> GetSubjectAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.Subject);

    public ValueTask<string?> GetTypeAsync(SpikeAuthorization authorization, CancellationToken cancellationToken) =>
        new(authorization.Type);

    public ValueTask<SpikeAuthorization> InstantiateAsync(CancellationToken cancellationToken) =>
        new(new SpikeAuthorization { Id = Guid.CreateVersion7() });

    public async IAsyncEnumerable<SpikeAuthorization> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var rows = await QueryAsync(
            "ORDER BY id LIMIT @count OFFSET @offset", cancellationToken, ("count", count ?? long.MaxValue), ("offset", (long)(offset ?? 0)));
        foreach (var authorization in rows)
        {
            yield return authorization;
        }
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<SpikeAuthorization>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Pruning is a job, not OpenIddict's (AD-8).");

    public async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken) =>
        await SpikeSql.ExecuteAsync(
            transaction.Context,
            """
            UPDATE spike_authorization SET status = @revoked, concurrency_token = gen_random_uuid()
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

    public ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken) =>
        RevokeAsync(null, identifier, null, null, cancellationToken);

    public ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken) =>
        RevokeAsync(subject, null, null, null, cancellationToken);

    public ValueTask SetApplicationIdAsync(SpikeAuthorization authorization, string? identifier, CancellationToken cancellationToken) =>
        Set(() => authorization.ApplicationId = SpikeSql.ParseId(identifier));

    public ValueTask SetCreationDateAsync(SpikeAuthorization authorization, DateTimeOffset? date, CancellationToken cancellationToken) =>
        Set(() => authorization.CreationDate = date);

    public ValueTask SetPropertiesAsync(SpikeAuthorization authorization, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        Set(() => authorization.Properties = properties);

    public ValueTask SetScopesAsync(SpikeAuthorization authorization, ImmutableArray<string> scopes, CancellationToken cancellationToken) =>
        Set(() => authorization.Scopes = scopes);

    public ValueTask SetStatusAsync(SpikeAuthorization authorization, string? status, CancellationToken cancellationToken) =>
        Set(() => authorization.Status = status);

    public ValueTask SetSubjectAsync(SpikeAuthorization authorization, string? subject, CancellationToken cancellationToken) =>
        Set(() => authorization.Subject = subject);

    public ValueTask SetTypeAsync(SpikeAuthorization authorization, string? type, CancellationToken cancellationToken) =>
        Set(() => authorization.Type = type);

    public async ValueTask UpdateAsync(SpikeAuthorization authorization, CancellationToken cancellationToken)
    {
        var next = Guid.NewGuid();
        var updated = await SpikeSql.ExecuteAsync(
            transaction.Context,
            """
            UPDATE spike_authorization
            SET application_id = @application_id, subject = @subject, status = @status, type = @type, scopes = @scopes,
                creation_date = @creation_date, properties = @properties, concurrency_token = @next
            WHERE id = @id AND concurrency_token = @concurrency_token
            """,
            cancellationToken,
            ("id", authorization.Id),
            ("application_id", authorization.ApplicationId),
            ("subject", authorization.Subject),
            ("status", authorization.Status),
            ("type", authorization.Type),
            ("scopes", authorization.Scopes.ToArray()),
            ("creation_date", authorization.CreationDate),
            ("properties", SpikeSql.Json(authorization.Properties)),
            ("next", next),
            ("concurrency_token", authorization.ConcurrencyToken));

        if (updated == 0)
        {
            throw new OpenIddictExceptions.ConcurrencyException("The authorization changed or was removed since it was read.");
        }

        authorization.ConcurrencyToken = next;
    }

    private static ValueTask Set(Action set)
    {
        set();
        return ValueTask.CompletedTask;
    }

    private Task<List<SpikeAuthorization>> QueryAsync(string where, CancellationToken cancellationToken, params (string, object?)[] parameters) =>
        SpikeSql.QueryAsync(transaction.Context, $"SELECT {Columns} FROM spike_authorization {where}", Map, cancellationToken, parameters);

    private static SpikeAuthorization Map(DbDataReader reader) => new()
    {
        Id = reader.GetGuid(reader.GetOrdinal("id")),
        ApplicationId = SpikeSql.Uuid(reader, "application_id"),
        Subject = SpikeSql.Text(reader, "subject"),
        Status = SpikeSql.Text(reader, "status"),
        Type = SpikeSql.Text(reader, "type"),
        Scopes = SpikeSql.Array(reader, "scopes"),
        CreationDate = SpikeSql.Date(reader, "creation_date"),
        Properties = SpikeSql.Properties(reader, "properties"),
        ConcurrencyToken = reader.GetGuid(reader.GetOrdinal("concurrency_token")),
    };

    private static NotSupportedException Unsupported() =>
        new("The spike stores don't take LINQ queries.");
}
