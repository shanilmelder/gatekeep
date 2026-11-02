using System.Collections.Immutable;
using System.Data.Common;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;

/// <summary>A <c>spike_application</c> row. Directory owns the real table (AD-8).</summary>
public sealed class SpikeApplication
{
    public Guid Id { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string? ClientType { get; set; }

    public string? ApplicationType { get; set; }

    public string? ConsentType { get; set; }

    public string? DisplayName { get; set; }

    public ImmutableArray<string> Permissions { get; set; } = [];

    public ImmutableArray<string> RedirectUris { get; set; } = [];

    public ImmutableArray<string> PostLogoutRedirectUris { get; set; } = [];

    public ImmutableArray<string> Requirements { get; set; } = [];

    public ImmutableDictionary<string, string> Settings { get; set; } = ImmutableDictionary<string, string>.Empty;

    public ImmutableDictionary<string, JsonElement> Properties { get; set; } = ImmutableDictionary<string, JsonElement>.Empty;
}

/// <summary>
/// Reads Applications on the request's transaction. The spike seeds them by SQL, so every write
/// is refused: Application writes are Directory's, not OpenIddict's.
/// </summary>
public sealed class SpikeApplicationStore(SpikeRequestTransaction transaction) : IOpenIddictApplicationStore<SpikeApplication>
{
    private const string Columns =
        "id, client_id, client_secret, client_type, application_type, consent_type, display_name, permissions, "
        + "redirect_uris, post_logout_redirect_uris, requirements, settings::text AS settings, properties::text AS properties";

    public async ValueTask<long> CountAsync(CancellationToken cancellationToken) =>
        (await SpikeSql.QueryAsync(transaction.Context, "SELECT count(*) FROM spike_application", r => r.GetInt64(0), cancellationToken))[0];

    public ValueTask<long> CountAsync<TResult>(Func<IQueryable<SpikeApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask CreateAsync(SpikeApplication application, CancellationToken cancellationToken) => throw ReadOnly();

    public ValueTask DeleteAsync(SpikeApplication application, CancellationToken cancellationToken) => throw ReadOnly();

    public async ValueTask<SpikeApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken) =>
        SpikeSql.ParseId(identifier) is { } id
            ? (await QueryAsync("WHERE id = @id", cancellationToken, ("id", id))).SingleOrDefault()
            : null;

    public async ValueTask<SpikeApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken) =>
        (await QueryAsync("WHERE client_id = @client_id", cancellationToken, ("client_id", identifier))).SingleOrDefault();

    public async IAsyncEnumerable<SpikeApplication> FindByPostLogoutRedirectUriAsync(
        string uri, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var application in await QueryAsync("WHERE @uri = ANY (post_logout_redirect_uris)", cancellationToken, ("uri", uri)))
        {
            yield return application;
        }
    }

    public async IAsyncEnumerable<SpikeApplication> FindByRedirectUriAsync(
        string uri, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var application in await QueryAsync("WHERE @uri = ANY (redirect_uris)", cancellationToken, ("uri", uri)))
        {
            yield return application;
        }
    }

    public ValueTask<string?> GetApplicationTypeAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.ApplicationType);

    public ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<SpikeApplication>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask<string?> GetClientIdAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.ClientId);

    public ValueTask<string?> GetClientSecretAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.ClientSecret);

    public ValueTask<string?> GetClientTypeAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.ClientType);

    public ValueTask<string?> GetConsentTypeAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.ConsentType);

    public ValueTask<string?> GetDisplayNameAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.DisplayName);

    public ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(ImmutableDictionary<CultureInfo, string>.Empty);

    public ValueTask<string?> GetIdAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.Id.ToString());

    public ValueTask<JsonWebKeySet?> GetJsonWebKeySetAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new((JsonWebKeySet?)null);

    public ValueTask<ImmutableArray<string>> GetPermissionsAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.Permissions);

    public ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.PostLogoutRedirectUris);

    public ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.Properties);

    public ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.RedirectUris);

    public ValueTask<ImmutableArray<string>> GetRequirementsAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.Requirements);

    public ValueTask<ImmutableDictionary<string, string>> GetSettingsAsync(SpikeApplication application, CancellationToken cancellationToken) =>
        new(application.Settings);

    public ValueTask<SpikeApplication> InstantiateAsync(CancellationToken cancellationToken) =>
        new(new SpikeApplication { Id = Guid.CreateVersion7() });

    public async IAsyncEnumerable<SpikeApplication> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var rows = await QueryAsync(
            "ORDER BY id LIMIT @count OFFSET @offset", cancellationToken, ("count", count ?? long.MaxValue), ("offset", (long)(offset ?? 0)));
        foreach (var application in rows)
        {
            yield return application;
        }
    }

    public IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<SpikeApplication>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) =>
        throw Unsupported();

    public ValueTask SetApplicationTypeAsync(SpikeApplication application, string? type, CancellationToken cancellationToken) =>
        Set(() => application.ApplicationType = type);

    public ValueTask SetClientIdAsync(SpikeApplication application, string? identifier, CancellationToken cancellationToken) =>
        Set(() => application.ClientId = identifier);

    public ValueTask SetClientSecretAsync(SpikeApplication application, string? secret, CancellationToken cancellationToken) =>
        Set(() => application.ClientSecret = secret);

    public ValueTask SetClientTypeAsync(SpikeApplication application, string? type, CancellationToken cancellationToken) =>
        Set(() => application.ClientType = type);

    public ValueTask SetConsentTypeAsync(SpikeApplication application, string? type, CancellationToken cancellationToken) =>
        Set(() => application.ConsentType = type);

    public ValueTask SetDisplayNameAsync(SpikeApplication application, string? name, CancellationToken cancellationToken) =>
        Set(() => application.DisplayName = name);

    public ValueTask SetDisplayNamesAsync(SpikeApplication application, ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;

    public ValueTask SetJsonWebKeySetAsync(SpikeApplication application, JsonWebKeySet? set, CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;

    public ValueTask SetPermissionsAsync(SpikeApplication application, ImmutableArray<string> permissions, CancellationToken cancellationToken) =>
        Set(() => application.Permissions = permissions);

    public ValueTask SetPostLogoutRedirectUrisAsync(SpikeApplication application, ImmutableArray<string> uris, CancellationToken cancellationToken) =>
        Set(() => application.PostLogoutRedirectUris = uris);

    public ValueTask SetPropertiesAsync(SpikeApplication application, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken) =>
        Set(() => application.Properties = properties);

    public ValueTask SetRedirectUrisAsync(SpikeApplication application, ImmutableArray<string> uris, CancellationToken cancellationToken) =>
        Set(() => application.RedirectUris = uris);

    public ValueTask SetRequirementsAsync(SpikeApplication application, ImmutableArray<string> requirements, CancellationToken cancellationToken) =>
        Set(() => application.Requirements = requirements);

    public ValueTask SetSettingsAsync(SpikeApplication application, ImmutableDictionary<string, string> settings, CancellationToken cancellationToken) =>
        Set(() => application.Settings = settings);

    public ValueTask UpdateAsync(SpikeApplication application, CancellationToken cancellationToken) => throw ReadOnly();

    private static ValueTask Set(Action set)
    {
        set();
        return ValueTask.CompletedTask;
    }

    private Task<List<SpikeApplication>> QueryAsync(string where, CancellationToken cancellationToken, params (string, object?)[] parameters) =>
        SpikeSql.QueryAsync(transaction.Context, $"SELECT {Columns} FROM spike_application {where}", Map, cancellationToken, parameters);

    private static SpikeApplication Map(DbDataReader reader) => new()
    {
        Id = reader.GetGuid(reader.GetOrdinal("id")),
        ClientId = SpikeSql.Text(reader, "client_id"),
        ClientSecret = SpikeSql.Text(reader, "client_secret"),
        ClientType = SpikeSql.Text(reader, "client_type"),
        ApplicationType = SpikeSql.Text(reader, "application_type"),
        ConsentType = SpikeSql.Text(reader, "consent_type"),
        DisplayName = SpikeSql.Text(reader, "display_name"),
        Permissions = SpikeSql.Array(reader, "permissions"),
        RedirectUris = SpikeSql.Array(reader, "redirect_uris"),
        PostLogoutRedirectUris = SpikeSql.Array(reader, "post_logout_redirect_uris"),
        Requirements = SpikeSql.Array(reader, "requirements"),
        Settings = SpikeSql.Settings(reader, "settings"),
        Properties = SpikeSql.Properties(reader, "properties"),
    };

    private static NotSupportedException ReadOnly() =>
        new("The spike seeds Applications by SQL. Writing them is Directory's job, not OpenIddict's.");

    private static NotSupportedException Unsupported() =>
        new("The spike stores don't take LINQ queries.");
}
