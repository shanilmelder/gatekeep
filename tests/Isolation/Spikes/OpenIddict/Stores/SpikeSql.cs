using System.Collections.Immutable;
using System.Data.Common;
using System.Text.Json;
using Gatekeep.Kernel.Persistence;
using Npgsql;
using NpgsqlTypes;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;

/// <summary>Commands on the request's <see cref="CommandContext"/>, and the column conversions.</summary>
internal static class SpikeSql
{
    public static NpgsqlCommand Command(CommandContext context, string sql, params (string Name, object? Value)[] parameters)
    {
        var command = (NpgsqlCommand)context.CreateCommand();
        command.CommandText = sql;

        foreach (var (name, value) in parameters)
        {
            command.Parameters.Add(value switch
            {
                JsonText json => new NpgsqlParameter(name, NpgsqlDbType.Jsonb) { Value = json.Value },
                DateTimeOffset date => new NpgsqlParameter(name, NpgsqlDbType.TimestampTz) { Value = date.ToUniversalTime() },
                string[] array => new NpgsqlParameter(name, NpgsqlDbType.Array | NpgsqlDbType.Text) { Value = array },
                null => new NpgsqlParameter(name, DBNull.Value),
                _ => new NpgsqlParameter(name, value),
            });
        }

        return command;
    }

    public static async Task<int> ExecuteAsync(
        CommandContext context, string sql, CancellationToken cancellationToken, params (string, object?)[] parameters)
    {
        await using var command = Command(context, sql, parameters);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>Reads every row before returning, so the connection is free for the next command.</summary>
    public static async Task<List<T>> QueryAsync<T>(
        CommandContext context, string sql, Func<DbDataReader, T> map, CancellationToken cancellationToken,
        params (string, object?)[] parameters)
    {
        await using var command = Command(context, sql, parameters);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        var rows = new List<T>();
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(map(reader));
        }

        return rows;
    }

    public static Guid? ParseId(string? identifier) =>
        Guid.TryParse(identifier, out var id) ? id : null;

    public static string? Text(DbDataReader reader, string column) =>
        reader.IsDBNull(reader.GetOrdinal(column)) ? null : reader.GetString(reader.GetOrdinal(column));

    public static Guid? Uuid(DbDataReader reader, string column) =>
        reader.IsDBNull(reader.GetOrdinal(column)) ? null : reader.GetGuid(reader.GetOrdinal(column));

    public static DateTimeOffset? Date(DbDataReader reader, string column) =>
        reader.IsDBNull(reader.GetOrdinal(column))
            ? null
            : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal(column));

    public static ImmutableArray<string> Array(DbDataReader reader, string column) =>
        [.. reader.GetFieldValue<string[]>(reader.GetOrdinal(column))];

    public static ImmutableDictionary<string, JsonElement> Properties(DbDataReader reader, string column) =>
        JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(reader.GetString(reader.GetOrdinal(column)))?
            .ToImmutableDictionary() ?? ImmutableDictionary<string, JsonElement>.Empty;

    public static ImmutableDictionary<string, string> Settings(DbDataReader reader, string column) =>
        JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(reader.GetOrdinal(column)))?
            .ToImmutableDictionary() ?? ImmutableDictionary<string, string>.Empty;

    public static JsonText Json<T>(T value) => new(JsonSerializer.Serialize(value));

    /// <summary>A value written as <c>jsonb</c>.</summary>
    public sealed record JsonText(string Value);
}
