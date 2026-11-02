using System.Text;
using System.Text.Json;
using Npgsql;

namespace Gatekeep.Tests.Isolation.Canary;

/// <summary>A raw value that must never be stored. <see cref="Kind"/> is what a report prints.</summary>
internal sealed record Canary(string Kind, string Value, string InShape);

/// <summary>Text to scan, and the name a finding reports it by.</summary>
internal sealed record CanarySource(string Name, string Text);

/// <summary>Holds no value, so a finding is safe to print whole.</summary>
internal sealed record CanaryFinding(string Kind, string Source)
{
    public override string ToString() => $"{Kind} canary found in {Source}";
}

internal sealed class CanaryFoundException(IEnumerable<CanaryFinding> findings)
    : Exception(string.Join(Environment.NewLine, findings));

/// <summary>
/// The canary scan (NFR-3, AD-24). A later story adds a value to <see cref="Canaries"/>
/// or a table to <see cref="AuditTables"/>, or passes another source to <see cref="Scan"/>.
/// Story 7.8's canary flows (<see cref="CanaryFlows"/>) plant their own values and scan every
/// table with <see cref="DatabaseSourcesAsync"/>, plus each run's logs, output and responses.
/// </summary>
internal static class CanaryScanner
{
    public static readonly IReadOnlyList<Canary> Canaries =
    [
        new("connection-password", "Cnry-pw-5f2a9c", "Host=db;Username=gk;Password=Cnry-pw-5f2a9c;Database=gatekeep"),
        new("bearer-token", "cnry.bearer.5f2a9c", "Authorization: Bearer cnry.bearer.5f2a9c"),
        new(
            "jwt",
            "eyJjYW5hcnkiOiIxIn0.eyJzdWIiOiJjYW5hcnkifQ.Y2FuYXJ5LXNpZw",
            "issued eyJjYW5hcnkiOiIxIn0.eyJzdWIiOiJjYW5hcnkifQ.Y2FuYXJ5LXNpZw"),
        new("authorization-code", "cnry-code-5f2a9c", "GET /callback?code=cnry-code-5f2a9c&state=1"),
        new(
            "private-key",
            "Q05SWVBSSVZBVEVLRVk1ZjJhOWM",
            "-----BEGIN PRIVATE KEY-----\nQ05SWVBSSVZBVEVLRVk1ZjJhOWM\n-----END PRIVATE KEY-----"),
    ];

    public static readonly IReadOnlyList<string> AuditTables =
        ["audit_event", "audit_detail", "deployment_audit_event", "deployment_audit_detail"];

    public static IReadOnlyList<CanaryFinding> Scan(IEnumerable<Canary> canaries, IEnumerable<CanarySource> sources)
    {
        var sourceList = sources.ToList();

        return canaries
            .SelectMany(canary => sourceList
                .Where(source => source.Text.Contains(canary.Value, StringComparison.Ordinal))
                .Select(source => new CanaryFinding(canary.Kind, source.Name)))
            .ToList();
    }

    public static void ThrowIfFound(IReadOnlyList<CanaryFinding> findings)
    {
        if (findings.Count > 0)
        {
            throw new CanaryFoundException(findings);
        }
    }

    /// <summary>
    /// One source per stored column, named by table, column and column kind. It reads as the
    /// superuser, which row-level security doesn't limit, so every Tenant's rows are seen.
    /// </summary>
    public static Task<IReadOnlyList<CanarySource>> AuditSourcesAsync(
        string superuserConnection,
        CancellationToken cancellationToken) =>
        TableSourcesAsync(superuserConnection, AuditTables, cancellationToken);

    /// <summary>
    /// Every base table in the database, audit tables included, one source per stored column
    /// as <see cref="AuditSourcesAsync"/> names them. A canary flow scans this after each run.
    /// </summary>
    public static async Task<IReadOnlyList<CanarySource>> DatabaseSourcesAsync(
        string superuserConnection,
        CancellationToken cancellationToken) =>
        await TableSourcesAsync(superuserConnection, await TablesAsync(superuserConnection, cancellationToken), cancellationToken);

    /// <summary>The database's base tables in <c>public</c>, which is every table Gatekeep has.</summary>
    public static async Task<IReadOnlyList<string>> TablesAsync(string superuserConnection, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(superuserConnection);
        await connection.OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name",
            connection);

        var tables = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            tables.Add(reader.GetString(0));
        }

        return tables;
    }

    private static async Task<IReadOnlyList<CanarySource>> TableSourcesAsync(
        string superuserConnection,
        IEnumerable<string> tables,
        CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(superuserConnection);
        await connection.OpenAsync(cancellationToken);

        var sources = new List<CanarySource>();
        foreach (var table in tables)
        {
            var kinds = await ColumnKindsAsync(connection, table, cancellationToken);
            var columns = await ColumnTextAsync(connection, table, cancellationToken);

            sources.AddRange(columns.Select(column =>
                new CanarySource($"{table}.{column.Key} ({kinds[column.Key]})", column.Value.ToString())));
        }

        return sources;
    }

    private static async Task<Dictionary<string, string>> ColumnKindsAsync(
        NpgsqlConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name = @table",
            connection);
        command.Parameters.AddWithValue("table", table);

        var kinds = new Dictionary<string, string>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            kinds.Add(reader.GetString(0), reader.GetString(1));
        }

        return kinds;
    }

    private static async Task<Dictionary<string, StringBuilder>> ColumnTextAsync(
        NpgsqlConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand($"SELECT row_to_json(t)::text FROM \"{table}\" t", connection);

        var columns = new Dictionary<string, StringBuilder>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // Parsed, not searched as JSON, because escaping would hide a value with a newline.
            using var row = JsonDocument.Parse(reader.GetString(0));
            foreach (var column in row.RootElement.EnumerateObject())
            {
                if (!columns.TryGetValue(column.Name, out var text))
                {
                    columns[column.Name] = text = new StringBuilder();
                }

                text.AppendLine(column.Value.ValueKind == JsonValueKind.String
                    ? column.Value.GetString()
                    : column.Value.GetRawText());
            }
        }

        return columns;
    }
}
