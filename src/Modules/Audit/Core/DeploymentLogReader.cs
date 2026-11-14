using System.Data.Common;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// The Deployment Log's search and open read (Story 7.7), the Deployment twin of
/// <see cref="TenantLogSearch"/> and <see cref="TenantLogEventReader"/>. Each filter is a fixed SQL
/// fragment on an indexed <c>deployment_audit_event</c> column, ANDed, with every value a
/// parameter: nothing a caller sends becomes SQL text. Pages are newest first by ID (UUIDv7, so by
/// time), one more row read to know whether another page follows. Only the open read touches
/// <c>deployment_audit_detail</c>.
/// </summary>
internal sealed class DeploymentLogReader : IDeploymentLogReader
{
    private const string Select =
        """
        SELECT id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id
        FROM deployment_audit_event
        WHERE true
        """;

    private const string ByType = "\n  AND type_code = ANY (@types)";

    private const string ByOutcome = "\n  AND type_code = ANY (@outcome_types)";

    private const string ByAdmin =
        "\n  AND ((actor_kind = 'admin' AND actor_id = @admin) OR (target_kind = 'admin' AND target_id = @admin))";

    private const string ByTenant = "\n  AND target_kind = 'tenant' AND target_id = @tenant";

    private const string ByFrom = "\n  AND occurred_at >= @from";

    private const string ByTo = "\n  AND occurred_at < @to";

    private const string ByAfter = "\n  AND id < @after";

    private const string Page = "\nORDER BY id DESC\nLIMIT @limit";

    private const string SelectEvent =
        """
        SELECT id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, seq, prev_hash, hash
        FROM deployment_audit_event
        WHERE id = @id
        """;

    // host() writes the address alone, without a netmask.
    private const string SelectDetail =
        """
        SELECT host(ip_address), user_agent, email
        FROM deployment_audit_detail
        WHERE event_id = @id
        """;

    public async Task<TenantLogPage> SearchAsync(CommandContext context, DeploymentLogQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(query);
        RequireDeployment(context);

        if (query.Limit is < 1 or > DeploymentLogQuery.MaxLimit)
        {
            throw new ArgumentException($"A page holds 1 to {DeploymentLogQuery.MaxLimit} events.", nameof(query));
        }

        if (query.From is { } from && query.To is { } to && from >= to)
        {
            throw new ArgumentException("A range's start comes before its end.", nameof(query));
        }

        // Nothing can match an empty code set.
        if (query.Types is { Count: 0 } || query.OutcomeTypes is { Count: 0 })
        {
            return new TenantLogPage([], null);
        }

        await using var command = context.CreateCommand();
        var sql = new StringBuilder(Select);

        if (query.Types is { } types)
        {
            sql.Append(ByType);
            Add(command, "types", Codes(types));
        }

        if (query.OutcomeTypes is { } outcomeTypes)
        {
            sql.Append(ByOutcome);
            Add(command, "outcome_types", Codes(outcomeTypes));
        }

        if (query.AdminId is { } admin)
        {
            sql.Append(ByAdmin);
            Add(command, "admin", admin);
        }

        if (query.TenantId is { } tenant)
        {
            sql.Append(ByTenant);
            Add(command, "tenant", tenant);
        }

        if (query.From is { } since)
        {
            sql.Append(ByFrom);
            Add(command, "from", since.ToUniversalTime());
        }

        if (query.To is { } until)
        {
            sql.Append(ByTo);
            Add(command, "to", until.ToUniversalTime());
        }

        if (query.After is { } after)
        {
            sql.Append(ByAfter);
            Add(command, "after", after);
        }

        sql.Append(Page);
        Add(command, "limit", query.Limit + 1);
        command.CommandText = sql.ToString();

        var events = new List<TenantLogEntry>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                events.Add(Entry(reader));
            }
        }

        if (events.Count <= query.Limit)
        {
            return new TenantLogPage(events, null);
        }

        events.RemoveAt(events.Count - 1);
        return new TenantLogPage(events, events[^1].Id);
    }

    public async Task<TenantLogEvent?> FindAsync(CommandContext context, Guid eventId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        RequireDeployment(context);

        TenantLogEntry entry;
        TenantLogSeal? seal;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectEvent;
            Add(command, "id", eventId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            entry = Entry(reader);
            seal = reader.IsDBNull(7)
                ? null
                : new TenantLogSeal(
                    reader.GetInt64(7),
                    reader.IsDBNull(8) ? null : reader.GetFieldValue<byte[]>(8),
                    reader.GetFieldValue<byte[]>(9));
        }

        TenantLogDetail? detail = null;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectDetail;
            Add(command, "id", eventId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                detail = new TenantLogDetail(
                    reader.IsDBNull(0) ? null : reader.GetString(0),
                    reader.IsDBNull(1) ? null : reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2));
            }
        }

        return new TenantLogEvent(entry, seal, detail);
    }

    private static void RequireDeployment(CommandContext context)
    {
        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("The Deployment Log is read in a Deployment scope.");
        }
    }

    private static TenantLogEntry Entry(DbDataReader reader) => new(
        reader.GetGuid(0),
        reader.GetFieldValue<DateTimeOffset>(1),
        new AuditTypeCode(reader.GetString(2)),
        StoredKinds.ActorKindOf(reader.GetString(3)),
        reader.IsDBNull(4) ? null : reader.GetGuid(4),
        reader.IsDBNull(5) ? null : StoredKinds.TargetKindOf(reader.GetString(5)),
        reader.IsDBNull(6) ? null : reader.GetGuid(6));

    private static string[] Codes(IEnumerable<AuditTypeCode> codes) => [.. codes.Select(c => c.Value).Distinct(StringComparer.Ordinal)];

    private static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
