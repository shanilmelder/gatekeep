using System.Data.Common;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// A Tenant's Log search (Story 7.4). Each filter is a fixed SQL fragment on an indexed
/// <c>audit_event</c> column, ANDed, with every value a parameter: nothing a caller sends becomes
/// SQL text. Pages are newest first by ID (UUIDv7, so by time), one more row read to know whether
/// another page follows. An email resolves first, to the User references on events whose detail
/// holds exactly that email, through <c>audit_detail (tenant_id, email)</c>; then the envelope is
/// searched for those Users, so an erased User's detail no longer finds them.
/// </summary>
internal sealed class TenantLogSearch : ITenantLogSearch
{
    /// <summary>The most User references one email resolves to: more than one is already unusual.</summary>
    public const int MaxResolvedUsers = 100;

    private const string ResolveEmail =
        """
        SELECT e.actor_id AS user_id
        FROM audit_detail AS d
        JOIN audit_event AS e ON e.tenant_id = d.tenant_id AND e.id = d.event_id
        WHERE d.tenant_id = @tenant_id AND d.email = @email AND e.actor_kind = 'user'
        UNION
        SELECT e.target_id
        FROM audit_detail AS d
        JOIN audit_event AS e ON e.tenant_id = d.tenant_id AND e.id = d.event_id
        WHERE d.tenant_id = @tenant_id AND d.email = @email AND e.target_kind = 'user'
        LIMIT @max_users
        """;

    private const string Select =
        """
        SELECT id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id
        FROM audit_event
        WHERE tenant_id = @tenant_id
        """;

    private const string ByType = "\n  AND type_code = ANY (@types)";

    private const string ByOutcome = "\n  AND type_code = ANY (@outcome_types)";

    private const string ByUser =
        "\n  AND ((actor_kind = 'user' AND actor_id = ANY (@users)) OR (target_kind = 'user' AND target_id = ANY (@users)))";

    private const string ByApplication =
        "\n  AND ((actor_kind = 'client' AND actor_id = @application) OR (target_kind = 'client' AND target_id = @application))";

    private const string ByFrom = "\n  AND occurred_at >= @from";

    private const string ByTo = "\n  AND occurred_at < @to";

    private const string ByAfter = "\n  AND id < @after";

    private const string Page = "\nORDER BY id DESC\nLIMIT @limit";

    public async Task<TenantLogPage> SearchAsync(CommandContext context, TenantLogQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(query);
        if (context.TenantId is not { } tenantId)
        {
            throw new InvalidOperationException("A Tenant's Log is read in its own Tenant scope.");
        }

        if (query.Limit is < 1 or > TenantLogQuery.MaxLimit)
        {
            throw new ArgumentException($"A page holds 1 to {TenantLogQuery.MaxLimit} events.", nameof(query));
        }

        if (query.UserId is not null && query.UserEmail is not null)
        {
            throw new ArgumentException("A User is searched by ID or by email, not both.", nameof(query));
        }

        if (query.From is { } from && query.To is { } to && from >= to)
        {
            throw new ArgumentException("A range's start comes before its end.", nameof(query));
        }

        // Nothing can match: an empty code set, or an email no event's detail names.
        if (query.Types is { Count: 0 } || query.OutcomeTypes is { Count: 0 })
        {
            return new TenantLogPage([], null);
        }

        Guid[]? users = query.UserId is { } userId ? [userId] : null;
        if (query.UserEmail is { } email)
        {
            users = await ResolveAsync(context, tenantId, email, cancellationToken);
            if (users.Length == 0)
            {
                return new TenantLogPage([], null);
            }
        }

        await using var command = context.CreateCommand();
        var sql = new StringBuilder(Select);
        Add(command, "tenant_id", tenantId);

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

        if (users is not null)
        {
            sql.Append(ByUser);
            Add(command, "users", users);
        }

        if (query.ApplicationId is { } application)
        {
            sql.Append(ByApplication);
            Add(command, "application", application);
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
                events.Add(new TenantLogEntry(
                    reader.GetGuid(0),
                    reader.GetFieldValue<DateTimeOffset>(1),
                    new AuditTypeCode(reader.GetString(2)),
                    ActorKindOf(reader.GetString(3)),
                    reader.IsDBNull(4) ? null : reader.GetGuid(4),
                    reader.IsDBNull(5) ? null : TargetKindOf(reader.GetString(5)),
                    reader.IsDBNull(6) ? null : reader.GetGuid(6)));
            }
        }

        if (events.Count <= query.Limit)
        {
            return new TenantLogPage(events, null);
        }

        events.RemoveAt(events.Count - 1);
        return new TenantLogPage(events, events[^1].Id);
    }

    private static async Task<Guid[]> ResolveAsync(CommandContext context, Guid tenantId, string email, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = ResolveEmail;
        Add(command, "tenant_id", tenantId);
        Add(command, "email", email);
        Add(command, "max_users", MaxResolvedUsers);

        var users = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            users.Add(reader.GetGuid(0));
        }

        return [.. users];
    }

    private static string[] Codes(IEnumerable<AuditTypeCode> codes) => [.. codes.Select(c => c.Value).Distinct(StringComparer.Ordinal)];

    private static ActorKind ActorKindOf(string stored) => stored switch
    {
        "system" => ActorKind.System,
        "anonymous" => ActorKind.Anonymous,
        "admin" => ActorKind.Admin,
        "user" => ActorKind.User,
        "client" => ActorKind.Client,
        _ => throw new InvalidOperationException("An audit event has an unknown Actor kind."),
    };

    private static AuditTargetKind TargetKindOf(string stored) => stored switch
    {
        "tenant" => AuditTargetKind.Tenant,
        "admin" => AuditTargetKind.Admin,
        "user" => AuditTargetKind.User,
        "client" => AuditTargetKind.Client,
        "api" => AuditTargetKind.Api,
        _ => throw new InvalidOperationException("An audit event has an unknown target kind."),
    };

    private static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
