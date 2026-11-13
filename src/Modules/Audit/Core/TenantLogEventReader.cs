using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// Opens one event of a Tenant's Log (Story 7.5): the envelope and seal from <c>audit_event</c>,
/// then, only when detail is asked for, the row in <c>audit_detail</c>. A caller without the
/// detail capability never causes a detail read, so no mapping bug can leak it.
/// </summary>
internal sealed class TenantLogEventReader : ITenantLogEventReader
{
    private const string SelectEvent =
        """
        SELECT id, occurred_at, type_code, actor_kind, actor_id, target_kind, target_id, seq, prev_hash, hash
        FROM audit_event
        WHERE tenant_id = @tenant_id AND id = @id
        """;

    // host() writes the address alone, without a netmask.
    private const string SelectDetail =
        """
        SELECT host(ip_address), user_agent, email
        FROM audit_detail
        WHERE tenant_id = @tenant_id AND event_id = @id
        """;

    public async Task<TenantLogEvent?> FindAsync(CommandContext context, Guid eventId, bool includeDetail, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.TenantId is not { } tenantId)
        {
            throw new InvalidOperationException("A Tenant's Log is read in its own Tenant scope.");
        }

        TenantLogEntry entry;
        TenantLogSeal? seal;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectEvent;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", eventId);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            entry = new TenantLogEntry(
                reader.GetGuid(0),
                reader.GetFieldValue<DateTimeOffset>(1),
                new AuditTypeCode(reader.GetString(2)),
                TenantLogSearch.ActorKindOf(reader.GetString(3)),
                reader.IsDBNull(4) ? null : reader.GetGuid(4),
                reader.IsDBNull(5) ? null : TenantLogSearch.TargetKindOf(reader.GetString(5)),
                reader.IsDBNull(6) ? null : reader.GetGuid(6));
            seal = reader.IsDBNull(7)
                ? null
                : new TenantLogSeal(
                    reader.GetInt64(7),
                    reader.IsDBNull(8) ? null : reader.GetFieldValue<byte[]>(8),
                    reader.GetFieldValue<byte[]>(9));
        }

        if (!includeDetail)
        {
            return new TenantLogEvent(entry, seal, null);
        }

        TenantLogDetail? detail = null;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SelectDetail;
            Add(command, "tenant_id", tenantId);
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

    private static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
