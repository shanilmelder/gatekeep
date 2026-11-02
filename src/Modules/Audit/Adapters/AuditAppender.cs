using System.Data.Common;
using System.Net;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Audit.Adapters;

/// <summary>
/// Picks the chain from the scope: a Tenant's, or the Deployment's when the scope has
/// no Tenant. Both rows go through the context, so they share its transaction. A User-Agent
/// comes from a request, so its credential shapes are masked before it's stored (T-42).
/// </summary>
internal sealed class AuditAppender : IAuditAppender
{
    private const string InsertTenantEvent =
        """
        INSERT INTO audit_event (tenant_id, id, type_code, actor_kind, actor_id, target_kind, target_id)
        VALUES (@tenant_id, @id, @type_code, @actor_kind, @actor_id, @target_kind, @target_id)
        """;

    private const string InsertTenantDetail =
        """
        INSERT INTO audit_detail (tenant_id, event_id, ip_address, user_agent, email)
        VALUES (@tenant_id, @id, @ip_address::inet, @user_agent, @email)
        """;

    private const string InsertDeploymentEvent =
        """
        INSERT INTO deployment_audit_event (id, type_code, actor_kind, actor_id, target_kind, target_id)
        VALUES (@id, @type_code, @actor_kind, @actor_id, @target_kind, @target_id)
        """;

    private const string InsertDeploymentDetail =
        """
        INSERT INTO deployment_audit_detail (event_id, ip_address, user_agent, email)
        VALUES (@id, @ip_address::inet, @user_agent, @email)
        """;

    public async Task AppendAsync(
        CommandContext context,
        AuditEvent auditEvent,
        AuditDetail? detail,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(auditEvent);

        // The sealer orders by ID, so IDs must sort by time.
        var id = Guid.CreateVersion7();
        var tenantId = context.TenantId;

        await using (var command = context.CreateCommand())
        {
            command.CommandText = tenantId is null ? InsertDeploymentEvent : InsertTenantEvent;
            AddKeys(command, tenantId, id);
            Add(command, "type_code", auditEvent.Type.Value);
            Add(command, "actor_kind", Stored(auditEvent.Actor.Kind));
            Add(command, "actor_id", auditEvent.Actor.Id);
            Add(command, "target_kind", auditEvent.TargetKind is { } kind ? Stored(kind) : null);
            Add(command, "target_id", auditEvent.TargetId);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (detail is null)
        {
            return;
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = tenantId is null ? InsertDeploymentDetail : InsertTenantDetail;
            AddKeys(command, tenantId, id);
            Add(command, "ip_address", StoredAddress(detail.IpAddress));
            Add(command, "user_agent", detail.UserAgent is { } userAgent ? CredentialShapes.MaskShapes(userAgent) : null);
            Add(command, "email", detail.Email);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static string Stored<TKind>(TKind kind)
        where TKind : struct, Enum =>
        kind.ToString().ToLowerInvariant();

    /// <summary>A zone suffix doesn't cast to <c>inet</c>, and a mapped address is really its IPv4 one.</summary>
    private static string? StoredAddress(IPAddress? address)
    {
        if (address is null)
        {
            return null;
        }

        var plain = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : new IPAddress(address.GetAddressBytes());

        return plain.ToString();
    }

    private static void AddKeys(DbCommand command, Guid? tenantId, Guid id)
    {
        Add(command, "id", id);

        if (tenantId is not null)
        {
            Add(command, "tenant_id", tenantId);
        }
    }

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
