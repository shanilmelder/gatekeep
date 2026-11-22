using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// Which Connections each Application allows (Story 4.12, FR-14): Directory owns <c>application_connection</c>. A missing row
/// means off; the <c>system</c> Application has no rows and follows every Connection its Tenant enables.
/// </summary>
internal sealed partial class DirectoryService
{
    public async Task<DatabaseConnection?> FindDatabaseConnectionForApplicationAsync(
        CommandContext context, Guid? applicationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (await ConnectionRows.FindAsync(context, locked: false, cancellationToken) is not { } connection)
        {
            return null;
        }

        // No Application: the system Application's view, which is the Tenant's own.
        if (applicationId is not { } application || !connection.Enabled)
        {
            return connection;
        }

        return connection with
        {
            Enabled = await ApplicationConnectionRows.AllowsAsync(context, application, connection.Id, cancellationToken),
        };
    }

    public Task<bool> IsConnectionEnabledForApplicationAsync(
        CommandContext context, Guid applicationId, Guid connectionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ApplicationConnectionRows.AllowsAsync(context, applicationId, connectionId, cancellationToken);
    }

    public async Task<IReadOnlyList<ApplicationConnection>?> ListApplicationConnectionsAsync(
        CommandContext context, Guid applicationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (await ApplicationRows.FindAsync(context, applicationId, cancellationToken) is null)
        {
            return null;
        }

        return await ApplicationConnectionRows.ListAsync(context, applicationId, cancellationToken);
    }

    public async Task<ApplicationConnectionWrite> SetApplicationConnectionAsync(
        CommandContext context, Actor actor, Guid applicationId, string connectionKind, bool enabled, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        _ = context.TenantId ?? throw new InvalidOperationException("An Application's Connections are changed only in a Tenant context.");

        var notFound = new ApplicationConnectionWrite(ApplicationConnectionWriteStatus.NotFound, null);

        // Decided under the Application's lock: two toggles of one Application take turns. The system Application is
        // never found here, so no row is ever written for it.
        if (await ApplicationRows.FindAsync(context, applicationId, cancellationToken, locked: true) is null)
        {
            return notFound;
        }

        var current = (await ApplicationConnectionRows.ListAsync(context, applicationId, cancellationToken))
            .FirstOrDefault(c => string.Equals(c.Kind, connectionKind, StringComparison.Ordinal));
        if (current is null)
        {
            return notFound;
        }

        if (current.Enabled == enabled)
        {
            return new ApplicationConnectionWrite(ApplicationConnectionWriteStatus.Unchanged, current);
        }

        await ApplicationConnectionRows.SetAsync(context, applicationId, current.ConnectionId, enabled, cancellationToken);
        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApplicationConnectionUpdated.Code, actor, AuditTargetKind.Client, applicationId),
            detail: null,
            cancellationToken);
        return new ApplicationConnectionWrite(ApplicationConnectionWriteStatus.Saved, current with { Enabled = enabled });
    }

    public async Task<IReadOnlyList<ConnectionApplication>?> ListConnectionApplicationsAsync(
        CommandContext context, string connectionKind, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!string.Equals(connectionKind, DirectoryContract.DatabaseConnectionKind, StringComparison.Ordinal)
            || await ConnectionRows.FindIdAsync(context, cancellationToken) is not { } connectionId)
        {
            return null;
        }

        return await ApplicationConnectionRows.ApplicationsAsync(context, connectionId, cancellationToken);
    }

    /// <summary>A new Application's defaults (Story 4.12), in its creation's command: every Connection of the Tenant, on.</summary>
    private static async Task InsertDefaultConnectionsAsync(CommandContext context, Guid applicationId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = ApplicationConnectionRows.InsertDefaults;
        Add(command, "tenant_id", context.TenantId);
        Add(command, "application_id", applicationId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}

/// <summary>Reads and writes <c>application_connection</c> rows (Story 4.12), always in the context Tenant.</summary>
internal static class ApplicationConnectionRows
{
    // Every Connection of the Tenant, on for the new Application, as the migration's backfill does: the effective rule
    // ANDs the Tenant's own switch, so one the Tenant disables now counts again once it is re-enabled. The system
    // Application is never created here.
    public const string InsertDefaults =
        """
        INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled)
        SELECT tenant_id, @application_id, id, true FROM connection WHERE tenant_id = @tenant_id
        """;

    // A Connection inserted after its Tenant's Applications (the hourly backfill's ensure): on for each visible one.
    public const string EnableForApplications =
        """
        INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled)
        SELECT a.tenant_id, a.id, @connection_id, true FROM application a
        WHERE a.tenant_id = @tenant_id AND a.kind <> 'system' AND a.deleted_at IS NULL
        """;

    // The one effective rule: the Tenant enables the Connection, and the Application is the system one, which follows its
    // Tenant, or has an enabled row. A missing row means off; a deleted or unknown Application finds no row here at all.
    private const string Allows =
        """
        SELECT c.enabled AND (
                 a.kind = 'system'
                 OR EXISTS (
                   SELECT 1 FROM application_connection ac
                   WHERE ac.tenant_id = a.tenant_id AND ac.application_id = a.id AND ac.connection_id = c.id AND ac.enabled))
        FROM connection c
        JOIN application a ON a.tenant_id = c.tenant_id AND a.id = @application_id AND a.deleted_at IS NULL
        WHERE c.tenant_id = @tenant_id AND c.id = @connection_id
        """;

    // Every Connection of the Tenant, with the Application's row; a missing one is off.
    private const string List =
        """
        SELECT c.id, c.kind, c.name, coalesce(ac.enabled, false), c.enabled
        FROM connection c
        LEFT JOIN application_connection ac
          ON ac.tenant_id = c.tenant_id AND ac.connection_id = c.id AND ac.application_id = @application_id
        WHERE c.tenant_id = @tenant_id
        ORDER BY c.kind, c.id
        """;

    // The caller holds the Application's lock and has decided the value changes.
    private const string Upsert =
        """
        INSERT INTO application_connection (tenant_id, application_id, connection_id, enabled, updated_at)
        VALUES (@tenant_id, @application_id, @connection_id, @enabled, now())
        ON CONFLICT (tenant_id, application_id, connection_id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()
        """;

    // The visible Applications the Connection is enabled for, by the effective rule: never the system one.
    private const string Applications =
        """
        SELECT a.id, a.name, a.kind
        FROM application a
        JOIN application_connection ac ON ac.tenant_id = a.tenant_id AND ac.application_id = a.id AND ac.enabled
        JOIN connection c ON c.tenant_id = ac.tenant_id AND c.id = ac.connection_id AND c.enabled
        WHERE a.tenant_id = @tenant_id AND ac.connection_id = @connection_id AND a.kind <> 'system' AND a.deleted_at IS NULL
        ORDER BY a.name, a.id
        """;

    public static async Task<bool> AllowsAsync(CommandContext context, Guid applicationId, Guid connectionId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Allows;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "application_id", applicationId);
        DirectoryService.Add(command, "connection_id", connectionId);
        return await command.ExecuteScalarAsync(cancellationToken) is true;
    }

    public static async Task<IReadOnlyList<ApplicationConnection>> ListAsync(CommandContext context, Guid applicationId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = List;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "application_id", applicationId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var connections = new List<ApplicationConnection>();
        while (await reader.ReadAsync(cancellationToken))
        {
            connections.Add(Read(reader));
        }

        return connections;
    }

    public static async Task SetAsync(CommandContext context, Guid applicationId, Guid connectionId, bool enabled, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Upsert;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "application_id", applicationId);
        DirectoryService.Add(command, "connection_id", connectionId);
        DirectoryService.Add(command, "enabled", enabled);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public static async Task<IReadOnlyList<ConnectionApplication>> ApplicationsAsync(CommandContext context, Guid connectionId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Applications;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "connection_id", connectionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var applications = new List<ConnectionApplication>();
        while (await reader.ReadAsync(cancellationToken))
        {
            var id = reader.GetGuid(0);
            applications.Add(new ConnectionApplication(id, PublicId.Format(PublicIdType.Application, id), reader.GetString(1), reader.GetString(2)));
        }

        return applications;
    }

    private static ApplicationConnection Read(DbDataReader reader) =>
        new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetBoolean(3), reader.GetBoolean(4));

    private static Guid TenantOf(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.TenantId
            ?? throw new InvalidOperationException("An Application's Connections are read only in a Tenant context.");
    }
}
