using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Modules.Tenancy.Core;

/// <summary>The SQL on <c>tenant</c>, <c>tenant_host</c> and <c>tenant_settings</c> (AD-27).</summary>
internal sealed class Tenants(IAuditAppender appender) : ITenants
{
    private const string UniqueViolation = "23505";

    /// <summary>The host guard's own SQLSTATE: a host for a Tenant that isn't creating, or a second one of its kind.</summary>
    private const string HostRefused = "GK002";

    private const string Savepoint = "tenant_insert";

    private const string InsertTenant =
        """
        INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base)
        VALUES (@id, @name, @label, 'creating', @issuer, @rp_id, @email_link_base)
        RETURNING created_at
        """;

    private const string InsertHost =
        """
        INSERT INTO tenant_host (host, tenant_id, kind)
        VALUES (@host, @tenant_id, 'subdomain')
        """;

    private const string SelectPage =
        """
        SELECT t.id, t.name, t.label, t.status, h.host, t.created_at
        FROM tenant t
        JOIN tenant_host h ON h.tenant_id = t.id AND h.kind = 'subdomain'
        WHERE t.status <> 'deleted'
          AND (@after::uuid IS NULL
               OR (t.created_at, t.id) > (SELECT a.created_at, a.id FROM tenant a WHERE a.id = @after))
        ORDER BY t.created_at, t.id
        LIMIT @limit
        """;

    private const string InsertSettings =
        """
        INSERT INTO tenant_settings (tenant_id) VALUES (@tenant_id)
        ON CONFLICT DO NOTHING
        """;

    private const string Activate = "UPDATE tenant SET status = 'active' WHERE id = @id AND status = 'creating'";

    private const string SelectActive =
        """
        SELECT t.id, t.name, t.label, t.status, h.host, t.created_at
        FROM tenant t
        JOIN tenant_host h ON h.tenant_id = t.id AND h.kind = 'subdomain'
        WHERE t.id = ANY(@ids) AND t.status = 'active'
        ORDER BY t.created_at, t.id
        """;

    /// <summary>
    /// <c>FOR NO KEY UPDATE</c>, not <c>FOR UPDATE</c>: it still serialises label changes, but it
    /// doesn't conflict with the <c>FOR KEY SHARE</c> every foreign-key insert referencing the Tenant
    /// takes, so its audit appends, sessions, roles, jobs and sign-ins go on while a change holds it.
    /// </summary>
    private const string LockLabel = "SELECT label, status FROM tenant WHERE id = @id FOR NO KEY UPDATE";

    private const string ReadLabel = "SELECT label, status FROM tenant WHERE id = @id";

    private const string SetLabel = "UPDATE tenant SET label = @label WHERE id = @id AND status = 'active'";

    /// <summary>
    /// A creation's completion locks the Tenant first (Story 1.29), so a deletion's start, which takes
    /// the same lock, either finds it active or makes it deleting before this reads it.
    /// </summary>
    private const string LockStatus = "SELECT status FROM tenant WHERE id = @id FOR NO KEY UPDATE";

    // NO KEY UPDATE, not UPDATE: other tables reference tenant, and their inserts' FOR KEY SHARE goes on.
    private const string LockForDeletion =
        """
        SELECT t.status, h.host
        FROM tenant t
        LEFT JOIN tenant_host h ON h.tenant_id = t.id AND h.kind = 'subdomain'
        WHERE t.id = @id
        FOR NO KEY UPDATE OF t
        """;

    private const string BeginDeletion = "UPDATE tenant SET status = 'deleting' WHERE id = @id AND status IN ('creating', 'active')";

    /// <summary>
    /// <c>FOR SHARE</c>: two stages of one deletion read it together, while it conflicts with a
    /// deletion's start and a creation's completion, which take <c>FOR NO KEY UPDATE</c>.
    /// </summary>
    private const string ShareStatus = "SELECT status FROM tenant WHERE id = @id FOR SHARE";

    private const string PurgeLock = "SELECT status FROM tenant WHERE id = @id FOR UPDATE";

    private const string MarkDeleted = "UPDATE tenant SET status = 'deleted' WHERE id = @id AND status = 'deleting'";

    private readonly IAuditAppender _appender = appender ?? throw new ArgumentNullException(nameof(appender));

    public async Task<TenantInsertResult> InsertAsync(CommandContext context, TenantDraft draft, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(draft);

        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("A Tenant is created in a Deployment context.");
        }

        if (draft.Id == Guid.Empty)
        {
            throw new ArgumentException("A Tenant needs an ID.", nameof(draft));
        }

        // A taken host leaves the caller's transaction usable, with nothing of this Tenant in it.
        await ExecuteAsync(context, $"SAVEPOINT {Savepoint}", cancellationToken);
        DateTimeOffset createdAt;
        try
        {
            await using (var command = context.CreateCommand())
            {
                command.CommandText = InsertTenant;
                Add(command, "id", draft.Id);
                Add(command, "name", draft.Name);
                Add(command, "label", TenantValues.Stored(draft.Label));
                Add(command, "issuer", draft.Address.Issuer);
                Add(command, "rp_id", draft.Address.RpId);
                Add(command, "email_link_base", draft.Address.EmailLinkBase);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                await reader.ReadAsync(cancellationToken);
                createdAt = reader.GetFieldValue<DateTimeOffset>(0);
            }

            await using (var command = context.CreateCommand())
            {
                command.CommandText = InsertHost;
                Add(command, "host", draft.Address.Host);
                Add(command, "tenant_id", draft.Id);
                await command.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        catch (DbException e) when (e.SqlState is UniqueViolation or HostRefused)
        {
            // The host's primary key, or the issuer or RP ID derived from it: one outcome, so
            // nothing tells a taken host from any other clash.
            await ExecuteAsync(context, $"ROLLBACK TO SAVEPOINT {Savepoint}", cancellationToken);
            return new TenantInsertResult(TenantInsertStatus.SubdomainTaken);
        }

        await ExecuteAsync(context, $"RELEASE SAVEPOINT {Savepoint}", cancellationToken);
        return new TenantInsertResult(TenantInsertStatus.Inserted, createdAt);
    }

    public async Task<IReadOnlyList<TenantRecord>> ListAsync(CommandContext context, Guid? after, int limit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);

        var tenants = new List<TenantRecord>();
        await using var command = context.CreateCommand();
        command.CommandText = SelectPage;
        Add(command, "after", after);
        Add(command, "limit", limit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            tenants.Add(new TenantRecord(
                reader.GetGuid(0),
                reader.GetString(1),
                TenantValues.ParseLabel(reader.GetString(2)),
                TenantValues.ParseStatus(reader.GetString(3)),
                reader.GetString(4),
                reader.GetFieldValue<DateTimeOffset>(5)));
        }

        return tenants;
    }

    public async Task<bool> ActivateAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant is activated in its own context.");
        }

        // Only a creating Tenant: a deleting or deleted one never gets settings back (Story 1.29).
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockStatus;
            Add(command, "id", tenantId);
            if (await command.ExecuteScalarAsync(cancellationToken) is not string status
                || TenantValues.ParseStatus(status) != TenantStatus.Creating)
            {
                return false;
            }
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertSettings;
            Add(command, "tenant_id", tenantId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Activate;
            Add(command, "id", tenantId);
            if (await command.ExecuteNonQueryAsync(cancellationToken) == 0)
            {
                return false;
            }
        }

        await _appender.AppendAsync(context, new AuditEvent(TenancyEvents.TenantActivated.Code, Actor.System), null, cancellationToken);
        return true;
    }

    public async Task<IReadOnlyList<TenantRecord>> ListActiveAsync(CommandContext context, IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(ids);

        var tenants = new List<TenantRecord>();
        if (ids.Count == 0)
        {
            return tenants;
        }

        await using var command = context.CreateCommand();
        command.CommandText = SelectActive;
        Add(command, "ids", ids.ToArray());

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            tenants.Add(new TenantRecord(
                reader.GetGuid(0),
                reader.GetString(1),
                TenantValues.ParseLabel(reader.GetString(2)),
                TenantValues.ParseStatus(reader.GetString(3)),
                reader.GetString(4),
                reader.GetFieldValue<DateTimeOffset>(5)));
        }

        return tenants;
    }

    public Task<TenantLabelState?> LockLabelAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken) =>
        LabelAsync(context, tenantId, LockLabel, cancellationToken);

    public Task<TenantLabelState?> GetLabelAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken) =>
        LabelAsync(context, tenantId, ReadLabel, cancellationToken);

    private static async Task<TenantLabelState?> LabelAsync(CommandContext context, Guid tenantId, string sql, CancellationToken cancellationToken)
    {
        RequireOwnContext(context, tenantId);

        await using var command = context.CreateCommand();
        command.CommandText = sql;
        Add(command, "id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new TenantLabelState(TenantValues.ParseLabel(reader.GetString(0)), TenantValues.ParseStatus(reader.GetString(1)));
    }

    public async Task SetLabelAsync(CommandContext context, Guid tenantId, TenantLabel label, Actor actor, bool removedProd, CancellationToken cancellationToken)
    {
        RequireOwnContext(context, tenantId);
        ArgumentNullException.ThrowIfNull(actor);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = SetLabel;
            Add(command, "label", TenantValues.Stored(label));
            Add(command, "id", tenantId);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // The caller holds the row lock and saw it active: nothing else can have changed it.
                throw new InvalidOperationException("No active Tenant's label was changed.");
            }
        }

        var code = removedProd ? TenancyEvents.ProdLabelRemoved.Code : TenancyEvents.LabelChanged.Code;
        await _appender.AppendAsync(context, new AuditEvent(code, actor, AuditTargetKind.Tenant, tenantId), null, cancellationToken);
    }

    public async Task<TenantDeletionState?> LockForDeletionAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        RequireDeployment(context);

        await using var command = context.CreateCommand();
        command.CommandText = LockForDeletion;
        Add(command, "id", tenantId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new TenantDeletionState(TenantValues.ParseStatus(reader.GetString(0)), reader.IsDBNull(1) ? null : reader.GetString(1));
    }

    public async Task BeginDeletionAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        RequireDeployment(context);

        await using var command = context.CreateCommand();
        command.CommandText = BeginDeletion;
        Add(command, "id", tenantId);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            // The caller holds the row lock and saw it creating or active: nothing else can have changed it.
            throw new InvalidOperationException("No creating or active Tenant was set deleting.");
        }
    }

    public async Task<TenantStatus?> LockStatusAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        RequireOwnScope(context, tenantId);

        await using var command = context.CreateCommand();
        command.CommandText = ShareStatus;
        Add(command, "id", tenantId);
        return await command.ExecuteScalarAsync(cancellationToken) is string status ? TenantValues.ParseStatus(status) : null;
    }

    public async Task<TenantStatus?> LockForPurgeAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        RequireOwnScope(context, tenantId);

        await using var command = context.CreateCommand();
        command.CommandText = PurgeLock;
        Add(command, "id", tenantId);
        return await command.ExecuteScalarAsync(cancellationToken) is string status ? TenantValues.ParseStatus(status) : null;
    }

    public async Task<bool> MarkDeletedAsync(CommandContext context, Guid tenantId, CancellationToken cancellationToken)
    {
        RequireOwnScope(context, tenantId);

        TenantStatus? status;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockStatus;
            Add(command, "id", tenantId);
            status = await command.ExecuteScalarAsync(cancellationToken) is string stored ? TenantValues.ParseStatus(stored) : null;
        }

        switch (status)
        {
            case TenantStatus.Deleted:
                // Repeated: already done, and nothing is written twice.
                return false;

            case TenantStatus.Deleting:
                break;

            default:
                throw new InvalidOperationException("Only a deleting Tenant is marked deleted.");
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = MarkDeleted;
            Add(command, "id", tenantId);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new InvalidOperationException("No deleting Tenant was marked deleted.");
            }
        }

        await _appender.AppendAsync(context, new AuditEvent(TenancyEvents.TenantDeleted.Code, Actor.System, AuditTargetKind.Tenant, tenantId), null, cancellationToken);
        return true;
    }

    private static void RequireDeployment(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("A Tenant's deletion starts in a Deployment context.");
        }
    }

    /// <summary>A deletion's stages and completion read and change the Tenant in its own scope only.</summary>
    private static void RequireOwnScope(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's status is read under lock and marked deleted in its own context.");
        }
    }

    /// <summary>A Tenant's label is read under lock and written in that Tenant's own context only.</summary>
    private static void RequireOwnContext(CommandContext context, Guid tenantId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (tenantId == Guid.Empty || context.TenantId != tenantId)
        {
            throw new InvalidOperationException("A Tenant's label is read and changed in its own context.");
        }
    }

    private static async Task ExecuteAsync(CommandContext context, string sql, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
