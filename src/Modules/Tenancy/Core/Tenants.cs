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
        WHERE @after::uuid IS NULL
           OR (t.created_at, t.id) > (SELECT a.created_at, a.id FROM tenant a WHERE a.id = @after)
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
