using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>APIs and their Permissions (Story 3.6, FR-16): Directory owns <c>api</c> and <c>permission</c>.</summary>
internal sealed partial class DirectoryService
{
    public async Task<ApiCreate> CreateApiAsync(CommandContext context, Actor actor, string name, string identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("An API is created only in a Tenant context.");

        if (ApiRules.CheckCreate(name, identifier).Count != 0)
        {
            throw new ArgumentException("The API's name or identifier breaks a rule.", nameof(identifier));
        }

        var now = _time.GetUtcNow();
        var id = Guid.CreateVersion7(now);
        if (!await ApiRows.InsertAsync(context, tenantId, id, name, identifier, now, cancellationToken))
        {
            return new ApiCreate(ApiCreateStatus.IdentifierTaken);
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApiCreated.Code, actor, AuditTargetKind.Api, id),
            detail: null,
            cancellationToken);

        return new ApiCreate(
            ApiCreateStatus.Created,
            new DirectoryApi(id, name, identifier, BuiltIn: false, OfflineAccess: false, Rbac: false, ApplicationLifetimes.Defaults, now));
    }

    public Task<DirectoryApiPage> ListApisPageAsync(CommandContext context, Guid? after, int limit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        return ApiRows.ListPageAsync(context, after, limit, cancellationToken);
    }

    public Task<DirectoryApi?> FindApiAsync(CommandContext context, Guid id, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ApiRows.FindAsync(context, id, locked: false, cancellationToken);
    }

    public async Task<IReadOnlyList<DirectoryPermission>?> ListPermissionsAsync(CommandContext context, Guid apiId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return await ApiRows.FindAsync(context, apiId, locked: false, cancellationToken) is null
            ? null
            : await ApiRows.PermissionsAsync(context, apiId, cancellationToken);
    }

    public async Task<ApiSettingsWrite?> UpdateApiSettingsAsync(
        CommandContext context, Actor actor, Guid id, ApiSettings settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(settings);
        _ = context.TenantId ?? throw new InvalidOperationException("An API is updated only in a Tenant context.");

        if (ApiRules.CheckSettings(settings).Count != 0)
        {
            throw new ArgumentException("A lifetime is outside its limits.", nameof(settings));
        }

        // Decided under the row's lock, on the same row the update then writes.
        if (await ApiRows.FindAsync(context, id, locked: true, cancellationToken) is not { } current)
        {
            return null;
        }

        // Nothing to change: no write and no event.
        if (current.OfflineAccess == settings.OfflineAccess && current.Rbac == settings.Rbac && current.Lifetimes == settings.Lifetimes)
        {
            return new ApiSettingsWrite(current, Changed: false);
        }

        if (await ApiRows.UpdateSettingsAsync(context, id, settings, cancellationToken) is not { } updated)
        {
            return null;
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApiUpdated.Code, actor, AuditTargetKind.Api, id),
            detail: null,
            cancellationToken);

        return new ApiSettingsWrite(updated, Changed: true);
    }

    public async Task<PermissionWrite> AddPermissionAsync(
        CommandContext context, Actor actor, Guid apiId, string value, string description, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Permission is added only in a Tenant context.");

        if (ApiRules.CheckPermission(value, description).Count != 0)
        {
            throw new ArgumentException("The Permission's value or description breaks a rule.", nameof(value));
        }

        // Under the API's row lock, held to the end of the caller's transaction: two adds count in turn.
        if (await ApiRows.FindAsync(context, apiId, locked: true, cancellationToken) is not { } api)
        {
            return new PermissionWrite(PermissionWriteStatus.NotFound);
        }

        if (api.BuiltIn)
        {
            return new PermissionWrite(PermissionWriteStatus.BuiltIn);
        }

        var permissions = await ApiRows.PermissionsAsync(context, apiId, cancellationToken);
        if (permissions.Any(p => string.Equals(p.Value, value, StringComparison.Ordinal)))
        {
            return new PermissionWrite(PermissionWriteStatus.Taken);
        }

        if (permissions.Count >= SecurityLimits.MaxPermissionsPerApi)
        {
            return new PermissionWrite(PermissionWriteStatus.LimitReached);
        }

        if (!await ApiRows.InsertPermissionsAsync(context, tenantId, apiId, [value], [description], _time.GetUtcNow(), cancellationToken))
        {
            return new PermissionWrite(PermissionWriteStatus.Taken);
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApiPermissionAdded.Code, actor, AuditTargetKind.Api, apiId),
            detail: null,
            cancellationToken);

        return new PermissionWrite(PermissionWriteStatus.Done, await ApiRows.PermissionsAsync(context, apiId, cancellationToken));
    }

    public async Task<PermissionWrite> RemovePermissionAsync(
        CommandContext context, Actor actor, Guid apiId, string value, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        _ = context.TenantId ?? throw new InvalidOperationException("A Permission is removed only in a Tenant context.");

        if (await ApiRows.FindAsync(context, apiId, locked: true, cancellationToken) is not { } api)
        {
            return new PermissionWrite(PermissionWriteStatus.NotFound);
        }

        if (api.BuiltIn)
        {
            return new PermissionWrite(PermissionWriteStatus.BuiltIn);
        }

        if (value is null || !await ApiRows.DeletePermissionAsync(context, apiId, value, cancellationToken))
        {
            return new PermissionWrite(PermissionWriteStatus.NotFound);
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ApiPermissionRemoved.Code, actor, AuditTargetKind.Api, apiId),
            detail: null,
            cancellationToken);

        return new PermissionWrite(PermissionWriteStatus.Done, await ApiRows.PermissionsAsync(context, apiId, cancellationToken));
    }

    public async Task<bool> EnsureBuiltInApiAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("The built-in Management API is ensured only in a Tenant context.");

        var now = _time.GetUtcNow();
        var changed = false;
        if (await ApiRows.FindBuiltInAsync(context, cancellationToken) is not { } apiId)
        {
            changed = await ApiRows.InsertBuiltInAsync(context, tenantId, Guid.CreateVersion7(now), now, cancellationToken);
            apiId = await ApiRows.FindBuiltInAsync(context, cancellationToken)
                ?? throw new InvalidOperationException("The Tenant's built-in Management API was neither inserted nor found.");
        }

        // Only the Permissions it lacks, and no insert at all when it lacks none: the row guard fires on every insert
        // attempt, so the hourly backfill of a Tenant whose deletion has since started must not try one.
        var held = await ApiRows.PermissionValuesAsync(context, apiId, cancellationToken);
        var missing = DirectoryContract.ManagementPermissions.Where(value => !held.Contains(value)).ToList();
        if (missing.Count == 0)
        {
            return changed;
        }

        // ON CONFLICT still lets a concurrent ensure that won insert them first.
        changed |= await ApiRows.InsertPermissionsAsync(
            context,
            tenantId,
            apiId,
            missing,
            [.. missing.Select(value => DirectoryContract.ManagementPermissionDescriptions[value])],
            now,
            cancellationToken);
        return changed;
    }
}

/// <summary>Reads and writes <c>api</c> and <c>permission</c> rows (Story 3.6), always in the context Tenant.</summary>
internal static class ApiRows
{
    private const string Columns =
        "id, name, identifier, built_in, offline_access, rbac, "
        + "access_token_lifetime, id_token_lifetime, refresh_token_absolute_lifetime, refresh_token_inactivity_lifetime, created_at";

    // Every other column takes its default: not built in, offline access and RBAC off, the default lifetimes. An
    // identifier the Tenant already has, exactly, inserts nothing.
    private const string Insert =
        """
        INSERT INTO api (tenant_id, id, name, identifier, created_at)
        VALUES (@tenant_id, @id, @name, @identifier, @created_at)
        ON CONFLICT (tenant_id, identifier) DO NOTHING
        """;

    // A concurrent insert that won leaves this one doing nothing, so the caller re-selects the winner.
    private const string InsertBuiltIn =
        """
        INSERT INTO api (tenant_id, id, name, identifier, built_in, created_at)
        VALUES (@tenant_id, @id, @name, @identifier, true, @created_at)
        ON CONFLICT DO NOTHING
        """;

    private const string InsertPermissions =
        """
        INSERT INTO permission (tenant_id, api_id, value, description, created_at)
        SELECT @tenant_id, @api_id, v.value, v.description, @created_at
        FROM unnest(@values::text[], @descriptions::text[]) AS v(value, description)
        ON CONFLICT DO NOTHING
        """;

    private const string DeletePermission =
        "DELETE FROM permission WHERE tenant_id = @tenant_id AND api_id = @api_id AND value = @value";

    private const string Select = $"SELECT {Columns} FROM api WHERE tenant_id = @tenant_id AND id = @id";

    // FOR NO KEY UPDATE, so no permission insert's foreign-key check waits on it.
    private const string SelectLocked = Select + " FOR NO KEY UPDATE";

    private const string SelectBuiltIn = "SELECT id FROM api WHERE tenant_id = @tenant_id AND built_in";

    private const string Permissions =
        "SELECT value, description, created_at FROM permission WHERE tenant_id = @tenant_id AND api_id = @api_id ORDER BY value";

    private const string PermissionValues =
        "SELECT value FROM permission WHERE tenant_id = @tenant_id AND api_id = @api_id";

    // The built-in API first, then the others newest first by the UUIDv7 ID.
    private const string FirstPage =
        $"SELECT {Columns} FROM api WHERE tenant_id = @tenant_id ORDER BY built_in DESC, id DESC LIMIT @limit";

    // Keyset after the previous page's last: when that was the built-in API, every other one follows.
    private const string NextPage =
        $"""
        SELECT {Columns} FROM api
        WHERE tenant_id = @tenant_id AND NOT built_in
          AND (id < @after OR coalesce((SELECT b.built_in FROM api b WHERE b.tenant_id = @tenant_id AND b.id = @after), false))
        ORDER BY id DESC LIMIT @limit
        """;

    private const string UpdateSettings =
        $"""
        UPDATE api
        SET offline_access = @offline_access, rbac = @rbac,
            access_token_lifetime = @access_token_lifetime, id_token_lifetime = @id_token_lifetime,
            refresh_token_absolute_lifetime = @refresh_token_absolute_lifetime,
            refresh_token_inactivity_lifetime = @refresh_token_inactivity_lifetime
        WHERE tenant_id = @tenant_id AND id = @id
        RETURNING {Columns}
        """;

    public static async Task<bool> InsertAsync(
        CommandContext context, Guid tenantId, Guid id, string name, string identifier, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Insert;
        DirectoryService.Add(command, "tenant_id", tenantId);
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "name", name);
        DirectoryService.Add(command, "identifier", identifier);
        DirectoryService.Add(command, "created_at", now);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public static async Task<bool> InsertBuiltInAsync(CommandContext context, Guid tenantId, Guid id, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = InsertBuiltIn;
        DirectoryService.Add(command, "tenant_id", tenantId);
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "name", DirectoryContract.ManagementApiName);
        DirectoryService.Add(command, "identifier", DirectoryContract.ManagementApiIdentifier);
        DirectoryService.Add(command, "created_at", now);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    /// <summary>Inserts each of <paramref name="values"/>, with the description at the same index, that the API lacks. Whether any was inserted.</summary>
    public static async Task<bool> InsertPermissionsAsync(
        CommandContext context,
        Guid tenantId,
        Guid apiId,
        IReadOnlyCollection<string> values,
        IReadOnlyCollection<string> descriptions,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = InsertPermissions;
        DirectoryService.Add(command, "tenant_id", tenantId);
        DirectoryService.Add(command, "api_id", apiId);
        DirectoryService.Add(command, "values", values.ToArray());
        DirectoryService.Add(command, "descriptions", descriptions.ToArray());
        DirectoryService.Add(command, "created_at", now);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public static async Task<bool> DeletePermissionAsync(CommandContext context, Guid apiId, string value, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = DeletePermission;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "api_id", apiId);
        DirectoryService.Add(command, "value", value);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public static async Task<DirectoryApi?> FindAsync(CommandContext context, Guid id, bool locked, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = locked ? SelectLocked : Select;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public static async Task<Guid?> FindBuiltInAsync(CommandContext context, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = SelectBuiltIn;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        return await command.ExecuteScalarAsync(cancellationToken) is Guid id ? id : null;
    }

    /// <summary>The values of the API's Permissions only: all <c>gk_worker</c> may read of them.</summary>
    public static async Task<HashSet<string>> PermissionValuesAsync(CommandContext context, Guid apiId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = PermissionValues;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "api_id", apiId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var values = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken))
        {
            values.Add(reader.GetString(0));
        }

        return values;
    }

    public static async Task<IReadOnlyList<DirectoryPermission>> PermissionsAsync(CommandContext context, Guid apiId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Permissions;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "api_id", apiId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var permissions = new List<DirectoryPermission>();
        while (await reader.ReadAsync(cancellationToken))
        {
            permissions.Add(new DirectoryPermission(reader.GetString(0), reader.GetString(1), reader.GetFieldValue<DateTimeOffset>(2)));
        }

        return permissions;
    }

    public static async Task<DirectoryApiPage> ListPageAsync(CommandContext context, Guid? after, int limit, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = after is null ? FirstPage : NextPage;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        if (after is { } cursor)
        {
            DirectoryService.Add(command, "after", cursor);
        }

        // One more than a page says whether another follows.
        DirectoryService.Add(command, "limit", limit + 1);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var apis = new List<DirectoryApi>();
        while (await reader.ReadAsync(cancellationToken))
        {
            apis.Add(Read(reader));
        }

        if (apis.Count <= limit)
        {
            return new DirectoryApiPage(apis, null);
        }

        var page = apis.Take(limit).ToList();
        return new DirectoryApiPage(page, page[^1].Id);
    }

    public static async Task<DirectoryApi?> UpdateSettingsAsync(CommandContext context, Guid id, ApiSettings settings, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = UpdateSettings;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "offline_access", settings.OfflineAccess);
        DirectoryService.Add(command, "rbac", settings.Rbac);
        DirectoryService.Add(command, "access_token_lifetime", settings.Lifetimes.AccessTokenLifetime);
        DirectoryService.Add(command, "id_token_lifetime", settings.Lifetimes.IdTokenLifetime);
        DirectoryService.Add(command, "refresh_token_absolute_lifetime", settings.Lifetimes.RefreshTokenAbsoluteLifetime);
        DirectoryService.Add(command, "refresh_token_inactivity_lifetime", settings.Lifetimes.RefreshTokenInactivityLifetime);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    private static Guid TenantOf(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.TenantId
            ?? throw new InvalidOperationException("APIs are read only in a Tenant context.");
    }

    private static DirectoryApi Read(DbDataReader reader) =>
        new(
            reader.GetGuid(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetBoolean(3),
            reader.GetBoolean(4),
            reader.GetBoolean(5),
            new ApplicationLifetimes(reader.GetInt32(6), reader.GetInt32(7), reader.GetInt32(8), reader.GetInt32(9)),
            reader.GetFieldValue<DateTimeOffset>(10));
}
