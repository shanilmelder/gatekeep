using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>A Tenant's database Connection (Story 4.6, FR-17, FR-18): Directory owns <c>connection</c>.</summary>
internal sealed partial class DirectoryService
{
    public async Task<bool> EnsureDatabaseConnectionAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("The database Connection is ensured only in a Tenant context.");

        // Read first, and no insert at all when it exists: the row guard fires on every insert attempt, so the hourly
        // backfill of a Tenant whose deletion has since started must not try one.
        if (await ConnectionRows.FindIdAsync(context, cancellationToken) is not null)
        {
            return false;
        }

        // ON CONFLICT still lets a concurrent ensure that won insert it first.
        return await ConnectionRows.InsertAsync(context, tenantId, Guid.CreateVersion7(_time.GetUtcNow()), cancellationToken);
    }

    public Task<DatabaseConnection?> FindDatabaseConnectionAsync(CommandContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ConnectionRows.FindAsync(context, locked: false, cancellationToken);
    }

    public async Task<ConnectionWrite> UpdateDatabaseConnectionSettingsAsync(
        CommandContext context, Actor actor, bool signupEnabled, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("The database Connection is changed only in a Tenant context.");

        // Decided under the row's lock, on the same row the update then writes.
        if (await ConnectionRows.FindAsync(context, locked: true, cancellationToken) is not { } current)
        {
            return new ConnectionWrite(ConnectionWriteStatus.NotFound, null);
        }

        if (current.SignupEnabled == signupEnabled)
        {
            return new ConnectionWrite(ConnectionWriteStatus.Unchanged, current);
        }

        var updated = await ConnectionRows.UpdateSignupAsync(context, current.Id, signupEnabled, cancellationToken)
            ?? throw new InvalidOperationException("The locked database Connection wasn't updated.");

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ConnectionUpdated.Code, actor, AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);
        return new ConnectionWrite(ConnectionWriteStatus.Saved, updated);
    }

    public async Task<ConnectionWrite> UpdatePasswordPolicyAsync(
        CommandContext context, Actor actor, PasswordPolicy policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(policy);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("The password policy is changed only in a Tenant context.");

        if (!PasswordPolicyRules.Valid(policy))
        {
            throw new ArgumentException("The password policy breaks a rule.", nameof(policy));
        }

        if (await ConnectionRows.FindAsync(context, locked: true, cancellationToken) is not { } current)
        {
            return new ConnectionWrite(ConnectionWriteStatus.NotFound, null);
        }

        if (current.Policy == policy)
        {
            return new ConnectionWrite(ConnectionWriteStatus.Unchanged, current);
        }

        var updated = await ConnectionRows.UpdatePolicyAsync(context, current.Id, policy, cancellationToken)
            ?? throw new InvalidOperationException("The locked database Connection wasn't updated.");

        await _audit.AppendAsync(
            context,
            new AuditEvent(DirectoryEvents.ConnectionPasswordPolicyUpdated.Code, actor, AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);
        return new ConnectionWrite(ConnectionWriteStatus.Saved, updated);
    }
}

/// <summary>Reads and writes <c>connection</c> rows (Story 4.6), always in the context Tenant.</summary>
internal static class ConnectionRows
{
    private const string Columns =
        "id, name, enabled, signup_enabled, password_min_length, password_strength, password_history_count, "
        + "password_dictionary, password_personal_data, updated_at";

    // Every other column takes its default, which a test holds equal to Directory's defaults.
    private const string Insert =
        """
        INSERT INTO connection (tenant_id, id, kind, name)
        VALUES (@tenant_id, @id, @kind, @name)
        ON CONFLICT DO NOTHING
        """;

    private const string SelectId = "SELECT id FROM connection WHERE tenant_id = @tenant_id AND kind = @kind";

    private const string Select = $"SELECT {Columns} FROM connection WHERE tenant_id = @tenant_id AND kind = @kind";

    // NO KEY UPDATE: nothing references the row, and gk_admin's column UPDATE is enough to take it.
    private const string SelectLocked = Select + " FOR NO KEY UPDATE";

    private const string UpdateSignup =
        $"""
        UPDATE connection SET signup_enabled = @signup_enabled, updated_at = now()
        WHERE tenant_id = @tenant_id AND id = @id
        RETURNING {Columns}
        """;

    private const string UpdatePolicy =
        $"""
        UPDATE connection
        SET password_min_length = @min_length, password_strength = @strength, password_history_count = @history_count,
            password_dictionary = @dictionary, password_personal_data = @personal_data, updated_at = now()
        WHERE tenant_id = @tenant_id AND id = @id
        RETURNING {Columns}
        """;

    public static async Task<bool> InsertAsync(CommandContext context, Guid tenantId, Guid id, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = Insert;
        DirectoryService.Add(command, "tenant_id", tenantId);
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "kind", DirectoryContract.DatabaseConnectionKind);
        DirectoryService.Add(command, "name", DirectoryContract.DatabaseConnectionName);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public static async Task<Guid?> FindIdAsync(CommandContext context, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = SelectId;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "kind", DirectoryContract.DatabaseConnectionKind);
        return await command.ExecuteScalarAsync(cancellationToken) is Guid id ? id : null;
    }

    public static async Task<DatabaseConnection?> FindAsync(CommandContext context, bool locked, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = locked ? SelectLocked : Select;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "kind", DirectoryContract.DatabaseConnectionKind);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public static async Task<DatabaseConnection?> UpdateSignupAsync(CommandContext context, Guid id, bool signupEnabled, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = UpdateSignup;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "signup_enabled", signupEnabled);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    public static async Task<DatabaseConnection?> UpdatePolicyAsync(CommandContext context, Guid id, PasswordPolicy policy, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = UpdatePolicy;
        DirectoryService.Add(command, "tenant_id", TenantOf(context));
        DirectoryService.Add(command, "id", id);
        DirectoryService.Add(command, "min_length", policy.MinLength);
        DirectoryService.Add(command, "strength", policy.Strength);
        DirectoryService.Add(command, "history_count", policy.HistoryCount);
        DirectoryService.Add(command, "dictionary", policy.Dictionary);
        DirectoryService.Add(command, "personal_data", policy.PersonalData);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    private static Guid TenantOf(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.TenantId
            ?? throw new InvalidOperationException("A database Connection is read only in a Tenant context.");
    }

    private static DatabaseConnection Read(DbDataReader reader) =>
        new(
            reader.GetGuid(0),
            reader.GetString(1),
            reader.GetBoolean(2),
            reader.GetBoolean(3),
            new PasswordPolicy(reader.GetInt32(4), reader.GetString(5), reader.GetInt32(6), reader.GetBoolean(7), reader.GetBoolean(8)),
            reader.GetFieldValue<DateTimeOffset>(9));
}
