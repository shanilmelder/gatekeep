using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Your credentials over <c>admin_credential</c> (Story 1.26). A removal locks the Admin's row
/// first, as registration does, so the floor it checks can't move under it; the delete trigger
/// holds the same floor for any other path.
/// </summary>
internal sealed class AdminCredentials(IAuditAppender appender) : IAdminCredentials
{
    private const string List =
        """
        SELECT id, backup_eligible, backed_up, transports, created_at, last_used_at
        FROM admin_credential WHERE admin_id = @admin ORDER BY created_at, id
        """;

    private const string LockAdmin = "SELECT 1 FROM admin WHERE id = @admin FOR UPDATE";

    private const string Find = "SELECT EXISTS (SELECT 1 FROM admin_credential WHERE id = @credential AND admin_id = @admin)";

    private const string DeleteGrants = "DELETE FROM admin_fresh_assertion WHERE credential_id = @credential";

    private const string Delete = "DELETE FROM admin_credential WHERE id = @credential AND admin_id = @admin";

    private static readonly AuditTypeCode Removed = AdminsEvents.CredentialRemoved.Code;

    public async Task<AdminCredentialList> ListAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        var rows = new List<(Guid Id, bool Eligible, bool BackedUp, string[] Transports, DateTimeOffset Created, DateTimeOffset? Used)>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = List;
            AdminSessions.Add(command, "admin", session.AdminId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                rows.Add((
                    reader.GetGuid(0),
                    // Flags not yet known, for a credential stored before they were kept, read as not set.
                    !reader.IsDBNull(1) && reader.GetBoolean(1),
                    !reader.IsDBNull(2) && reader.GetBoolean(2),
                    reader.GetFieldValue<string[]>(3),
                    reader.GetFieldValue<DateTimeOffset>(4),
                    reader.IsDBNull(5) ? null : reader.GetFieldValue<DateTimeOffset>(5)));
            }
        }

        var (_, recoveryCode) = await AdminSessions.FloorAsync(context, session.AdminId, cancellationToken);

        // Removing one must leave the floor: so only with more than two is any one removable.
        var removable = rows.Count > AdminsContract.RequiredCredentials;
        return new AdminCredentialList(
            [.. rows.Select(r => new AdminCredentialSummary(r.Id, Kind(r.Eligible, r.Transports), r.BackedUp, r.Created, r.Used, removable))],
            recoveryCode);
    }

    public async Task<CredentialRemovalStatus> RemoveAsync(
        CommandContext context,
        AdminSession session,
        Guid credentialId,
        Guid? confirmedWith,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        await ExecuteAsync(context, LockAdmin, session.AdminId, null, cancellationToken);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Find;
            AdminSessions.Add(command, "credential", credentialId);
            AdminSessions.Add(command, "admin", session.AdminId);
            if (await command.ExecuteScalarAsync(cancellationToken) is not true)
            {
                // Unknown, or another Admin's: the same answer, and nothing changes.
                return CredentialRemovalStatus.NotFound;
            }
        }

        var (credentials, _) = await AdminSessions.FloorAsync(context, session.AdminId, cancellationToken);
        if (credentials - 1 < AdminsContract.RequiredCredentials)
        {
            return CredentialRemovalStatus.Minimum;
        }

        // Its grants first: each one references it, and none may outlive it.
        await ExecuteAsync(context, DeleteGrants, null, credentialId, cancellationToken);
        await ExecuteAsync(context, Delete, session.AdminId, credentialId, cancellationToken);

        // A removed credential is usually a lost or suspect device, and a Session doesn't record
        // which credential started it: every other Session of the Admin ends. This one just proved
        // itself with a credential that stays.
        // Removed with its own confirmation, it leaves this Session proven by nothing: it ends as well.
        var endsThis = confirmedWith == credentialId;
        await AdminSessions.RevokeAsync(context, appender, session.AdminId, session.AdminId, keep: endsThis ? null : session.Id, cancellationToken);

        await appender.AppendAsync(
            context,
            new AuditEvent(Removed, Actor.Admin(session.AdminId), AuditTargetKind.Admin, session.AdminId),
            detail: null,
            cancellationToken);
        return endsThis ? CredentialRemovalStatus.RemovedSessionEnded : CredentialRemovalStatus.Removed;
    }

    /// <summary>Passkey when backup-eligible or reported internal or hybrid; a security key otherwise.</summary>
    private static AdminCredentialKind Kind(bool backupEligible, string[] transports) =>
        backupEligible || transports.Contains("internal") || transports.Contains("hybrid")
            ? AdminCredentialKind.Passkey
            : AdminCredentialKind.SecurityKey;

    private static async Task ExecuteAsync(CommandContext context, string sql, Guid? adminId, Guid? credentialId, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = sql;
        if (adminId is { } admin)
        {
            AdminSessions.Add(command, "admin", admin);
        }

        if (credentialId is { } credential)
        {
            AdminSessions.Add(command, "credential", credential);
        }

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
