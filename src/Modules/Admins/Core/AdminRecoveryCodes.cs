using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Admin Recovery Codes over <c>admin_recovery_code</c> (Story 1.26). The code exists only in
/// memory, in the issue's one response; the table holds its HMAC under the Deployment
/// <c>hmac</c> key, with domain separation, so the code alone finds its row with one keyed lookup.
/// Issuing and confirming lock the Admin's row, as registration does.
/// </summary>
internal sealed class AdminRecoveryCodes(IAuditAppender appender, IKeyCustody custody) : IAdminRecoveryCodes
{
    private static readonly KeyName HmacKey = KeyName.ForDeployment(DeploymentKeyClass.Hmac);

    private static ReadOnlySpan<byte> Label => "gatekeep-admin-recovery-code\0"u8;

    private const string LockAdmin = "SELECT deployment_owner FROM admin WHERE id = @admin FOR UPDATE";

    private const string DeleteUnconfirmed = "DELETE FROM admin_recovery_code WHERE admin_id = @admin AND confirmed_at IS NULL";

    private const string Insert =
        """
        INSERT INTO admin_recovery_code (id, admin_id, code_hmac, hmac_key_version, created_at)
        VALUES (@id, @admin, @hmac, @version, clock_timestamp())
        """;

    private const string Confirm =
        """
        UPDATE admin_recovery_code SET confirmed_at = clock_timestamp()
        WHERE id = @id AND admin_id = @admin AND confirmed_at IS NULL AND used_at IS NULL
        """;

    private const string Use =
        """
        UPDATE admin_recovery_code SET used_at = clock_timestamp()
        WHERE code_hmac = @hmac AND confirmed_at IS NOT NULL AND used_at IS NULL
        RETURNING admin_id
        """;

    private static readonly AuditTypeCode Issued = AdminsEvents.RecoveryCodeIssued.Code;

    private static readonly AuditTypeCode Used = AdminsEvents.RecoveryCodeUsed.Code;

    public async Task<RecoveryCodeIssue> IssueAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        if (!await AllowedAsync(context, session, cancellationToken))
        {
            return new RecoveryCodeIssue(RecoveryCodeStatus.Refused, null);
        }

        var code = RandomNumberGenerator.GetString(AdminRecoveryCode.Alphabet, AdminRecoveryCode.Length);

        // Custody first: if it fails, nothing is written and the caller rolls back.
        var hmac = await HmacAsync(code, cancellationToken);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = DeleteUnconfirmed;
            AdminSessions.Add(command, "admin", session.AdminId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var issueId = Guid.CreateVersion7();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Insert;
            AdminSessions.Add(command, "id", issueId);
            AdminSessions.Add(command, "admin", session.AdminId);
            AdminSessions.Add(command, "hmac", hmac.Value);
            AdminSessions.Add(command, "version", hmac.KeyVersion);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return new RecoveryCodeIssue(RecoveryCodeStatus.Accepted, new Secret<string>(AdminRecoveryCode.Display(code)), issueId);
    }

    public async Task<RecoveryCodeStatus> ConfirmAsync(CommandContext context, AdminSession session, Guid issueId, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        if (!await AllowedAsync(context, session, cancellationToken))
        {
            return RecoveryCodeStatus.Refused;
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Confirm;
            AdminSessions.Add(command, "id", issueId);
            AdminSessions.Add(command, "admin", session.AdminId);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // Not the code on this screen: a later issue replaced it, or it was never this Admin's.
                return RecoveryCodeStatus.Superseded;
            }
        }

        var actor = Actor.Admin(session.AdminId);
        await appender.AppendAsync(context, new AuditEvent(Issued, actor, AuditTargetKind.Admin, session.AdminId), detail: null, cancellationToken);

        // One credential and a confirmed code: the floor, reached here and not before.
        await AdminSessions.MeetFloorAsync(context, appender, session.AdminId, metBefore: false, cancellationToken);
        return RecoveryCodeStatus.Accepted;
    }

    public async Task<RecoveryCodeRedemption?> RedeemAsync(
        CommandContext context,
        Secret<string> code,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(code);

        if (code.Use(AdminRecoveryCode.Normalize) is not { } normalized)
        {
            return null;
        }

        var hmac = await HmacAsync(normalized, cancellationToken);

        Guid adminId;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Use;
            AdminSessions.Add(command, "hmac", hmac.Value);
            if (await command.ExecuteScalarAsync(cancellationToken) is not Guid owner)
            {
                // Wrong, unconfirmed or used: the same refusal, and nothing written.
                return null;
            }

            adminId = owner;
        }

        // Whoever held this Admin's Sessions may hold the lost device: every one of them ends.
        await AdminSessions.RevokeAsync(context, appender, adminId, adminId, keep: null, cancellationToken);
        if (presentedSession is not null)
        {
            await AdminSessions.SupersedeAsync(context, appender, presentedSession, adminId, cancellationToken);
        }

        var session = await AdminSessions.StartAsync(context, adminId, AdminSessionKind.Recovery, cancellationToken);
        var (credentials, recoveryCode) = await AdminSessions.FloorAsync(context, adminId, cancellationToken);
        await appender.AppendAsync(
            context,
            new AuditEvent(Used, Actor.Admin(adminId), AuditTargetKind.Admin, adminId),
            detail: null,
            cancellationToken);
        return new RecoveryCodeRedemption(session, AdminSession.MeetsFloor(credentials, recoveryCode));
    }

    /// <summary>
    /// Whether the Session may still take or confirm a code, read under the Admin's row lock: a
    /// setup Session of an Admin who isn't the Owner, with exactly one credential and no confirmed,
    /// unused code.
    /// </summary>
    private static async Task<bool> AllowedAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken)
    {
        if (session.Kind != AdminSessionKind.Setup)
        {
            return false;
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = LockAdmin;
            AdminSessions.Add(command, "admin", session.AdminId);
            if (await command.ExecuteScalarAsync(cancellationToken) is not false)
            {
                // The Deployment Owner registers two credentials (FR-2), or the row is gone.
                return false;
            }
        }

        var (credentials, recoveryCode) = await AdminSessions.FloorAsync(context, session.AdminId, cancellationToken);
        return credentials == 1 && !recoveryCode;
    }

    /// <summary>The stored form of a normalized code: its HMAC under the Deployment hmac key, with domain separation.</summary>
    private async Task<KeyHmac> HmacAsync(string normalized, CancellationToken cancellationToken)
    {
        var input = new byte[Label.Length + Encoding.ASCII.GetByteCount(normalized)];
        try
        {
            Label.CopyTo(input);
            Encoding.ASCII.GetBytes(normalized, input.AsSpan(Label.Length));
            return await custody.HmacAsync(HmacKey, new Secret<byte[]>(input), cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
