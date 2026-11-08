using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// <c>gatekeep recover-admin</c>'s enrolments over <c>admin_enrolment</c> (Story 1.32), issued as
/// <c>gk_cli</c>. The value exists only in the Cli's memory and the link it prints; the table holds
/// its SHA-256. The issue and expiry times come from the database clock, read before the Security
/// Alert and the off-server record are sent, so both name exactly the times the row holds.
/// </summary>
internal sealed class EnrolmentIssuer(IAuditAppender appender) : IAdminEnrolmentIssuer
{
    private const string ReadAdmins = "SELECT id FROM admin ORDER BY created_at, id";

    private const string ReadNow = "SELECT clock_timestamp()";

    // The trigger refuses an issue time later than now or a lifetime ago, and the CHECK any other expiry.
    private const string Insert =
        """
        INSERT INTO admin_enrolment (id, admin_id, value_sha256, created_at, expires_at)
        VALUES (@id, @admin, @hash, @created, @expires)
        """;

    private static readonly AuditTypeCode Issued = AdminsEvents.EnrolmentIssued.Code;

    public async Task<EnrolmentCandidates> ReadAsync(CommandContext context, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);

        var admins = new List<EnrolmentCandidate>();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReadAdmins;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var id = reader.GetGuid(0);
                admins.Add(new EnrolmentCandidate(id, PublicId.Format(PublicIdType.Admin, id)));
            }
        }

        DateTimeOffset now;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = ReadNow;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new InvalidOperationException("The clock query returned no row.");
            }

            now = reader.GetFieldValue<DateTimeOffset>(0);
        }

        return new EnrolmentCandidates(admins, now);
    }

    public AdminEnrolment Plan(Guid adminId, DateTimeOffset issuedAt)
    {
        if (adminId == Guid.Empty)
        {
            throw new ArgumentException("An empty ID names no Admin.", nameof(adminId));
        }

        // PostgreSQL keeps microseconds: the times sent out are exactly the times stored.
        var issued = new DateTimeOffset(issuedAt.UtcTicks - (issuedAt.UtcTicks % 10), TimeSpan.Zero);
        return new AdminEnrolment(Guid.CreateVersion7(issued), adminId, issued, issued + SecurityLimits.AdminEnrolmentLifetime);
    }

    public async Task IssueAsync(CommandContext context, AdminEnrolment enrolment, Secret<string> value, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(enrolment);
        ArgumentNullException.ThrowIfNull(value);

        var hash = value.Use(AdminEnrolmentValue.Hash)
            ?? throw new ArgumentException($"An enrolment value is {AdminEnrolmentValue.Length} base64url characters.", nameof(value));

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Insert;
            AdminSessions.Add(command, "id", enrolment.Id);
            AdminSessions.Add(command, "admin", enrolment.AdminId);
            AdminSessions.Add(command, "hash", hash);
            AdminSessions.Add(command, "created", enrolment.IssuedAt);
            AdminSessions.Add(command, "expires", enrolment.ExpiresAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(Issued, Actor.System, AuditTargetKind.Admin, enrolment.AdminId),
            detail: null,
            cancellationToken);
    }
}

/// <summary>
/// Redeems <c>recover-admin</c> enrolments as <c>gk_admin</c> (Story 1.32), as
/// <see cref="AdminRecoveryCodes"/> redeems a code: the value's SHA-256 finds an unused, live row,
/// locked, which is used up; every Session of its Admin ends; a restricted Session starts.
/// </summary>
internal sealed class AdminEnrolments(IAuditAppender appender) : IAdminEnrolments
{
    private const string Find =
        """
        SELECT id, admin_id FROM admin_enrolment
        WHERE value_sha256 = @hash AND used_at IS NULL AND expires_at > clock_timestamp()
        FOR UPDATE
        """;

    private const string Use = "UPDATE admin_enrolment SET used_at = clock_timestamp() WHERE id = @id AND used_at IS NULL";

    private const string UseOthers = "UPDATE admin_enrolment SET used_at = clock_timestamp() WHERE admin_id = @admin AND used_at IS NULL";

    private static readonly AuditTypeCode Used = AdminsEvents.EnrolmentUsed.Code;

    public async Task<EnrolmentRedemption?> RedeemAsync(
        CommandContext context,
        Secret<string> value,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(value);

        if (value.Use(AdminEnrolmentValue.Hash) is not { } hash)
        {
            return null;
        }

        Guid enrolmentId;
        Guid adminId;
        try
        {
            await using var command = context.CreateCommand();
            command.CommandText = Find;
            AdminSessions.Add(command, "hash", hash);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                // Unknown, used or expired: the same refusal, and nothing written.
                return null;
            }

            enrolmentId = reader.GetGuid(0);
            adminId = reader.GetGuid(1);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = Use;
            AdminSessions.Add(command, "id", enrolmentId);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                return null;
            }
        }

        // Recovery is done once: a leftover link from an earlier run of recover-admin for this Admin
        // is used up too, so it can't run it again.
        await using (var command = context.CreateCommand())
        {
            command.CommandText = UseOthers;
            AdminSessions.Add(command, "admin", adminId);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        // Whoever held this Admin's Sessions may hold what was lost: every one of them ends.
        await AdminSessions.RevokeAsync(context, appender, adminId, adminId, keep: null, cancellationToken);
        if (presentedSession is not null)
        {
            await AdminSessions.SupersedeAsync(context, appender, presentedSession, adminId, cancellationToken);
        }

        // Below the floor, as a first Admin who lost their setup Session is, setup asks for two
        // credentials; at it, recovery asks for one fresh one. WebAuthn stays the only way in.
        var (credentials, recoveryCode) = await AdminSessions.FloorAsync(context, adminId, cancellationToken);
        var setupComplete = AdminSession.MeetsFloor(credentials, recoveryCode);
        var kind = setupComplete ? AdminSessionKind.Recovery : AdminSessionKind.Setup;
        var session = await AdminSessions.StartAsync(context, adminId, kind, cancellationToken);

        await appender.AppendAsync(
            context,
            new AuditEvent(Used, Actor.Admin(adminId), AuditTargetKind.Admin, adminId),
            detail: null,
            cancellationToken);
        return new EnrolmentRedemption(session, setupComplete);
    }
}
