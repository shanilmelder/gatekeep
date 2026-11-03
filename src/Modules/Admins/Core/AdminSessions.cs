using System.Data.Common;
using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Admin Sessions over <c>admin_session</c> (Story 1.21), with the Admin's credential count
/// (Story 1.22), which decides what the Session may reach. Every time comes from one
/// <c>clock_timestamp()</c> per statement, and the idle expiry never passes the absolute one.
/// </summary>
internal sealed class AdminSessions(IAuditAppender appender) : IAdminSessions
{
    private const string Insert =
        """
        INSERT INTO admin_session (id, id_hash, admin_id, kind, created_at, idle_expires_at, absolute_expires_at)
        SELECT @id, @id_hash, @admin_id, @kind, c.t, least(c.t + @idle, c.t + @absolute), c.t + @absolute
        FROM (SELECT clock_timestamp() AS t) AS c
        """;

    // The row lock keeps an ending and a slide on one Session from crossing.
    private const string Find =
        """
        SELECT s.id, s.admin_id, s.kind, s.ended_at IS NOT NULL,
               c.t >= s.idle_expires_at OR c.t >= s.absolute_expires_at,
               a.deployment_owner,
               (SELECT count(*)::int FROM admin_credential AS c WHERE c.admin_id = s.admin_id)
        FROM admin_session AS s
        JOIN admin AS a ON a.id = s.admin_id
        CROSS JOIN (SELECT clock_timestamp() AS t) AS c
        WHERE s.id_hash = @id_hash
        FOR UPDATE OF s
        """;

    private const string Slide =
        "UPDATE admin_session SET idle_expires_at = least(clock_timestamp() + @idle, absolute_expires_at) WHERE id = @id";

    private const string Expire =
        "UPDATE admin_session SET ended_at = clock_timestamp(), end_reason = 'expired' WHERE id = @id AND ended_at IS NULL";

    private const string SignOut =
        "UPDATE admin_session SET ended_at = clock_timestamp(), end_reason = 'signed_out' WHERE id = @id AND ended_at IS NULL";

    private const string Supersede =
        """
        UPDATE admin_session SET ended_at = clock_timestamp(), end_reason = 'superseded'
        WHERE id_hash = @id_hash AND ended_at IS NULL
          AND idle_expires_at > clock_timestamp() AND absolute_expires_at > clock_timestamp()
        RETURNING admin_id
        """;

    private static readonly AuditTypeCode SignedOut = AdminsEvents.SessionSignedOut.Code;

    private static readonly AuditTypeCode Superseded = AdminsEvents.SessionSuperseded.Code;

    /// <summary>Starts a Session for <paramref name="adminId"/>, in the caller's transaction.</summary>
    public static async Task<AdminSessionGrant> StartAsync(
        CommandContext context,
        Guid adminId,
        AdminSessionKind kind,
        CancellationToken cancellationToken)
    {
        var id = Guid.CreateVersion7();
        var (sessionToken, idHash, csrfToken) = SessionSecrets.Generate();

        await using var command = context.CreateCommand();
        command.CommandText = Insert;
        Add(command, "id", id);
        Add(command, "id_hash", idHash);
        Add(command, "admin_id", adminId);
        Add(command, "kind", KindCode(kind));
        Add(command, "idle", SecurityLimits.AdminSessionIdle);
        Add(command, "absolute", SecurityLimits.AdminSessionAbsolute);
        await command.ExecuteNonQueryAsync(cancellationToken);

        return new AdminSessionGrant(adminId, id, sessionToken, csrfToken);
    }

    public async Task<AdminSession?> AuthenticateAsync(
        CommandContext context,
        Secret<string> sessionToken,
        CancellationToken cancellationToken)
    {
        RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(sessionToken);

        // The ID's bytes give both the hash to look up and the CSRF token to expect.
        var raw = new byte[SessionSecrets.Bytes];
        byte[] idHash;
        byte[] csrf;
        try
        {
            if (!sessionToken.Use(token => SessionSecrets.TryDecode(token, raw)))
            {
                return null;
            }

            idHash = SHA256.HashData(raw);
            csrf = SessionSecrets.DeriveCsrf(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }

        AdminSession session;
        bool ended;
        bool expired;
        await using (var command = context.CreateCommand())
        {
            command.CommandText = Find;
            Add(command, "id_hash", idHash);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            session = new AdminSession(
                reader.GetGuid(0),
                reader.GetGuid(1),
                ParseKind(reader.GetString(2)),
                reader.GetBoolean(5),
                reader.GetInt32(6),
                csrf);
            ended = reader.GetBoolean(3);
            expired = reader.GetBoolean(4);
        }

        if (ended)
        {
            return null;
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = expired ? Expire : Slide;
            Add(command, "id", session.Id);
            if (!expired)
            {
                Add(command, "idle", SecurityLimits.AdminSessionIdle);
            }

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return expired ? null : session;
    }

    public async Task<bool> EndAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken)
    {
        RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        await using (var command = context.CreateCommand())
        {
            command.CommandText = SignOut;
            Add(command, "id", session.Id);
            if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                // Ended already, by another tab or an expiry: nothing happened here to audit.
                return false;
            }
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(SignedOut, Actor.Admin(session.AdminId), AuditTargetKind.Admin, session.AdminId),
            detail: null,
            cancellationToken);
        return true;
    }

    /// <summary>
    /// Ends with <c>superseded</c> the live Session whose ID is <paramref name="sessionToken"/>, if
    /// there is one, and appends <see cref="AdminsEvents.SessionSuperseded"/> for it, in the caller's
    /// transaction: a sign-in by <paramref name="actorAdminId"/> in a browser that holds one replaces
    /// it. A malformed, unknown, ended or expired one changes nothing and audits nothing.
    /// </summary>
    public static async Task SupersedeAsync(
        CommandContext context,
        IAuditAppender appender,
        Secret<string> sessionToken,
        Guid actorAdminId,
        CancellationToken cancellationToken)
    {
        if (SessionSecrets.TryHash(sessionToken) is not { } idHash)
        {
            return;
        }

        await using var command = context.CreateCommand();
        command.CommandText = Supersede;
        Add(command, "id_hash", idHash);
        if (await command.ExecuteScalarAsync(cancellationToken) is not Guid owner)
        {
            return;
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(Superseded, Actor.Admin(actorAdminId), AuditTargetKind.Admin, owner),
            detail: null,
            cancellationToken);
    }

    internal static void RequireDeployment(CommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.TenantId is not null)
        {
            throw new InvalidOperationException("Admins are reached only in a Deployment scope.");
        }
    }

    internal static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    private static string KindCode(AdminSessionKind kind) => kind switch
    {
        AdminSessionKind.Setup => "setup",
        AdminSessionKind.Full => "full",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static AdminSessionKind ParseKind(string code) => code switch
    {
        "setup" => AdminSessionKind.Setup,
        "full" => AdminSessionKind.Full,
        _ => throw new InvalidOperationException("An Admin Session has an unknown kind."),
    };
}
