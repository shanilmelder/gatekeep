using System.Buffers.Text;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Sessions.Core;

internal sealed class SessionService(IAuditAppender audit, TimeProvider time) : ISessions
{
    private static readonly AuditTypeCode Started = SessionsEvents.SessionStarted.Code;

    private const string InsertSession =
        """
        INSERT INTO user_session
          (tenant_id, id, user_id, id_hash, amr, auth_time, connection_id, idle_expires_at, absolute_expires_at, created_at)
        VALUES
          (@tenant_id, @id, @user_id, @id_hash, @amr, @auth_time, @connection_id, @idle_expires_at, @absolute_expires_at, @created_at)
        """;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));

    public async Task<StartedSession> StartAsync(
        CommandContext context,
        NewSession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(session);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Session is started only in a Tenant context.");

        if (session.UserId == Guid.Empty)
        {
            throw new ArgumentException("A Session needs a User.", nameof(session));
        }

        if (session.Amr is null || session.Amr.Count == 0 || session.Amr.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("A Session needs at least one authentication method.", nameof(session));
        }

        // timestamptz holds microseconds, so what's returned must be what's stored.
        var now = ToMicroseconds(_time.GetUtcNow());
        var authTime = ToMicroseconds(session.AuthTime.ToUniversalTime());
        var idleExpiresAt = now + SecurityLimits.UserSessionIdleDefault;
        var absoluteExpiresAt = now + SecurityLimits.UserSessionAbsoluteDefault;
        var id = Guid.CreateVersion7(now);
        var (token, hash) = NewOpaqueValue();

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertSession;
            Add(command, "tenant_id", tenantId);
            Add(command, "id", id);
            Add(command, "user_id", session.UserId);
            Add(command, "id_hash", hash);
            Add(command, "amr", session.Amr.ToArray());
            Add(command, "auth_time", authTime);
            Add(command, "connection_id", session.ConnectionId);
            Add(command, "idle_expires_at", idleExpiresAt);
            Add(command, "absolute_expires_at", absoluteExpiresAt);
            Add(command, "created_at", now);

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await _audit.AppendAsync(
            context,
            new AuditEvent(Started, Actor.User(session.UserId), AuditTargetKind.User, session.UserId),
            detail: null,
            cancellationToken);

        return new StartedSession(id, token, authTime, idleExpiresAt, absoluteExpiresAt);
    }

    private static DateTimeOffset ToMicroseconds(DateTimeOffset value) =>
        new(value.Ticks - (value.Ticks % TimeSpan.TicksPerMicrosecond), value.Offset);

    /// <summary>
    /// 256 random bits as base64url, and the SHA-256 of that text's ASCII bytes, which is all
    /// that's stored. A cookie value is looked up by hashing it the same way.
    /// </summary>
    private static (Secret<string> Value, byte[] Hash) NewOpaqueValue()
    {
        var random = RandomNumberGenerator.GetBytes(32);

        try
        {
            var value = Base64Url.EncodeToString(random);
            return (new Secret<string>(value), SHA256.HashData(Encoding.ASCII.GetBytes(value)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
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
