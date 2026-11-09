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

    // A family's authorization and its anchored Session, ended or not (Story 2.10).
    private const string SelectFamily =
        """
        SELECT a.id, a.status = 'valid', a.creation_date, s.id, s.user_id, s.amr, s.auth_time
        FROM "authorization" a
        JOIN user_session s ON s.tenant_id = a.tenant_id AND s.id = a.user_session_id
        WHERE a.tenant_id = @tenant_id AND a.id = @id AND a.creation_date IS NOT NULL
        """;

    // OpenIddict's own redemption, committed for a refused refresh (Story 2.10): only a valid refresh token.
    private const string BurnRefreshToken =
        """
        UPDATE token
        SET status = @redeemed, redemption_date = coalesce(redemption_date, @now), concurrency_token = gen_random_uuid()
        WHERE tenant_id = @tenant_id AND id = @id AND type = @type AND status = @valid
        """;

    // OpenIddict's values, as the token store writes them.
    private const string RefreshTokenType = OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.RefreshToken;
    private const string RedeemedStatus = OpenIddict.Abstractions.OpenIddictConstants.Statuses.Redeemed;
    private const string ValidStatus = OpenIddict.Abstractions.OpenIddictConstants.Statuses.Valid;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));
    private readonly SessionRevocation _revocation = new(audit, time);

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

    public async Task<TokenFamily?> FindFamilyAsync(CommandContext context, Guid authorizationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Token Family is read only in a Tenant context.");

        if (authorizationId == Guid.Empty)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = SelectFamily;
        Add(command, "tenant_id", tenantId);
        Add(command, "id", authorizationId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new TokenFamily(
            reader.GetGuid(0),
            reader.GetBoolean(1),
            reader.GetFieldValue<DateTimeOffset>(2),
            reader.GetGuid(3),
            reader.GetGuid(4),
            reader.GetFieldValue<string[]>(5),
            reader.GetFieldValue<DateTimeOffset>(6));
    }

    public async Task<bool> BurnRefreshTokenAsync(CommandContext context, Guid tokenId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A refresh token is burnt only in a Tenant context.");

        await using var command = context.CreateCommand();
        command.CommandText = BurnRefreshToken;
        Add(command, "tenant_id", tenantId);
        Add(command, "id", tokenId);
        Add(command, "type", RefreshTokenType);
        Add(command, "redeemed", RedeemedStatus);
        Add(command, "valid", ValidStatus);
        Add(command, "now", ToMicroseconds(_time.GetUtcNow()));

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public Task<RevocationOutcome> RevokeAccessAsync(
        CommandContext context,
        RevocationScope scope,
        Guid? exceptSessionId,
        RevocationReason reason,
        Actor actor,
        CancellationToken cancellationToken) =>
        _revocation.RevokeAsync(context, scope, exceptSessionId, reason, actor, cancellationToken);

    /// <summary>timestamptz holds microseconds, so what's compared or returned must be what's stored.</summary>
    internal static DateTimeOffset ToMicroseconds(DateTimeOffset value) =>
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
