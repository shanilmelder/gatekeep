using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Sessions.Core;

internal sealed class SessionService(IAuditAppender audit, TimeProvider time) : ISessions
{
    private static readonly AuditTypeCode Started = SessionsEvents.SessionStarted.Code;

    private static readonly AuditTypeCode Rotated = SessionsEvents.SessionRotated.Code;

    private const string InsertSession =
        """
        INSERT INTO user_session
          (tenant_id, id, user_id, id_hash, amr, auth_time, connection_id, idle_expires_at, absolute_expires_at, created_at)
        VALUES
          (@tenant_id, @id, @user_id, @id_hash, @amr, @auth_time, @connection_id, @idle_expires_at, @absolute_expires_at, @created_at)
        """;

    // Story 4.2: a live Session of the same User, given a new identifier hash and the new authentication in one
    // statement, so the presented identifier stops working. Its absolute expiry never moves.
    private const string RotateSession =
        """
        UPDATE user_session
        SET id_hash = @id_hash, amr = @amr, auth_time = @auth_time, connection_id = @connection_id,
            idle_expires_at = least(@idle_expires_at, absolute_expires_at)
        WHERE tenant_id = @tenant_id AND id_hash = @presented_hash AND user_id = @user_id
          AND ended_at IS NULL AND idle_expires_at > @now AND absolute_expires_at > @now
        RETURNING id, idle_expires_at, absolute_expires_at
        """;

    private const string SelectLive =
        """
        SELECT id, user_id, amr, auth_time, idle_expires_at, absolute_expires_at
        FROM user_session
        WHERE tenant_id = @tenant_id AND {0}
          AND ended_at IS NULL AND idle_expires_at > @now AND absolute_expires_at > @now
        """;

    // Unaudited (AD-5): a used Session's idle expiry slides, never past its absolute expiry.
    private const string TouchSession =
        """
        UPDATE user_session
        SET idle_expires_at = least(@idle_expires_at, absolute_expires_at)
        WHERE tenant_id = @tenant_id AND id = @id
          AND ended_at IS NULL AND idle_expires_at > @now AND absolute_expires_at > @now
        """;

    // A family's authorization and its anchored Session, ended or not (Story 2.10), the authorization row
    // share-locked until the caller's transaction ends (see ISessions.FindFamilyAsync).
    private const string SelectFamily =
        """
        SELECT a.id, a.status = 'valid', a.creation_date, s.id, s.user_id,
               CASE WHEN a.properties -> @amr_property IS NOT NULL
                    THEN ARRAY(SELECT jsonb_array_elements_text(a.properties -> @amr_property)) ELSE s.amr END,
               coalesce((a.properties ->> @auth_time_property)::timestamptz, s.auth_time)
        FROM "authorization" a
        JOIN user_session s ON s.tenant_id = a.tenant_id AND s.id = a.user_session_id
        WHERE a.tenant_id = @tenant_id AND a.id = @id AND a.creation_date IS NOT NULL
        FOR SHARE OF a
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

    public Task<StartedSession> StartAsync(
        CommandContext context,
        NewSession session,
        CancellationToken cancellationToken) =>
        StartOrRotateAsync(context, session, presented: null, cancellationToken);

    public async Task<StartedSession> StartOrRotateAsync(
        CommandContext context,
        NewSession session,
        Secret<string>? presented,
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
        var (token, hash) = OpaqueValues.New();

        // A presented live Session of the same User is rotated: the same row, a new identifier.
        if (HashOf(presented) is { } presentedHash)
        {
            await using var rotate = context.CreateCommand();
            rotate.CommandText = RotateSession;
            Add(rotate, "tenant_id", tenantId);
            Add(rotate, "presented_hash", presentedHash);
            Add(rotate, "user_id", session.UserId);
            Add(rotate, "id_hash", hash);
            Add(rotate, "amr", session.Amr.ToArray());
            Add(rotate, "auth_time", authTime);
            Add(rotate, "connection_id", session.ConnectionId);
            Add(rotate, "idle_expires_at", idleExpiresAt);
            Add(rotate, "now", now);

            Guid? rotatedId = null;
            DateTimeOffset rotatedIdle = default;
            DateTimeOffset rotatedAbsolute = default;
            await using (var reader = await rotate.ExecuteReaderAsync(cancellationToken))
            {
                if (await reader.ReadAsync(cancellationToken))
                {
                    rotatedId = reader.GetGuid(0);
                    rotatedIdle = reader.GetFieldValue<DateTimeOffset>(1);
                    rotatedAbsolute = reader.GetFieldValue<DateTimeOffset>(2);
                }
            }

            if (rotatedId is { } sessionId)
            {
                await _audit.AppendAsync(
                    context,
                    new AuditEvent(Rotated, Actor.User(session.UserId), AuditTargetKind.User, session.UserId),
                    detail: null,
                    cancellationToken);

                return new StartedSession(sessionId, token, authTime, rotatedIdle, rotatedAbsolute);
            }
        }

        var id = Guid.CreateVersion7(now);
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

    public async Task<LiveSession?> FindLiveAsync(CommandContext context, Secret<string> presented, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(presented);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Session is read only in a Tenant context.");

        return HashOf(presented) is { } hash
            ? await ReadLiveAsync(context, tenantId, "id_hash = @key", hash, cancellationToken)
            : null;
    }

    public async Task<LiveSession?> FindLiveAsync(CommandContext context, Guid sessionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Session is read only in a Tenant context.");

        return sessionId == Guid.Empty ? null : await ReadLiveAsync(context, tenantId, "id = @key", sessionId, cancellationToken);
    }

    public async Task<bool> TouchAsync(CommandContext context, Guid sessionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Session is touched only in a Tenant context.");

        var now = ToMicroseconds(_time.GetUtcNow());
        await using var command = context.CreateCommand();
        command.CommandText = TouchSession;
        Add(command, "tenant_id", tenantId);
        Add(command, "id", sessionId);
        Add(command, "idle_expires_at", now + SecurityLimits.UserSessionIdleDefault);
        Add(command, "now", now);

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    /// <summary>The stored hash of a presented identifier, or null for none or one without an identifier's shape.</summary>
    private static byte[]? HashOf(Secret<string>? presented) =>
        presented?.Use(static v => OpaqueValues.IsWellFormed(v) ? OpaqueValues.Hash(v) : null);

    private async Task<LiveSession?> ReadLiveAsync(CommandContext context, Guid tenantId, string match, object key, CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText = string.Format(System.Globalization.CultureInfo.InvariantCulture, SelectLive, match);
        Add(command, "tenant_id", tenantId);
        Add(command, "key", key);
        Add(command, "now", ToMicroseconds(_time.GetUtcNow()));

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new LiveSession(
            reader.GetGuid(0),
            reader.GetGuid(1),
            reader.GetFieldValue<string[]>(2),
            reader.GetFieldValue<DateTimeOffset>(3),
            reader.GetFieldValue<DateTimeOffset>(4),
            reader.GetFieldValue<DateTimeOffset>(5));
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
        Add(command, "amr_property", SessionsContract.FamilyAmrProperty);
        Add(command, "auth_time_property", SessionsContract.FamilyAuthTimeProperty);

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

    private static void Add(DbCommand command, string name, object? value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value ?? DBNull.Value;
        command.Parameters.Add(parameter);
    }
}
