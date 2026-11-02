using System.Data.Common;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Sessions.Core;

/// <summary>
/// The one place that ends a Session or revokes a Token Family or token (AD-13). An
/// architecture test fails if any other file under <c>src/</c> writes those columns or values.
/// Every statement names the context's Tenant as well as relying on row-level security.
/// </summary>
internal sealed class SessionRevocation(IAuditAppender audit, TimeProvider time)
{
    private static readonly AuditTypeCode Revoked = new("sessions.access.revoked");

    private const string EndSessions =
        """
        UPDATE user_session
        SET ended_at = @ended_at, end_reason = @end_reason
        WHERE tenant_id = @tenant_id AND ended_at IS NULL AND ({0})
        """;

    private const string RevokeFamilies =
        """
        UPDATE "authorization"
        SET status = 'revoked', concurrency_token = gen_random_uuid()
        WHERE tenant_id = @tenant_id AND status <> 'revoked' AND ({0})
        """;

    private const string RevokeTokens =
        """
        UPDATE token
        SET status = 'revoked', concurrency_token = gen_random_uuid()
        WHERE tenant_id = @tenant_id AND status <> 'revoked' AND ({0})
        """;

    private readonly IAuditAppender _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    private readonly TimeProvider _time = time ?? throw new ArgumentNullException(nameof(time));

    public async Task<RevocationOutcome> RevokeAsync(
        CommandContext context,
        RevocationScope scope,
        Guid? exceptSessionId,
        RevocationReason reason,
        Actor actor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("Access is revoked only in a Tenant context.");

        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(reason);
        ArgumentNullException.ThrowIfNull(actor);

        if (exceptSessionId is { } except)
        {
            if (scope is not RevocationScope.User)
            {
                throw new ArgumentException("Only a User scope can spare the acting Session.", nameof(exceptSessionId));
            }

            if (except == Guid.Empty)
            {
                throw new ArgumentException("The acting Session ID can't be empty.", nameof(exceptSessionId));
            }
        }

        var filter = Filter.For(scope, exceptSessionId);

        if (filter.Except is not null && !await ActingSessionExistsAsync(context, tenantId, filter, cancellationToken))
        {
            throw new ArgumentException(
                "The acting Session isn't a Session of this User in this Tenant.", nameof(exceptSessionId));
        }

        var endedAt = SessionService.ToMicroseconds(_time.GetUtcNow());

        var sessionsEnded = filter.Sessions is null
            ? 0
            : await ExecuteAsync(context, EndSessions, filter.Sessions, tenantId, filter, cancellationToken, endedAt, reason);
        var familiesRevoked = await ExecuteAsync(context, RevokeFamilies, filter.Families, tenantId, filter, cancellationToken);
        var tokensRevoked = await ExecuteAsync(context, RevokeTokens, filter.Tokens, tenantId, filter, cancellationToken);

        var target = scope is RevocationScope.User user
            ? new AuditEvent(Revoked, actor, AuditTargetKind.User, user.Id)
            : new AuditEvent(Revoked, actor);

        await _audit.AppendAsync(context, target, detail: null, cancellationToken);

        return new RevocationOutcome(sessionsEnded, familiesRevoked, tokensRevoked);
    }

    /// <summary>A wrong acting Session would spare nothing and silently end the one the User is using.</summary>
    private static async Task<bool> ActingSessionExistsAsync(
        CommandContext context,
        Guid tenantId,
        Filter filter,
        CancellationToken cancellationToken)
    {
        await using var command = context.CreateCommand();
        command.CommandText =
            "SELECT EXISTS (SELECT 1 FROM user_session WHERE tenant_id = @tenant_id AND id = @except AND user_id = @id)";
        Add(command, "tenant_id", tenantId);
        Add(command, "id", filter.Id!.Value);
        Add(command, "except", filter.Except!.Value);

        return (bool)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private static async Task<int> ExecuteAsync(
        CommandContext context,
        string template,
        string condition,
        Guid tenantId,
        Filter filter,
        CancellationToken cancellationToken,
        DateTimeOffset? endedAt = null,
        RevocationReason? reason = null)
    {
        await using var command = context.CreateCommand();
        command.CommandText = string.Format(System.Globalization.CultureInfo.InvariantCulture, template, condition);
        Add(command, "tenant_id", tenantId);

        if (filter.Id is { } id)
        {
            Add(command, "id", id);
        }

        if (filter.Except is { } except)
        {
            Add(command, "except", except);
        }

        if (endedAt is { } at)
        {
            Add(command, "ended_at", at);
            Add(command, "end_reason", reason!.Code);
        }

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void Add(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    /// <summary>
    /// Each scope as three fixed WHERE conditions over <c>@id</c> and <c>@except</c>. No caller
    /// text reaches the SQL: the conditions are constants and the IDs are parameters.
    /// <see cref="Sessions"/> is null when the scope ends no Session.
    /// </summary>
    private sealed record Filter(Guid? Id, Guid? Except, string? Sessions, string Families, string Tokens)
    {
        private const string UserSessions =
            "SELECT s.id FROM user_session s WHERE s.tenant_id = @tenant_id AND s.user_id = @id";

        private const string UserSessionsExcept = UserSessions + " AND s.id <> @except";

        private const string FamilyTokens =
            "authorization_id IN (SELECT a.id FROM \"authorization\" a WHERE a.tenant_id = @tenant_id AND {0})";

        public static Filter For(RevocationScope scope, Guid? except) => scope switch
        {
            RevocationScope.Authorization a => new Filter(
                a.Id, null, null, "id = @id", "authorization_id = @id"),
            RevocationScope.Session s => new Filter(
                s.Id, null, "id = @id", "user_session_id = @id", OfFamilies("a.user_session_id = @id")),
            RevocationScope.User u when except is null => new Filter(
                u.Id,
                null,
                "user_id = @id",
                $"user_session_id IN ({UserSessions})",
                OfFamilies($"a.user_session_id IN ({UserSessions})")),
            RevocationScope.User u => new Filter(
                u.Id,
                except,
                "user_id = @id AND id <> @except",
                $"user_session_id IN ({UserSessionsExcept})",
                OfFamilies($"a.user_session_id IN ({UserSessionsExcept})")),
            RevocationScope.Application p => new Filter(
                p.Id, null, null, "application_id = @id", "application_id = @id OR " + OfFamilies("a.application_id = @id")),
            RevocationScope.Tenant => new Filter(null, null, "true", "true", "true"),
            _ => throw new ArgumentException("Unknown revocation scope.", nameof(scope)),
        };

        private static string OfFamilies(string familyCondition) =>
            string.Format(System.Globalization.CultureInfo.InvariantCulture, FamilyTokens, familyCondition);
    }
}
