using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Fresh assertions over <c>admin_fresh_assertion</c> (Story 1.26). A pending challenge and a
/// verified grant are each a row, never updated: a begin inserts the challenge, a take deletes it,
/// a pass inserts the grant and a consume deletes it, each one statement, so single use is the
/// database's own fact. Every time comes from <c>clock_timestamp()</c>.
/// </summary>
internal sealed class FreshAssertionGrants(IAuditAppender appender, IWebAuthnVerifier verifier) : IAdminFreshAssertions
{
    private const int ChallengeBytes = 32;

    private const string SweepExpired = "DELETE FROM admin_fresh_assertion WHERE expires_at <= clock_timestamp()";

    // Only the newest confirmation counts: the Session's pending challenge, and a grant for the same binding.
    private const string DeleteSuperseded =
        """
        DELETE FROM admin_fresh_assertion
        WHERE session_id = @session AND (stage = 'challenge' OR (stage = 'verified' AND binding_hash = @binding))
        """;

    private const string InsertChallenge =
        """
        INSERT INTO admin_fresh_assertion (id, session_id, stage, binding_hash, challenge_sha256, created_at, expires_at)
        SELECT @id, @session, 'challenge', @binding, @challenge, c.t, c.t + @lifetime
        FROM (SELECT clock_timestamp() AS t) AS c
        """;

    // An expired one goes too: whatever was pending is used up by asking.
    private const string TakeChallenge =
        """
        DELETE FROM admin_fresh_assertion
        WHERE session_id = @session AND stage = 'challenge'
        RETURNING challenge_sha256, binding_hash, expires_at > clock_timestamp()
        """;

    private const string InsertGrant =
        """
        INSERT INTO admin_fresh_assertion (id, session_id, stage, binding_hash, credential_id, created_at, expires_at)
        SELECT @id, @session, 'verified', @binding, @credential, c.t, c.t + @lifetime
        FROM (SELECT clock_timestamp() AS t) AS c
        """;

    private const string Consume =
        """
        DELETE FROM admin_fresh_assertion
        WHERE session_id = @session AND stage = 'verified' AND binding_hash = @binding AND expires_at > clock_timestamp()
        RETURNING credential_id
        """;

    // Two begins in one Session take turns, so neither trips the one-challenge index.
    private const string LockSession = "SELECT 1 FROM admin_session WHERE id = @session FOR UPDATE";

    private static readonly AuditTypeCode Verified = AdminsEvents.FreshAssertionVerified.Code;

    private static readonly AuditTypeCode Failed = AdminsEvents.FreshAssertionFailed.Code;

    private static readonly AuditTypeCode Regressed = AdminsEvents.CredentialSignCountRegressed.Code;

    public async Task<WebAuthnRequestOptions> BeginAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        FreshAssertionBinding binding,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(relyingParty);
        ArgumentNullException.ThrowIfNull(binding);

        var bindingHash = binding.Hash;
        var challenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
        foreach (var sql in new[] { LockSession, SweepExpired, DeleteSuperseded, InsertChallenge })
        {
            await using var command = context.CreateCommand();
            command.CommandText = sql;
            if (sql == LockSession)
            {
                AdminSessions.Add(command, "session", session.Id);
            }
            else if (sql != SweepExpired)
            {
                AdminSessions.Add(command, "session", session.Id);
                AdminSessions.Add(command, "binding", bindingHash);
            }

            if (sql == InsertChallenge)
            {
                AdminSessions.Add(command, "id", Guid.CreateVersion7());
                AdminSessions.Add(command, "challenge", SHA256.HashData(challenge));
                AdminSessions.Add(command, "lifetime", SecurityLimits.WebAuthnChallengeLifetime);
            }

            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        return verifier.BeginAssertion(new WebAuthnAssertionBegin(relyingParty, challenge));
    }

    public async Task<FreshAssertionChallenge?> TakeChallengeAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);

        await using var command = context.CreateCommand();
        command.CommandText = TakeChallenge;
        AdminSessions.Add(command, "session", session.Id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var challenge = reader.GetFieldValue<byte[]>(0);
        var binding = reader.GetFieldValue<byte[]>(1);
        return reader.GetBoolean(2) ? new FreshAssertionChallenge(challenge, binding) : null;
    }

    public async Task<FreshAssertionOutcome> FinishAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        FreshAssertionChallenge challenge,
        WebAuthnAssertion assertion,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(relyingParty);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(assertion);

        var check = await AdminAssertions.CheckAsync(
            context, verifier, relyingParty, challenge.ChallengeSha256, assertion, owner: session.AdminId, cancellationToken);
        var actor = Actor.Admin(session.AdminId);
        switch (check.Kind)
        {
            case AssertionCheckKind.Unattributed:
                return FreshAssertionOutcome.Unattributed(check.Refusal ?? WebAuthnRefusal.Invalid);

            case AssertionCheckKind.Regressed:
            case AssertionCheckKind.Failed:
                // The Session's own Admin signed it, so the Actor is known, unlike at sign-in.
                await appender.AppendAsync(
                    context,
                    new AuditEvent(check.Kind == AssertionCheckKind.Regressed ? Regressed : Failed, actor, AuditTargetKind.Admin, session.AdminId),
                    detail: null,
                    cancellationToken);
                return new FreshAssertionOutcome(FreshAssertionStatus.Refused, check.Refusal, Audited: true);
        }

        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertGrant;
            AdminSessions.Add(command, "id", Guid.CreateVersion7());
            AdminSessions.Add(command, "session", session.Id);
            AdminSessions.Add(command, "binding", challenge.BindingHash);
            AdminSessions.Add(command, "credential", check.CredentialRow);
            AdminSessions.Add(command, "lifetime", SecurityLimits.RecentAuthentication);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await appender.AppendAsync(context, new AuditEvent(Verified, actor, AuditTargetKind.Admin, session.AdminId), detail: null, cancellationToken);
        return new FreshAssertionOutcome(FreshAssertionStatus.Verified, null, Audited: true);
    }

    public async Task<Guid?> ConsumeAsync(CommandContext context, AdminSession session, FreshAssertionBinding binding, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(binding);

        await using var command = context.CreateCommand();
        command.CommandText = Consume;
        AdminSessions.Add(command, "session", session.Id);
        AdminSessions.Add(command, "binding", binding.Hash);
        return await command.ExecuteScalarAsync(cancellationToken) is Guid credential ? credential : null;
    }
}
