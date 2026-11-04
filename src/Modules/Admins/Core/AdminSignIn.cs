using System.Security.Cryptography;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// Admin sign-in over <c>admin_signin_challenge</c>, <c>admin_credential</c>, <c>admin</c> and
/// <c>admin_session</c> (Story 1.23), and nothing else: no Identity, Authentication or Sessions
/// table. A pending challenge is a row holding only its SHA-256 and its binding cookie's, with an
/// expiry from the database clock; taking it deletes it, in a transaction of its own, so it never
/// verifies twice. The credential's row and its Admin's are locked for the finish, so sign-ins
/// with one credential run one at a time, and the counter moves only by a compare-and-set on the
/// value that was verified. Only a refusal after the signature verified is audited: before it, the
/// response proves nothing about who sent it, and anyone with a credential ID could write events
/// against a chosen Admin.
/// </summary>
internal sealed class AdminSignIn(IAuditAppender appender, IWebAuthnVerifier verifier) : IAdminSignIn
{
    private const int ChallengeBytes = 32;

    private const string SweepExpired = "DELETE FROM admin_signin_challenge WHERE expires_at <= clock_timestamp()";

    private const string DeleteBinding = "DELETE FROM admin_signin_challenge WHERE binding_hash = @binding";

    private const string InsertChallenge =
        """
        INSERT INTO admin_signin_challenge (id, binding_hash, challenge_sha256, created_at, expires_at)
        SELECT @id, @binding, @challenge, c.t, c.t + @lifetime
        FROM (SELECT clock_timestamp() AS t) AS c
        """;

    // An expired row goes too: whatever the binding named is used up by asking.
    private const string TakeChallenge =
        """
        DELETE FROM admin_signin_challenge
        WHERE binding_hash = @binding
        RETURNING challenge_sha256, expires_at > clock_timestamp()
        """;

    private static readonly AuditTypeCode Succeeded = AdminsEvents.SignInSucceeded.Code;

    private static readonly AuditTypeCode Failed = AdminsEvents.SignInFailed.Code;

    private static readonly AuditTypeCode Regressed = AdminsEvents.CredentialSignCountRegressed.Code;

    public async Task<AdminSignInStart> BeginAsync(
        CommandContext context,
        WebAuthnRelyingParty relyingParty,
        Secret<string>? presentedBinding,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(relyingParty);

        // Bounded by the sweep: the table holds at most 5 minutes of begins.
        await using (var command = context.CreateCommand())
        {
            command.CommandText = SweepExpired;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        if (SessionSecrets.TryHash(presentedBinding) is { } presented)
        {
            await using var command = context.CreateCommand();
            command.CommandText = DeleteBinding;
            AdminSessions.Add(command, "binding", presented);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var challenge = RandomNumberGenerator.GetBytes(ChallengeBytes);
        var (binding, bindingHash) = SessionSecrets.GenerateValue();
        await using (var command = context.CreateCommand())
        {
            command.CommandText = InsertChallenge;
            AdminSessions.Add(command, "id", Guid.CreateVersion7());
            AdminSessions.Add(command, "binding", bindingHash);
            AdminSessions.Add(command, "challenge", SHA256.HashData(challenge));
            AdminSessions.Add(command, "lifetime", SecurityLimits.WebAuthnChallengeLifetime);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var options = verifier.BeginAssertion(new WebAuthnAssertionBegin(relyingParty, challenge));
        return new AdminSignInStart(options, binding);
    }

    public async Task<byte[]?> TakeChallengeAsync(CommandContext context, Secret<string>? binding, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        if (SessionSecrets.TryHash(binding) is not { } bindingHash)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = TakeChallenge;
        AdminSessions.Add(command, "binding", bindingHash);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var hash = reader.GetFieldValue<byte[]>(0);
        return reader.GetBoolean(1) ? hash : null;
    }

    public async Task<AdminSignInOutcome> FinishAsync(
        CommandContext context,
        WebAuthnRelyingParty relyingParty,
        byte[] challengeSha256,
        WebAuthnAssertion assertion,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(relyingParty);
        ArgumentNullException.ThrowIfNull(challengeSha256);
        ArgumentNullException.ThrowIfNull(assertion);

        var check = await AdminAssertions.CheckAsync(context, verifier, relyingParty, challengeSha256, assertion, owner: null, cancellationToken);
        switch (check.Kind)
        {
            case AssertionCheckKind.Unattributed:
                // Nothing proves the credential's holder sent it, so it is logged, not audited.
                return AdminSignInOutcome.Unattributed(check.Refusal ?? WebAuthnRefusal.Invalid);

            case AssertionCheckKind.Regressed:
            case AssertionCheckKind.Failed:
                // The holder's own signature: a possible clone, or the compare-and-set's miss.
                await AppendRefusalAsync(context, check.Kind == AssertionCheckKind.Regressed ? Regressed : Failed, check.AdminId, cancellationToken);
                return new AdminSignInOutcome(AdminSignInStatus.Refused, null, false, check.Refusal, Audited: true);
        }

        var adminId = check.AdminId;

        // One browser holds one live Admin Session: the one it presented is replaced.
        if (presentedSession is not null)
        {
            await AdminSessions.SupersedeAsync(context, appender, presentedSession, adminId, cancellationToken);
        }

        var session = await AdminSessions.StartAsync(context, adminId, AdminSessionKind.Full, cancellationToken);

        var (credentials, recoveryCode) = await AdminSessions.FloorAsync(context, adminId, cancellationToken);

        await appender.AppendAsync(
            context,
            new AuditEvent(Succeeded, Actor.Admin(adminId), AuditTargetKind.Admin, adminId),
            detail: null,
            cancellationToken);

        return new AdminSignInOutcome(
            AdminSignInStatus.SignedIn,
            session,
            AdminSession.MeetsFloor(credentials, recoveryCode),
            null,
            Audited: true);
    }

    private Task AppendRefusalAsync(CommandContext context, AuditTypeCode code, Guid adminId, CancellationToken cancellationToken) =>
        appender.AppendAsync(context, new AuditEvent(code, Actor.Anonymous, AuditTargetKind.Admin, adminId), detail: null, cancellationToken);
}
