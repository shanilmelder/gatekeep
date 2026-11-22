using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>
/// A reset link's page as Hosted Login shows it (Story 4.11): whether the link can be used now (never while the database
/// Connection isn't enabled), the password policy the strength meter checks in the browser, the database Connection's or the
/// defaults, and for a usable link its User's email, for password managers' username field.
/// </summary>
public sealed record ResetLinkState(bool Usable, int MinLength, string Strength, string? Email = null);

/// <summary>How "Reset password" ended (Story 4.11).</summary>
public enum PasswordResetStatus
{
    /// <summary>The link is malformed, another Tenant's, unknown, expired, used, superseded or its credential no longer active: nothing written.</summary>
    Unusable,

    /// <summary>The confirmation isn't the new password: nothing written.</summary>
    Mismatch,

    /// <summary>The new password failed the policy, history included: <see cref="PasswordResetResult.FailedRules"/> names each rule. Nothing written.</summary>
    RuleFailed,

    /// <summary>No hashing slot came free in time: nothing written.</summary>
    Unavailable,

    /// <summary>The password was replaced, every Session and Token Family of the User ended, and a security notice queued. No Session started.</summary>
    Reset,
}

/// <summary>
/// "Reset password"'s result (Story 4.11): its status, any failed rules, and whether the browser's own sign-in transaction,
/// at the neutral confirmation, went back to Login (so Password changed offers "Log in").
/// </summary>
public sealed record PasswordResetResult(PasswordResetStatus Status, IReadOnlyList<string> FailedRules, bool ContinueToLogin = false);

/// <summary>
/// Password reset through Hosted Login (Story 4.11, FR-19, FR-48, NFR-6, NFR-20), each call one command in the caller's
/// Tenant context and transaction, with its audit events and any email job. A request answers alike for every address and
/// does the same work for each. A completed reset never starts a Session: it ends every Session and Token Family of the
/// User through the one revocation path, and notifies the User.
/// </summary>
public interface IPasswordReset
{
    /// <summary>
    /// "Forgot password?" (Story 4.11): moves a transaction at the Password step (<see cref="SignInSteps.Identifier"/>
    /// only) to Forgot password, recording <see cref="SignInSteps.Reset"/>, the step version incremented and the life slid,
    /// with <c>authentication.signin_transaction.extended</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at the Password step. Nothing is kept.</exception>
    [StateChanging]
    Task<MovedSignIn> OpenAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken);

    /// <summary>
    /// "Send reset link" for <paramref name="email"/>, a valid address, at Forgot password (Story 4.11). With
    /// <paramref name="issue"/>, the User with that address is read with no lock: one holding an active password gets a new
    /// reset link, superseding its older ones, and the <c>password_reset</c> email with the link as its Transit-encrypted
    /// credential, in the same command; for any other address a link value is minted and encrypted the same way, then
    /// discarded, so the work matches; so does a known address whose credential changed since it was read. A pending-only
    /// sign-up, never verified, gets no reset email: its path is signing up again. Without <paramref name="issue"/> (a recipient past its limit) nothing is issued or
    /// sent. Either way the transaction records <see cref="SignInSteps.ResetSent"/> with the address as its identifier,
    /// with <c>authentication.signin_transaction.extended</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at Forgot password. Nothing is kept.</exception>
    /// <exception cref="ArgumentException">The email isn't a valid address (<c>AuthenticationContract.TryNormalizeEmail</c>). Nothing is written.</exception>
    [StateChanging]
    Task<MovedSignIn> RequestAsync(CommandContext context, SignInTransaction transaction, string email, bool issue, CancellationToken cancellationToken);

    /// <summary>
    /// "Back to login" (Story 4.11): moves a transaction at Forgot password or its neutral confirmation back to Login, its
    /// identifier kept, with <c>authentication.signin_transaction.extended</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction is at neither. Nothing is kept.</exception>
    [StateChanging]
    Task<MovedSignIn> BackAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken);

    /// <summary>
    /// The reset link <paramref name="token"/>'s page (Story 4.11), read with no lock: whether it can be used now, the policy
    /// and the email. A used or expired link is found but unusable; a superseded one is gone. It writes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<ResetLinkState> OpenLinkAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken);

    /// <summary>
    /// "Reset password" with the link <paramref name="token"/> (Story 4.11), in this order: an unusable link, or a database
    /// Connection not enabled, is <see cref="PasswordResetStatus.Unusable"/>; a <paramref name="confirm"/> other than
    /// <paramref name="password"/> <see cref="PasswordResetStatus.Mismatch"/>; then, in one slot of the hashing budget
    /// (<see cref="PasswordResetStatus.Unavailable"/> with none), the database Connection's rules, with the User's email for
    /// the personal-data rule and their newest history hashes for the history rule, <see cref="PasswordResetStatus.RuleFailed"/>,
    /// and the new hash. All of those read the link with no lock and write nothing. Then the link is locked and checked again,
    /// and, in one command: Identity replaces the password, keeps it in the history, deletes pending
    /// credentials, uses the link and verifies the email; every other reset link of the User is superseded;
    /// <c>ISessions.RevokeAccessAsync</c> ends every Session and Token Family of the User, sparing none; a
    /// <c>security_notification</c> email is queued; and no Session starts. When <paramref name="transaction"/> is the
    /// browser's live transaction at the neutral confirmation, for the reset User's own address, it goes back to Login with
    /// its email kept.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is kept.</exception>
    [StateChanging]
    Task<PasswordResetResult> CompleteAsync(
        CommandContext context,
        Secret<string> token,
        Secret<string> password,
        Secret<string> confirm,
        SignInTransaction? transaction,
        CancellationToken cancellationToken);

    /// <summary>
    /// A reset link's "Send a new link" (Story 4.11): when the link's row still exists unused (a used link sends nothing; a
    /// superseded one is gone), its User still holds an active password, the database Connection is enabled, and
    /// <paramref name="recipientAllowed"/> allows the User's lower-cased email (the recipient limit a request counts), a new
    /// reset link and email go out, superseding the rest; otherwise nothing, and the caller shows the same neutral
    /// confirmation either way. A foreign or malformed link is refused before any lookup.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task SendNewLinkAsync(
        CommandContext context, Secret<string> token, Func<string, Task<bool>> recipientAllowed, CancellationToken cancellationToken);
}
