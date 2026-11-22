using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>How a password submit ended (Story 4.9).</summary>
public enum SignInStatus
{
    /// <summary>
    /// An unknown account, no active password, or a wrong one, alike: one Argon2id verification ran, and nothing was
    /// written. <see cref="SignInResult.FailedUserId"/> names the User when the account exists.
    /// </summary>
    Incorrect,

    /// <summary>No hashing slot came free in time, or no database Connection is enabled: nothing hashed or written.</summary>
    Unavailable,

    /// <summary>The correct password of a verified User: a Session started, and the transaction records its authentication.</summary>
    Authenticated,

    /// <summary>
    /// The correct password of a User whose email isn't verified: no Session; the transaction records
    /// <see cref="SignInSteps.Registered"/> and a new verification link went out by email.
    /// </summary>
    VerificationRequired,
}

/// <summary>
/// A password submit's result (Story 4.9): its status, the transaction's step version and expiry, the Session when
/// authenticated, and the User a failure is about when the account exists.
/// </summary>
public sealed record SignInResult(
    SignInStatus Status,
    int StepVersion,
    DateTimeOffset ExpiresAt,
    StartedSession? Session = null,
    Guid? FailedUserId = null);

/// <summary>
/// Password sign-in through Hosted Login (Story 4.9, FR-23, NFR-2, NFR-20), each call one command in the caller's Tenant
/// context and transaction. Every account costs the same: one Argon2id verification through the hashing budget sign-up
/// shares, against a dummy hash when there is no account or active password. The answer never depends on which.
/// </summary>
public interface ISignIn
{
    /// <summary>
    /// Submits <paramref name="password"/> for a transaction at the Password step (<see cref="SignInSteps.Identifier"/> only).
    /// The User with the transaction's identifier is read with no lock, then exactly one verification runs in a hashing
    /// slot, against its active credential's hash or the dummy. A wrong password, no active credential or no account is
    /// <see cref="SignInStatus.Incorrect"/>, writing nothing; the caller writes <see cref="RecordFailureAsync"/> in a
    /// scope of its own. The correct password of a verified User (or with verification off on a Dev Tenant) rehashes a
    /// hash with old parameters in the same slot, starts a Session with <c>amr: ["pwd"]</c> and the credential's
    /// Connection, rotating the live one <paramref name="presentedSession"/> names for the same User, records
    /// <see cref="SignInSteps.Authenticated"/> and writes <c>authentication.signin.succeeded</c>. That of an unverified
    /// User records <see cref="SignInSteps.Registered"/> with the User and credential, and sends a new verification link.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at the Password step. Nothing is kept.</exception>
    [StateChanging]
    Task<SignInResult> SignInAsync(
        CommandContext context,
        SignInTransaction transaction,
        Secret<string> password,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);

    /// <summary>
    /// Writes <c>authentication.signin.failed</c>, anonymous, targeting <paramref name="userId"/> when the account exists
    /// and nothing otherwise (Story 4.9). The caller writes it in its own committed scope, so it survives the request's
    /// rollback. It holds no email or password.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task RecordFailureAsync(CommandContext context, Guid? userId, CancellationToken cancellationToken);

    /// <summary>
    /// The identifier chip's "Edit" (Story 4.9): moves a transaction at the Password step back to Login, its identifier
    /// kept, the step version incremented and the life slid, with <c>authentication.signin_transaction.extended</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at the Password step. Nothing is kept.</exception>
    [StateChanging]
    Task<MovedSignIn> BackAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken);
}
