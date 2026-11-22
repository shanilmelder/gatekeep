using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>A sign-in Protocol asks for: the Application it is for and its authorization parameters.</summary>
public sealed record SignInRequest(Guid ApplicationId, IReadOnlyDictionary<string, string> Parameters);

/// <summary>
/// A begun sign-in. <paramref name="Binding"/> is the <c>__Host-gk_txn</c> value: base64url of
/// 32 random bytes. Only its SHA-256 is stored, so it can't be read back.
/// </summary>
public sealed record StartedSignIn(Guid TransactionId, Secret<string> Binding);

/// <summary>
/// The steps a sign-in transaction records as passed, in order, in <c>completed_steps</c> (Story 4.2): Login's
/// <see cref="Identifier"/>, or a sign-up's <see cref="Signup"/> then <see cref="Registered"/> (Story 4.7), then
/// <see cref="Authenticated"/>. From Story 4.9 a transaction at <see cref="Identifier"/> stands at the Password step, and
/// the correct password of a User whose email isn't verified records <see cref="Registered"/> after it. From Story 4.11,
/// "Forgot password?" records <see cref="Reset"/> after <see cref="Identifier"/>, and a reset request <see cref="ResetSent"/>.
/// </summary>
public static class SignInSteps
{
    /// <summary>Login's email was entered and recorded.</summary>
    public const string Identifier = "identifier";

    /// <summary>"Sign up" was chosen at Login (Story 4.7): the transaction stands at Signup. Back removes it.</summary>
    public const string Signup = "signup";

    /// <summary>
    /// A sign-up was submitted and recorded (Story 4.7), or the correct password of an unverified User was (Story 4.9): the
    /// transaction stands at Email verification required.
    /// </summary>
    public const string Registered = "registered";

    /// <summary>"Forgot password?" was chosen at the Password step (Story 4.11): the transaction stands at Forgot password.</summary>
    public const string Reset = "reset";

    /// <summary>
    /// A reset was requested at Forgot password (Story 4.11), whatever the address: the transaction stands at the neutral
    /// confirmation, from which "Back to login" goes back to Login.
    /// </summary>
    public const string ResetSent = "reset_sent";

    /// <summary>A credential step authenticated the User, and a Session was issued.</summary>
    public const string Authenticated = "authenticated";
}

/// <summary>
/// A sign-in transaction as it stands (Story 4.2, AD-12): the only record of which steps have passed. Its
/// <see cref="StepVersion"/> is its current step's, which every step moved on increments. Times are in UTC.
/// </summary>
/// <param name="Identifier">The email entered at Login, trimmed, or null before it.</param>
/// <param name="AuthenticatedSessionId">The Session its authentication issued, once <see cref="SignInSteps.Authenticated"/> has passed.</param>
/// <param name="CompletedAt">When the authorization request it was for completed; a completed transaction is never used again.</param>
/// <param name="SignupUserId">The User its sign-up registered (Story 4.7); null for an address already verified, which gets nothing.</param>
/// <param name="SignupCredentialId">The pending credential its sign-up made (Story 4.7). Only that credential's activation signs this transaction in.</param>
public sealed record SignInTransaction(
    Guid Id,
    Guid ApplicationId,
    IReadOnlyDictionary<string, string> Parameters,
    IReadOnlyList<string> CompletedSteps,
    int StepVersion,
    string? Identifier,
    Guid? AuthenticatedSessionId,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? CompletedAt,
    Guid? SignupUserId = null,
    Guid? SignupCredentialId = null)
{
    /// <summary>Whether <paramref name="step"/> has passed.</summary>
    public bool HasPassed(string step) => CompletedSteps.Contains(step, StringComparer.Ordinal);

    /// <summary>Whether its sliding life has run out at <paramref name="now"/>.</summary>
    public bool IsExpiredAt(DateTimeOffset now) => ExpiresAt <= now;
}

/// <summary>
/// What recording Login's email moved a transaction on to (Story 4.2): its new step version and expiry, and the
/// Session the credential step's authentication issued, if it authenticated the User. With none, no credential
/// step is available for the transaction.
/// </summary>
public sealed record IdentifiedSignIn(int StepVersion, DateTimeOffset ExpiresAt, StartedSession? Session);

/// <summary>Sign-in (AD-8, AD-12). Authentication owns <c>signin_transaction</c>.</summary>
public interface IAuthentication
{
    /// <summary>
    /// Writes a <c>signin_transaction</c> row bound to a new browser value, the context's
    /// Tenant and the Application, and one <c>authentication.signin_transaction.started</c>
    /// audit event, both in the caller's context. It expires after the §5.2 sliding lifetime.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">
    /// The Application ID is empty, a parameter is null or holds a NUL character, or the
    /// parameters exceed 16 KiB as JSON. Nothing is written.
    /// </exception>
    [StateChanging]
    Task<StartedSignIn> BeginAsync(CommandContext context, SignInRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// The transaction bound to <paramref name="binding"/>, the <c>__Host-gk_txn</c> value, in the context's
    /// Tenant, looked up only by the value's SHA-256 under row-level security (Story 4.2): live, expired or
    /// completed. Null when none is, a malformed value included. The row stays locked until the caller's
    /// transaction ends, so two requests can't move one transaction on at once. It writes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<SignInTransaction?> FindAsync(CommandContext context, Secret<string> binding, CancellationToken cancellationToken);

    /// <summary>
    /// Starts a new transaction in place of an expired one (Story 4.2): the same Application, parameters and
    /// identifier, a new binding and a full sliding life, with its <c>authentication.signin_transaction.started</c>
    /// event. The expired row's binding is replaced by one no cookie holds, in the same context, so its old cookie is
    /// refused from then on; the row itself is left for Story 4.3's purge.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<StartedSignIn> RestartAsync(CommandContext context, SignInTransaction expired, CancellationToken cancellationToken);

    /// <summary>
    /// Slides an uncompleted transaction's life to the §5.2 sliding lifetime from now, with one
    /// <c>authentication.signin_transaction.extended</c> event (Story 4.2). Its new expiry.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or no uncompleted transaction has that ID. Nothing is written.</exception>
    [StateChanging]
    Task<DateTimeOffset> ExtendAsync(CommandContext context, Guid transactionId, CancellationToken cancellationToken);

    /// <summary>
    /// Records Login's email in a transaction at Login (Story 4.2): the trimmed email in <c>identifier</c>,
    /// <see cref="SignInSteps.Identifier"/> appended, the step version incremented and the life slid, with
    /// <c>authentication.signin_transaction.extended</c> and <c>authentication.signin_transaction.identified</c>.
    /// Then it asks the credential step for the next step, which never depends on whether an account exists.
    /// When the credential step authenticates the User, it issues a Session through Sessions, rotating the
    /// live one <paramref name="presentedSession"/> names for the same User, and records
    /// <see cref="SignInSteps.Authenticated"/> and the Session.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or the transaction isn't at Login. Nothing is kept.</exception>
    /// <exception cref="ArgumentException">The email isn't a valid address of at most 254 characters (<c>AuthenticationContract.TryNormalizeEmail</c>). Nothing is written.</exception>
    [StateChanging]
    Task<IdentifiedSignIn> IdentifyAsync(
        CommandContext context,
        SignInTransaction transaction,
        string email,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);

    /// <summary>
    /// Completes an authenticated transaction of <paramref name="applicationId"/> (Story 4.2): <c>completed_at</c>
    /// is set, with one <c>authentication.signin_transaction.completed</c> event, and it is never used again.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The context has no Tenant, or no uncompleted, authenticated transaction of that Application has that ID. Nothing is written.
    /// </exception>
    [StateChanging]
    Task CompleteAsync(CommandContext context, Guid transactionId, Guid applicationId, CancellationToken cancellationToken);

    /// <summary>
    /// Writes one <c>authentication.signin_transaction.refused</c> event, anonymous and with no target (Story 4.2):
    /// the one effect a refused Hosted Login request keeps, written in a fresh context once the request's own
    /// work is undone.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task RefuseAsync(CommandContext context, CancellationToken cancellationToken);
}

/// <summary>
/// Authentication's credential-step port (Story 4.2): the step after Login's email. A credential step that
/// authenticates the User returns who and how; null means it authenticated no one, and the sign-in
/// goes on to the Password step (Story 4.9) while the database Connection is enabled. The release build's default always
/// returns null; only the tests plug in one that authenticates. The step after Continue never depends on whether an
/// account exists.
/// </summary>
public interface ICredentialStep
{
    /// <summary>The authentication <paramref name="transaction"/>'s recorded identifier leads to, or null.</summary>
    ValueTask<CredentialAuthentication?> AfterIdentifierAsync(CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken);
}

/// <summary>A credential step's completed authentication: the User, the methods used and when.</summary>
public sealed record CredentialAuthentication(Guid UserId, IReadOnlyList<string> Amr, DateTimeOffset AuthTime);
