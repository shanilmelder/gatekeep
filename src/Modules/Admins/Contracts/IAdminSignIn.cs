using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Kernel.WebAuthn;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// A begun sign-in: the request options for <c>navigator.credentials.get</c>, and the binding
/// value for the <c>__Host-gk-admin-signin</c> cookie, 32 CSPRNG bytes as base64url, of which only
/// the SHA-256 is stored with the challenge's.
/// </summary>
public sealed record AdminSignInStart(WebAuthnRequestOptions Options, Secret<string> Binding);

/// <summary>What a finished sign-in came to.</summary>
public enum AdminSignInStatus
{
    /// <summary>The assertion verified: the counter advanced and a full Session started.</summary>
    SignedIn,

    /// <summary>
    /// Refused, with no Session. When <see cref="AdminSignInOutcome.Audited"/>, the signature had
    /// verified over a registered credential and its Admin's refusal event was written in the
    /// caller's transaction, which the caller commits; otherwise nothing was written.
    /// </summary>
    Refused,
}

/// <summary>
/// A finished sign-in: the new Session and whether its Admin has finished credential setup when
/// signed in; why not, for the caller's log only, when refused.
/// </summary>
public sealed record AdminSignInOutcome(
    AdminSignInStatus Status,
    AdminSessionGrant? Session,
    bool SetupComplete,
    WebAuthnRefusal? Refusal,
    bool Audited)
{
    /// <summary>A refusal before any signature verified, or naming no registered credential: nothing is written.</summary>
    public static AdminSignInOutcome Unattributed(WebAuthnRefusal refusal) => new(AdminSignInStatus.Refused, null, false, refusal, false);
}

/// <summary>
/// Admin sign-in with WebAuthn only (Story 1.23, FR-46, AD-31): no email, password, username or
/// Tenant Connection. The credential is discoverable, so the request options list none, and the
/// Admin is found from the credential the assertion names, in <c>admin_credential</c> alone; no
/// Identity, Authentication or Sessions table is read. The pending challenge lives in
/// <c>admin_signin_challenge</c> as its SHA-256 for 5 minutes, bound to the browser that began it
/// by the SHA-256 of its binding cookie. Every step runs as <c>gk_admin</c>, in a Deployment scope.
/// A finish is two transactions, as registration's: the caller takes the challenge in its own and
/// commits it, so it is used up whatever happens after, then verifies and starts the Session in
/// another. The caller counts each begin and each complete per client under
/// <see cref="AdminsContract.SignInBeginPolicy"/> and <see cref="AdminsContract.SignInCompletePolicy"/>
/// first, each in its own committed transaction.
/// </summary>
public interface IAdminSignIn
{
    /// <summary>
    /// Starts a sign-in: a fresh 32-byte challenge and a fresh binding value, stored as their
    /// SHA-256 with an expiry 5 minutes from the database clock. In the same transaction it
    /// deletes every expired pending sign-in, and the one <paramref name="presentedBinding"/>
    /// names, so only the newest challenge a browser holds can answer.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<AdminSignInStart> BeginAsync(
        CommandContext context,
        WebAuthnRelyingParty relyingParty,
        Secret<string>? presentedBinding,
        CancellationToken cancellationToken);

    /// <summary>
    /// Takes the pending challenge <paramref name="binding"/> names: deletes its row, expired or not,
    /// and returns the SHA-256 when it was still live. Null for no binding, a malformed or unknown
    /// one, and an expired or used one. The caller commits this on its own, before anything is verified, so
    /// the challenge can never answer twice, whatever fails after.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<byte[]?> TakeChallengeAsync(CommandContext context, Secret<string>? binding, CancellationToken cancellationToken);

    /// <summary>
    /// Verifies <paramref name="assertion"/> against the challenge <see cref="TakeChallengeAsync"/>
    /// took and the registered credential it names, locking that credential's row and its Admin's.
    /// The row lock makes sign-ins with one credential run one at a time. A verified one advances
    /// the counter with a compare-and-set on the verified value, ends with <c>superseded</c> the live
    /// Session <paramref name="presentedSession"/> names (appending <see cref="AdminsEvents.SessionSuperseded"/>),
    /// starts a full Session and appends <see cref="AdminsEvents.SignInSucceeded"/>, all in the
    /// caller's transaction. A refusal before the signature verified, or for an unknown credential,
    /// writes nothing and is only logged. A signature that verified with a counter that didn't go up
    /// appends <see cref="AdminsEvents.CredentialSignCountRegressed"/>: serialised by the lock, a
    /// lower counter after a higher one is indistinguishable from a clone and is reported as one.
    /// The compare-and-set can't then lose; if it ever did, <see cref="AdminsEvents.SignInFailed"/>
    /// is appended, as defence in depth.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<AdminSignInOutcome> FinishAsync(
        CommandContext context,
        WebAuthnRelyingParty relyingParty,
        byte[] challengeSha256,
        WebAuthnAssertion assertion,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);
}
