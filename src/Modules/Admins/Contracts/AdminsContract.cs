using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Core;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>What a composition root uses to wire the Admins module.</summary>
public static class AdminsContract
{
    /// <summary>
    /// Bootstrap claims (Story 1.21): 5 per client in a fixed 15-minute window, counted in
    /// <c>admin_attempt</c> in their own committed transaction before the token is compared.
    /// </summary>
    public static readonly RateLimitPolicy BootstrapClaimPolicy = new(
        "admins.bootstrap.claim",
        SecurityLimits.BootstrapClaimAttempts,
        SecurityLimits.BootstrapClaimWindow);

    /// <summary>
    /// Credential registration (Story 1.22): 10 attempts per Admin Session in a fixed 15-minute
    /// window, each begin and each finish, counted in <c>admin_attempt</c> in their own
    /// transaction before the attempt runs. The subject is the Session's ID.
    /// </summary>
    public static readonly RateLimitPolicy CredentialRegistrationPolicy = new(
        "admins.credential.register",
        SecurityLimits.CredentialRegistrationAttempts,
        SecurityLimits.CredentialRegistrationWindow);

    /// <summary>
    /// Admin sign-in begins (Story 1.23): 20 per client in a fixed 15-minute window, counted in
    /// <c>admin_attempt</c> in their own committed transaction before the begin runs.
    /// </summary>
    public static readonly RateLimitPolicy SignInBeginPolicy = new(
        "admins.signin.begin",
        SecurityLimits.AdminSignInBeginAttempts,
        SecurityLimits.AdminSignInWindow);

    /// <summary>
    /// Admin sign-in completes (Story 1.23): 10 per client in a fixed 15-minute window, counted in
    /// <c>admin_attempt</c> in their own committed transaction before the complete runs. Every
    /// complete counts, a success too, and nothing resets the window.
    /// </summary>
    public static readonly RateLimitPolicy SignInCompletePolicy = new(
        "admins.signin.complete",
        SecurityLimits.AdminSignInCompleteAttempts,
        SecurityLimits.AdminSignInWindow);

    /// <summary>
    /// Audited capability refusals (Story 1.24): 30 per Admin in a fixed 15-minute window, counted
    /// in <c>admin_attempt</c> in the request checks' transaction. Within it a refusal writes
    /// <see cref="AdminsEvents.AccessDenied"/>; past it, the same refusal is only logged (AD-9 caps
    /// rejected events per source). The subject is the Admin's ID.
    /// </summary>
    public static readonly RateLimitPolicy AccessDeniedAuditPolicy = new(
        "admins.access.denial_audit",
        SecurityLimits.AdminAccessDeniedAuditAttempts,
        SecurityLimits.AdminAccessDeniedAuditWindow);

    /// <summary>
    /// The WebAuthn credentials an Admin registers before they can do anything else: two, so
    /// losing one device can't lock them out (FR-2, FR-46).
    /// </summary>
    public const int RequiredCredentials = 2;

    /// <summary>
    /// The Kernel <see cref="IRateLimiter"/> for Admin attempts, such as bootstrap claims and
    /// Admin sign-in (AD-14). It counts in <c>admin_attempt</c> and serves a Deployment scope
    /// only: in a Tenant's it throws <see cref="InvalidOperationException"/> and writes nothing.
    /// It runs as <c>gk_admin</c>, the only role granted the table.
    /// </summary>
    public static IRateLimiter CreateAttemptLimiter() => new AdminAttemptLimiter();

    /// <summary>
    /// The bootstrap token issuer behind <c>gatekeep init</c> (Story 1.19). It runs as
    /// <c>gk_cli</c>, in a Deployment scope, and writes its event through <paramref name="appender"/>.
    /// </summary>
    public static IBootstrapIssuer CreateBootstrapIssuer(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new BootstrapIssuer(appender);
    }

    /// <summary>
    /// The bootstrap claim behind <c>POST /api/v1/deployment/bootstrap</c> (Story 1.21). It runs as
    /// <c>gk_admin</c>, in a Deployment scope, waits at most <paramref name="lockTimeout"/> for the
    /// bootstrap row lock and writes its event through <paramref name="appender"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="lockTimeout"/> isn't 1 millisecond to 1 minute.</exception>
    public static IBootstrapClaimer CreateBootstrapClaimer(IAuditAppender appender, TimeSpan lockTimeout)
    {
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentOutOfRangeException.ThrowIfLessThan(lockTimeout, TimeSpan.FromMilliseconds(1));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(lockTimeout, TimeSpan.FromMinutes(1));
        return new BootstrapClaimer(appender, lockTimeout);
    }

    /// <summary>
    /// Admin Sessions (Story 1.21). They run as <c>gk_admin</c>, in a Deployment scope, and write
    /// the sign-out event (Story 1.23) through <paramref name="appender"/>.
    /// </summary>
    public static IAdminSessions CreateSessions(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new AdminSessions(appender);
    }

    /// <summary>
    /// Admin sign-in with WebAuthn (Story 1.23). It runs as <c>gk_admin</c>, in a Deployment
    /// scope, verifies through <paramref name="verifier"/>, and writes its events through
    /// <paramref name="appender"/>.
    /// </summary>
    public static IAdminSignIn CreateSignIn(IAuditAppender appender, IWebAuthnVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(verifier);
        return new AdminSignIn(appender, verifier);
    }

    /// <summary>
    /// The capability authorizer (Story 1.24) over <see cref="AdminCapabilities"/>. It runs as
    /// <c>gk_admin</c>, in a Deployment scope, reads <c>tenant_role</c> on every call, and writes
    /// <see cref="AdminsEvents.AccessDenied"/> through <paramref name="appender"/>.
    /// </summary>
    public static IAdminAuthorization CreateAuthorization(IAuditAppender appender)
    {
        ArgumentNullException.ThrowIfNull(appender);
        return new AdminAuthorization(appender);
    }

    /// <summary>
    /// Admin WebAuthn credential registration (Story 1.22). It runs as <c>gk_admin</c>, in a
    /// Deployment scope, verifies through <paramref name="verifier"/>, and writes its events
    /// through <paramref name="appender"/>.
    /// </summary>
    public static IAdminCredentialRegistration CreateCredentialRegistration(IAuditAppender appender, IWebAuthnVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(appender);
        ArgumentNullException.ThrowIfNull(verifier);
        return new AdminCredentialRegistration(appender, verifier);
    }
}
