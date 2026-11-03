using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.RateLimiting;
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

    /// <summary>Admin Sessions (Story 1.21). They run as <c>gk_admin</c>, in a Deployment scope.</summary>
    public static IAdminSessions CreateSessions() => new AdminSessions();
}
