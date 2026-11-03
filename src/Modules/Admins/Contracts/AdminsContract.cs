using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Modules.Admins.Core;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>What a composition root uses to wire the Admins module.</summary>
public static class AdminsContract
{
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
}
