namespace Gatekeep.Kernel.Limits;

/// <summary>
/// The one file of security limits (spine "Limits" rule, PRD §5.2). Every lifetime a
/// module applies comes from here, never from a literal. Later stories add the rest of
/// §5.2 as they first use it.
/// </summary>
public static class SecurityLimits
{
    /// <summary>A sign-in transaction's sliding lifetime: 30 minutes (AD-12, per EXPERIENCE).</summary>
    public static readonly TimeSpan SignInTransactionLifetime = TimeSpan.FromMinutes(30);

    /// <summary>The default User Session idle lifetime: 3 days (PRD §5.2, AD-12).</summary>
    public static readonly TimeSpan UserSessionIdleDefault = TimeSpan.FromDays(3);

    /// <summary>The default User Session absolute lifetime: 7 days (PRD §5.2, AD-12).</summary>
    public static readonly TimeSpan UserSessionAbsoluteDefault = TimeSpan.FromDays(7);
}
