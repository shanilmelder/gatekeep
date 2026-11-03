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

    /// <summary>An Admin Session's idle lifetime, slid by each authenticated request: 30 minutes (PRD §5.2).</summary>
    public static readonly TimeSpan AdminSessionIdle = TimeSpan.FromMinutes(30);

    /// <summary>An Admin Session's absolute lifetime, which no request extends: 8 hours (PRD §5.2).</summary>
    public static readonly TimeSpan AdminSessionAbsolute = TimeSpan.FromHours(8);

    /// <summary>
    /// Bootstrap claims one client may make in <see cref="BootstrapClaimWindow"/>: 5 (Story 1.21).
    /// Every claim is counted, before its token is compared, whatever its outcome.
    /// </summary>
    public const int BootstrapClaimAttempts = 5;

    /// <summary>The fixed window bootstrap claims are counted in: 15 minutes (Story 1.21).</summary>
    public static readonly TimeSpan BootstrapClaimWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Credential registration attempts one Admin Session may make in
    /// <see cref="CredentialRegistrationWindow"/>: 10 (Story 1.22). Each begin and each finish counts.
    /// </summary>
    public const int CredentialRegistrationAttempts = 10;

    /// <summary>The fixed window credential registration attempts are counted in: 15 minutes (Story 1.22).</summary>
    public static readonly TimeSpan CredentialRegistrationWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How long a WebAuthn challenge may be answered: 5 minutes. A registration's (Story 1.22) and
    /// an Admin sign-in's (Story 1.23).
    /// </summary>
    public static readonly TimeSpan WebAuthnChallengeLifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Admin sign-in begins one client may make in <see cref="AdminSignInWindow"/>: 20 (Story 1.23).
    /// Each is counted before it runs.
    /// </summary>
    public const int AdminSignInBeginAttempts = 20;

    /// <summary>
    /// Admin sign-in completes one client may make in <see cref="AdminSignInWindow"/>: 10 (Story 1.23).
    /// Every complete is counted before it runs, a success too, so a failed one can't be undone.
    /// </summary>
    public const int AdminSignInCompleteAttempts = 10;

    /// <summary>The fixed window Admin sign-in begins and completes are counted in: 15 minutes (Story 1.23).</summary>
    public static readonly TimeSpan AdminSignInWindow = TimeSpan.FromMinutes(15);
}
