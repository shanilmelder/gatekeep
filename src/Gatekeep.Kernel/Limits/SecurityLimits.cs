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

    /// <summary>
    /// Capability refusals one Admin may have audited in <see cref="AdminAccessDeniedAuditWindow"/>:
    /// 30 (Story 1.24, AD-9's capped rejected events). Every refusal is counted; past the limit it
    /// is still refused alike, but only logged, so one Admin can't flood the Deployment chain.
    /// </summary>
    public const int AdminAccessDeniedAuditAttempts = 30;

    /// <summary>The fixed window audited capability refusals are counted in: 15 minutes (Story 1.24).</summary>
    public static readonly TimeSpan AdminAccessDeniedAuditWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How long a verified fresh WebAuthn assertion may confirm its one sensitive action: 5 minutes
    /// (PRD §5.2, "Recent authentication"; Story 1.26). The first request it matches uses it up.
    /// </summary>
    public static readonly TimeSpan RecentAuthentication = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Fresh-assertion ceremony calls one Admin Session may make in <see cref="FreshAssertionWindow"/>:
    /// 10 (Story 1.26). Each begin and each complete counts, before it runs.
    /// </summary>
    public const int FreshAssertionAttempts = 10;

    /// <summary>The fixed window fresh-assertion calls are counted in: 15 minutes (Story 1.26).</summary>
    public static readonly TimeSpan FreshAssertionWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Admin Recovery Code redemptions one client may make in <see cref="AdminRecoveryCodeWindow"/>:
    /// 5 (Story 1.26, PRD §5.2). Each is counted before the code is read, whatever its outcome.
    /// </summary>
    public const int AdminRecoveryCodeAttempts = 5;

    /// <summary>The fixed window Admin Recovery Code redemptions are counted in: 15 minutes (Story 1.26).</summary>
    public static readonly TimeSpan AdminRecoveryCodeWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Admin Recovery Code redemptions the whole Deployment may take in <see cref="AdminRecoveryCodeWindow"/>:
    /// 50 (Story 1.26), whatever client sends them, so many clients together can't guess for long.
    /// </summary>
    public const int AdminRecoveryCodeDeploymentAttempts = 50;

    /// <summary>
    /// The most WebAuthn credentials one Admin may hold: 10 (Story 1.26). It bounds the exclude list
    /// and Your credentials, and the database refuses an 11th.
    /// </summary>
    public const int MaxAdminCredentials = 10;
}
