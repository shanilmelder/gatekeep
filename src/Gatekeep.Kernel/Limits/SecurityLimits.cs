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
    /// How long a <c>gatekeep recover-admin</c> enrolment can be redeemed: 15 minutes from its issue
    /// (Story 1.32, AD-31, PRD §5.2). It is single use, and <c>admin_enrolment</c> refuses any other expiry.
    /// </summary>
    public static readonly TimeSpan AdminEnrolmentLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Enrolment redemptions one client may make in <see cref="AdminEnrolmentWindow"/>: 5 (Story 1.32).
    /// Each is counted before the value is looked up, whatever its outcome.
    /// </summary>
    public const int AdminEnrolmentAttempts = 5;

    /// <summary>
    /// Enrolment redemptions the whole Deployment may take in <see cref="AdminEnrolmentWindow"/>: 50
    /// (Story 1.32), whatever client sends them.
    /// </summary>
    public const int AdminEnrolmentDeploymentAttempts = 50;

    /// <summary>The fixed window enrolment redemptions are counted in: 15 minutes (Story 1.32).</summary>
    public static readonly TimeSpan AdminEnrolmentWindow = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The most WebAuthn credentials one Admin may hold: 10 (Story 1.26). It bounds the exclude list
    /// and Your credentials, and the database refuses an 11th.
    /// </summary>
    public const int MaxAdminCredentials = 10;

    /// <summary>
    /// How long Host.Hosted keeps a Tenant's built OpenIddict runtime: 5 seconds at most (AD-11's JWKS
    /// exception, Story 2.3). Its unwrapped token protection key lives no longer than that either.
    /// </summary>
    public static readonly TimeSpan TenantRuntimeLifetime = TimeSpan.FromSeconds(5);

    /// <summary>How long a relying party may cache a Tenant's JWKS: 15 minutes, as <c>max-age=900</c> (AD-11).</summary>
    public static readonly TimeSpan JwksMaxAge = TimeSpan.FromMinutes(15);

    /// <summary>How long one key custody call on the Hosted request path may take: 5 seconds (Story 2.3).</summary>
    public static readonly TimeSpan KeyCustodyCallTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The longest a Signing or Management key may exist: 180 days (PRD §5.2, AD-11, Story 2.4). Not
    /// configurable in v1. A key's age counts from its row's <c>created_at</c>, not from its promotion.
    /// </summary>
    public static readonly TimeSpan SigningKeyMaxAge = TimeSpan.FromDays(180);

    /// <summary>
    /// How long before <see cref="SigningKeyMaxAge"/> the daily rotation replaces a <c>current</c> key:
    /// 30 days (AD-11). A key is due once it is 150 days old.
    /// </summary>
    public static readonly TimeSpan SigningKeyRotationMargin = TimeSpan.FromDays(30);

    /// <summary>
    /// How long a <c>next</c> Signing Key must have been published in JWKS before a routine rotation
    /// promotes it: 15 minutes (AD-11), so relying parties have it before it signs.
    /// </summary>
    public static readonly TimeSpan SigningKeyPublicationBeforePromotion = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The hard lifetime of the longest-lived token a Signing Key signs, the access and ID tokens:
    /// 1 hour (PRD §5.2). Their configurable default is shorter.
    /// </summary>
    public static readonly TimeSpan HardSignedTokenLifetime = TimeSpan.FromHours(1);

    /// <summary>
    /// How long a <c>previous</c> key stays published after its rotation before it retires:
    /// <see cref="HardSignedTokenLifetime"/> plus 15 minutes (AD-11), so every token it signed has expired.
    /// </summary>
    public static readonly TimeSpan SigningKeyRetirementDelay = HardSignedTokenLifetime + TimeSpan.FromMinutes(15);

    /// <summary>
    /// How old a <c>sig-</c> or <c>mgmt-</c> Transit key that no row names must be before the orphan
    /// sweep deletes it: 24 hours (AD-11), far past any provisioning or rotation still in flight.
    /// </summary>
    public static readonly TimeSpan OrphanKeyGrace = TimeSpan.FromHours(24);

    /// <summary>
    /// The default lifetime of an access token: 15 minutes (PRD §5.2, Story 2.5), never more than
    /// <see cref="HardSignedTokenLifetime"/>. A Client Credentials token carries it as <c>expires_in</c> 900.
    /// </summary>
    public static readonly TimeSpan DefaultAccessTokenLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// The default lifetime of an ID token: 15 minutes (PRD §5.2, Story 2.9), the same as an access
    /// token's, never more than <see cref="HardSignedTokenLifetime"/>.
    /// </summary>
    public static readonly TimeSpan DefaultIdentityTokenLifetime = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How long an authorization code can be redeemed after it is issued: 60 seconds (PRD §5.2,
    /// Story 2.9). It is single-use within that time, and bound to its client, redirect URI and Tenant.
    /// </summary>
    public static readonly TimeSpan AuthorizationCodeLifetime = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Token requests one Tenant's token endpoint takes in <see cref="TokenRequestWindow"/>: 1200, from
    /// every source together (PRD §5.2, AD-14, Story 2.5). Each is counted before its client is
    /// authenticated, so past it every request is a 429 until the window ends.
    /// </summary>
    public const int TokenRequestTenantAttempts = 1200;

    /// <summary>
    /// Token requests one source (an IPv4 address, or an IPv6 /64) may send one Tenant's token endpoint
    /// in <see cref="TokenRequestWindow"/>: 60 (PRD §5.2, AD-14, Story 2.5), counted like the Tenant's.
    /// </summary>
    public const int TokenRequestSourceAttempts = 60;

    /// <summary>The fixed window token requests are counted in: 1 minute (PRD §5.2, Story 2.5).</summary>
    public static readonly TimeSpan TokenRequestWindow = TimeSpan.FromMinutes(1);

    /// <summary>
    /// How often one source's unauthenticated cross-Tenant mismatches reach the probed Tenant's Log: once
    /// per hour at most (PRD §5.2, AD-9, Story 2.5). Every mismatch is still counted, and an authenticated
    /// cross-Tenant attempt is always written.
    /// </summary>
    public static readonly TimeSpan CrossTenantMismatchLogWindow = TimeSpan.FromHours(1);

    /// <summary>
    /// The unauthenticated cross-Tenant mismatches one source's counter records in
    /// <see cref="CrossTenantMismatchLogWindow"/> before it stops growing: 10,000 (Story 2.5). It only
    /// measures: a mismatch past it is refused exactly alike.
    /// </summary>
    public const int CrossTenantMismatchCountedAttempts = 10_000;

    /// <summary>
    /// How long a rotated-out client secret keeps working beside its replacement by default: 24 hours
    /// (PRD §5.2). Epic 3 rotates; Story 2.5 adds only the <c>expires_at</c> it ends by.
    /// </summary>
    public static readonly TimeSpan ClientSecretOverlap = TimeSpan.FromHours(24);

    /// <summary>The longest a rotated-out client secret may overlap its replacement: 7 days (PRD §5.2).</summary>
    public static readonly TimeSpan HardClientSecretOverlap = TimeSpan.FromDays(7);
}
