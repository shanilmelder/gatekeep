using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// The audit events Admins writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class AdminsEvents
{
    /// <summary>
    /// Written on the Deployment chain by <c>gatekeep init</c> when it issues the first bootstrap
    /// token, in the transaction that stores the token's hash. The envelope holds no token, hash
    /// or time: the expiry is the issue time plus 15 minutes, kept exactly in <c>bootstrap_state</c>.
    /// </summary>
    public static readonly AuditEventDefinition BootstrapTokenIssued = new(
        new AuditTypeCode("bootstrap.token.issued"),
        "gatekeep init issued the first one-time bootstrap token. It expires 15 minutes after issue. Holds no token or hash.",
        AuditOutcome.Success);

    /// <summary>
    /// Written instead of <see cref="BootstrapTokenIssued"/> when <c>gatekeep init</c> runs again
    /// before bootstrap completes: the new token's hash replaces the old one, which voids it.
    /// </summary>
    public static readonly AuditEventDefinition BootstrapTokenReissued = new(
        new AuditTypeCode("bootstrap.token.reissued"),
        "gatekeep init reissued the bootstrap token, voiding the previous one. It expires 15 minutes after issue. Holds no token or hash.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when the bootstrap token is claimed (Story 1.21), in the
    /// transaction that creates the first Admin as Deployment Owner, completes bootstrap and starts
    /// their setup Admin Session. The Actor and the target are that Admin. Holds no token, hash,
    /// Session ID or CSRF token.
    /// </summary>
    public static readonly AuditEventDefinition BootstrapAdminCreated = new(
        new AuditTypeCode("bootstrap.admin.created"),
        "The bootstrap token was claimed: the first Admin was created as Deployment Owner and bootstrap completed. Holds no token or hash.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain once per WebAuthn credential an Admin registers (Story 1.22),
    /// in the transaction that stores it. The Actor and the target are that Admin. Holds no
    /// credential ID, public key, challenge or user handle.
    /// </summary>
    public static readonly AuditEventDefinition CredentialRegistered = new(
        new AuditTypeCode("admin.credential.registered"),
        "An Admin registered a WebAuthn credential. Holds no credential ID, public key, challenge or user handle.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when an Admin comes to meet the credential floor (Story 1.22,
    /// FR-2, FR-46): two WebAuthn credentials, or one and a confirmed offline Recovery Code (Story
    /// 1.26). It is written in the transaction of the registration, or the code's confirmation, that
    /// did it, after that step's own event, and only when the Admin didn't meet the floor before:
    /// their setup and recovery Sessions become full there too. The Actor and the target are that Admin.
    /// </summary>
    public static readonly AuditEventDefinition SetupCompleted = new(
        new AuditTypeCode("admin.setup.completed"),
        "An Admin came to hold two WebAuthn credentials, or one and an offline Recovery Code, which completed setup and made their Session full.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when an Admin signs in with WebAuthn (Story 1.23), in the
    /// transaction that advances the credential's counter and starts their full Session. The Actor
    /// and the target are that Admin. Holds no credential ID, challenge, user handle, Session ID or
    /// CSRF token.
    /// </summary>
    public static readonly AuditEventDefinition SignInSucceeded = new(
        new AuditTypeCode("admin.signin.succeeded"),
        "An Admin signed in with a WebAuthn credential and a full Admin Session started. Holds no credential ID, challenge, user handle or Session ID.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when a sign-in is refused after its signature verified over
    /// one of an Admin's registered credentials, for a reason other than a counter regression
    /// (Story 1.23). Today that is only the counter's compare-and-set finding the stored value
    /// moved, which the credential's row lock makes unreachable: it is kept as defence in depth,
    /// and the code stays published for it. The Actor is Anonymous, as nobody signed in; the target
    /// is the Admin who owns the credential. Committed although the sign-in is refused. A refusal
    /// before the signature verified (a bad signature, another user handle or RP ID, a missing
    /// flag, an unknown credential) proves nothing about who sent it, so it is only logged:
    /// otherwise anyone with a credential ID could write this against a chosen Admin.
    /// </summary>
    public static readonly AuditEventDefinition SignInFailed = new(
        new AuditTypeCode("admin.signin.failed"),
        "A sign-in whose signature verified over an Admin's WebAuthn credential was refused. Holds no credential ID, challenge or user handle.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the Deployment chain instead of <see cref="SignInFailed"/> when an assertion with
    /// a valid signature carries a signature counter that doesn't advance past the stored non-zero
    /// one (Story 1.23): the sign of a cloned authenticator. Sign-ins with one credential run one at
    /// a time under its row lock, so an assertion with a lower counter that arrives after a higher
    /// one, even from the same authenticator, is indistinguishable from a clone and is reported as
    /// one. The Actor is Anonymous at sign-in; for a fresh assertion (Story 1.26), whose Session
    /// already names its Admin, the Actor is that Admin. The target is the Admin who owns the
    /// credential. The counter is left as it was.
    /// </summary>
    public static readonly AuditEventDefinition CredentialSignCountRegressed = new(
        new AuditTypeCode("admin.credential.sign_count_regressed"),
        "A sign-in with an Admin's WebAuthn credential was refused because its signature counter went backwards: it may be cloned.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the Deployment chain when an Admin signs out (Story 1.23), in the transaction
    /// that ends their Session, and only when that call ended it. The Actor and the target are
    /// that Admin. Holds no Session ID.
    /// </summary>
    public static readonly AuditEventDefinition SessionSignedOut = new(
        new AuditTypeCode("admin.session.signed_out"),
        "An Admin signed out, which ended their Admin Session. Holds no Session ID.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when a sign-in ends a live Admin Session the same browser
    /// presented, as <c>superseded</c> (Story 1.23), in the sign-in's transaction, and only when it
    /// ended one. The Actor is the Admin who signed in; the target is the Admin whose Session ended.
    /// Holds no Session ID.
    /// </summary>
    public static readonly AuditEventDefinition SessionSuperseded = new(
        new AuditTypeCode("admin.session.superseded"),
        "A sign-in in the same browser ended a live Admin Session as superseded. Holds no Session ID.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when an authenticated Admin, past the Origin, Session, CSRF
    /// and setup checks, is refused a capability (Story 1.24, AD-9), in the request checks'
    /// transaction. Every refusal is counted per Admin under
    /// <see cref="AdminsContract.AccessDeniedAuditPolicy"/>: the first 30 in 15 minutes are
    /// audited, and past that the same refusal is only logged, so one Admin can't flood the chain.
    /// The Actor is the Admin; the target is the path Tenant when the path named a well-formed
    /// Tenant ID, and none otherwise. That ID is the caller's, as sent: the authorizer doesn't read
    /// <c>tenant</c>, so it may name no Tenant at all. Holds no capability name, Session ID or CSRF
    /// token: the capability goes only in the log line.
    /// </summary>
    public static readonly AuditEventDefinition AccessDenied = new(
        new AuditTypeCode("admin.access.denied"),
        "An Admin was refused a capability. The target is the path's Tenant ID as sent, which may not exist. Past 30 per Admin in 15 minutes, only logged. Holds no capability name.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the refused Tenant's own chain beside <see cref="AccessDenied"/> (Story 7.4, AD-9,
    /// FR-40), so the attacked Tenant's Log shows the attempt: when an Admin who holds no Tenant Role
    /// in the path Tenant is refused there, the Tenant exists, and the refusal was within
    /// <see cref="AdminsContract.AccessDeniedAuditPolicy"/>'s cap, which this shares. It goes in its
    /// own Tenant scope, committed before the Deployment write's. The Actor is the Admin; the target
    /// the Tenant. Holds no capability name, Session ID or CSRF token. An unknown or malformed Tenant
    /// has no chain to write to, so only the Deployment Log holds that refusal.
    /// </summary>
    public static readonly AuditEventDefinition CrossTenantRejected = new(
        new AuditTypeCode("admin.cross_tenant.rejected"),
        "An Admin holding no Tenant Role in this Tenant was refused a request in it. Past 30 refusals per Admin in 15 minutes, only logged. Holds no capability name.",
        AuditOutcome.Failure,
        TenantLogClass.CrossTenantRejection);

    /// <summary>
    /// Written on the Deployment chain when an Admin confirms a sensitive action with a fresh
    /// WebAuthn assertion (Story 1.26, FR-46), in the transaction that stores the grant, once the
    /// signature over one of their own credentials verified with user verification. The Actor and
    /// the target are that Admin. Holds no credential ID, challenge, binding, action or Session ID.
    /// </summary>
    public static readonly AuditEventDefinition FreshAssertionVerified = new(
        new AuditTypeCode("admin.fresh_assertion.verified"),
        "An Admin confirmed a sensitive action with a fresh WebAuthn assertion. Holds no credential ID, challenge, binding or Session ID.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when a fresh assertion whose signature verified over one of
    /// the Admin's own credentials is refused for a reason other than a counter regression (Story
    /// 1.26). Today that is only the counter's compare-and-set finding the stored value moved,
    /// which the credential's row lock makes unreachable: it is defence in depth, as
    /// <see cref="SignInFailed"/> is. The Actor and the target are the Session's Admin. Every
    /// other refusal is only logged.
    /// </summary>
    public static readonly AuditEventDefinition FreshAssertionFailed = new(
        new AuditTypeCode("admin.fresh_assertion.failed"),
        "A fresh assertion whose signature verified over an Admin's own WebAuthn credential was refused. Holds no credential ID, challenge or binding.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the Deployment chain when an Admin removes one of their WebAuthn credentials in
    /// Your credentials (Story 1.26), in the transaction that deletes it, after a fresh assertion.
    /// The Actor and the target are that Admin. Holds no credential ID or public key.
    /// </summary>
    public static readonly AuditEventDefinition CredentialRemoved = new(
        new AuditTypeCode("admin.credential.removed"),
        "An Admin removed one of their WebAuthn credentials. Holds no credential ID or public key.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain once for each live Admin Session another action ended as
    /// <c>revoked</c> (Story 1.26): removing a credential ends the Admin's other Sessions, and
    /// redeeming a Recovery Code ends all of them. The Actor is the Admin who acted; the target is
    /// the Admin whose Session ended. Holds no Session ID.
    /// </summary>
    public static readonly AuditEventDefinition SessionRevoked = new(
        new AuditTypeCode("admin.session.revoked"),
        "A credential removal or a Recovery Code ended a live Admin Session as revoked. Holds no Session ID.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when an Admin confirms they saved their offline Recovery
    /// Code (Story 1.26, FR-46), in the transaction that confirms it: only then can it be redeemed.
    /// The Actor and the target are that Admin. Holds no code, HMAC or key version.
    /// </summary>
    public static readonly AuditEventDefinition RecoveryCodeIssued = new(
        new AuditTypeCode("admin.recovery_code.issued"),
        "An Admin confirmed they saved an offline Recovery Code, which can now be used once. Holds no code or HMAC.",
        AuditOutcome.Success);

    /// <summary>
    /// Written on the Deployment chain when an Admin's Recovery Code is redeemed at sign-in (Story
    /// 1.26), in the transaction that uses it up, ends their Sessions and starts a recovery Session,
    /// which reaches only credential registration. The Actor and the target are that Admin. Holds
    /// no code, HMAC or Session ID.
    /// </summary>
    public static readonly AuditEventDefinition RecoveryCodeUsed = new(
        new AuditTypeCode("admin.recovery_code.used"),
        "An Admin's offline Recovery Code was used to start a Session that reaches only credential registration. Holds no code or HMAC.",
        AuditOutcome.Success);
}
