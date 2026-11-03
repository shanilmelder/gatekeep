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
        "gatekeep init issued the first one-time bootstrap token. It expires 15 minutes after issue. Holds no token or hash.");

    /// <summary>
    /// Written instead of <see cref="BootstrapTokenIssued"/> when <c>gatekeep init</c> runs again
    /// before bootstrap completes: the new token's hash replaces the old one, which voids it.
    /// </summary>
    public static readonly AuditEventDefinition BootstrapTokenReissued = new(
        new AuditTypeCode("bootstrap.token.reissued"),
        "gatekeep init reissued the bootstrap token, voiding the previous one. It expires 15 minutes after issue. Holds no token or hash.");

    /// <summary>
    /// Written on the Deployment chain when the bootstrap token is claimed (Story 1.21), in the
    /// transaction that creates the first Admin as Deployment Owner, completes bootstrap and starts
    /// their setup Admin Session. The Actor and the target are that Admin. Holds no token, hash,
    /// Session ID or CSRF token.
    /// </summary>
    public static readonly AuditEventDefinition BootstrapAdminCreated = new(
        new AuditTypeCode("bootstrap.admin.created"),
        "The bootstrap token was claimed: the first Admin was created as Deployment Owner and bootstrap completed. Holds no token or hash.");
}
