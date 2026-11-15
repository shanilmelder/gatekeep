using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>
/// The audit events Sessions writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class SessionsEvents
{
    /// <summary>Written when a User's Session starts, with the User as Actor and target.</summary>
    public static readonly AuditEventDefinition SessionStarted = new(
        new AuditTypeCode("sessions.session.started"),
        "A User's Session started. Names the User only: the Session ID is stored only as its hash.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a User authenticates again in a browser presenting their live Session (Story 4.2): the
    /// Session's identifier is replaced, so the old one stops working. The User is Actor and target.
    /// </summary>
    public static readonly AuditEventDefinition SessionRotated = new(
        new AuditTypeCode("sessions.session.rotated"),
        "A User authenticated again in a browser holding their live Session, so its identifier was replaced and the old one stopped working. Names the User only.",
        AuditOutcome.Success);

    /// <summary>
    /// Written once per run of the hourly expired-state purge (Story 4.3) that deleted at least one expired token, dead
    /// Token Family, over Session or sign-in transaction past its restart retention. Actor System, no target. A run that
    /// deletes nothing writes nothing.
    /// </summary>
    public static readonly AuditEventDefinition ExpiredStatePurged = new(
        new AuditTypeCode("sessions.expired_state.purged"),
        "The hourly purge deleted the Tenant's expired tokens, empty Token Families, over Sessions with no family, and sign-in transactions over an hour past expiry.",
        AuditOutcome.Success);

    /// <summary>Written once by every <c>ISessions.RevokeAccessAsync</c> call, the one revocation path (AD-13).</summary>
    public static readonly AuditEventDefinition AccessRevoked = new(
        new AuditTypeCode("sessions.access.revoked"),
        "Sessions in scope ended and their Token Families and tokens were revoked. User scope targets the User.",
        AuditOutcome.Success,
        TenantLogClass.SessionRevocation);
}
