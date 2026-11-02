using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>
/// The audit events Sessions writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class SessionsEvents
{
    /// <summary>Written by <c>ISessions.StartAsync</c> with the User as Actor and target.</summary>
    public static readonly AuditEventDefinition SessionStarted = new(
        new AuditTypeCode("sessions.session.started"),
        "A User Session started. Only the hash of its identifier is stored.");

    /// <summary>Written once by every <c>ISessions.RevokeAccessAsync</c> call, the one revocation path (AD-13).</summary>
    public static readonly AuditEventDefinition AccessRevoked = new(
        new AuditTypeCode("sessions.access.revoked"),
        "Sessions in scope ended and their Token Families and tokens were revoked. User scope targets the User.",
        TenantLogClass.SessionRevocation);
}
