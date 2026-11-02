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
        "A User's Session started. Names the User only: the Session ID is stored only as its hash.");
}
