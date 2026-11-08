using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>
/// The audit events Authentication writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class AuthenticationEvents
{
    /// <summary>Written when a sign-in transaction begins, with an anonymous Actor: nobody is signed in yet.</summary>
    public static readonly AuditEventDefinition SignInTransactionStarted = new(
        new AuditTypeCode("authentication.signin_transaction.started"),
        "A sign-in transaction began for an Application. The caller is anonymous, so no person is named.",
        AuditOutcome.Success);
}
