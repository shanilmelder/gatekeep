using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>
/// The audit events Authentication writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class AuthenticationEvents
{
    /// <summary>Written by <c>IAuthentication.BeginAsync</c> with an anonymous Actor.</summary>
    public static readonly AuditEventDefinition SignInTransactionStarted = new(
        new AuditTypeCode("authentication.signin_transaction.started"),
        "A sign-in transaction began, bound to a browser value, the Tenant and an Application.");
}
