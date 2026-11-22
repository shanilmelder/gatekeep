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

    /// <summary>
    /// Written each time a sign-in transaction's sliding life is extended (Story 4.2): by opening the Login page, by
    /// "Keep going", and by recording Login's email. A stale step or an invalid email extends nothing. Anonymous.
    /// </summary>
    public static readonly AuditEventDefinition SignInTransactionExtended = new(
        new AuditTypeCode("authentication.signin_transaction.extended"),
        "A sign-in transaction's 30-minute sliding life was extended: its Login page was opened, Keep going was chosen or its email was recorded. Anonymous.",
        AuditOutcome.Success);

    /// <summary>Written when a sign-in transaction records the email entered at Login (Story 4.2). Anonymous, and it holds no email.</summary>
    public static readonly AuditEventDefinition SignInTransactionIdentified = new(
        new AuditTypeCode("authentication.signin_transaction.identified"),
        "A sign-in transaction recorded the email entered at Login. The caller is anonymous, and the email isn't in the event.",
        AuditOutcome.Success);

    /// <summary>Written when an authenticated sign-in transaction completes its authorization request (Story 4.2). Anonymous.</summary>
    public static readonly AuditEventDefinition SignInTransactionCompleted = new(
        new AuditTypeCode("authentication.signin_transaction.completed"),
        "An authenticated sign-in transaction completed its authorization request, and can't be used again. The caller is anonymous.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a Hosted Login request is refused for its sign-in transaction or its request checks (Story 4.2):
    /// no, a completed or another Application's transaction, a step not yet passed, or a wrong Origin or CSRF token.
    /// Anonymous, with no target.
    /// </summary>
    public static readonly AuditEventDefinition SignInTransactionRefused = new(
        new AuditTypeCode("authentication.signin_transaction.refused"),
        "A Hosted Login request was refused: its sign-in transaction was missing, completed, another Application's or not at that step, or its Origin or CSRF token was wrong. Anonymous.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written when a User signs in with their password at Hosted Login and a Session starts (Story 4.9, FR-40), in the same
    /// command. Actor and target are the User; it holds no email or password.
    /// </summary>
    public static readonly AuditEventDefinition SignInSucceeded = new(
        new AuditTypeCode("authentication.signin.succeeded"),
        "A User signed in with their password at Hosted Login, and a Session started. The User is Actor and target.",
        AuditOutcome.Success,
        TenantLogClass.SignIn);

    /// <summary>
    /// Written when a password submit at Hosted Login fails (Story 4.9, FR-40): an unknown account, no active password or
    /// a wrong one, alike. Anonymous; the target is the User when the account exists, none otherwise. It holds no email or
    /// password, and is kept through its own committed scope.
    /// </summary>
    public static readonly AuditEventDefinition SignInFailed = new(
        new AuditTypeCode("authentication.signin.failed"),
        "A password sign-in at Hosted Login failed. Anonymous; the target is the User when the account exists.",
        AuditOutcome.Failure,
        TenantLogClass.SignIn);
}
