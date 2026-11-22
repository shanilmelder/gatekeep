using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Identity.Contracts;

/// <summary>
/// The audit events Identity writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class IdentityEvents
{
    /// <summary>
    /// Written when a sign-up gives a User a new password credential (Story 4.7): a new User, or an unverified one signing
    /// up again. Anonymous, and the target is the User; it holds no email or password. A sign-up with an address already
    /// verified writes nothing, this event included.
    /// </summary>
    public static readonly AuditEventDefinition UserSignedUp = new(
        new AuditTypeCode("identity.user.signed_up"),
        "A sign-up gave a User a new password, pending its email's verification unless a Dev Tenant turned that off. Names the User only, never the email or password.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a verification link verifies a User's email (Story 4.7): the link is used, its password activated and
    /// every other pending one deleted. Anonymous, and the target is the User; it holds no email or link.
    /// </summary>
    public static readonly AuditEventDefinition UserEmailVerified = new(
        new AuditTypeCode("identity.user.email_verified"),
        "A User's email was verified by a link, which activated the password it was sent for and removed any other pending one. Names the User only.",
        AuditOutcome.Success);

    /// <summary>
    /// Written when a reset link replaces a User's password (Story 4.11, FR-19, FR-40), in the same command: the link is
    /// used, the email verified and every pending credential deleted, and every Session and Token Family of the User ends.
    /// The User is Actor and target; it holds no detail, link or password.
    /// </summary>
    public static readonly AuditEventDefinition PasswordReset = new(
        new AuditTypeCode("identity.password.reset"),
        "A User reset their password with a reset link; every Session and Token Family of theirs ended. The User is Actor and target.",
        AuditOutcome.Success,
        TenantLogClass.PasswordReset);
}
