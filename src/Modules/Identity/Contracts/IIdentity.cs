using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Identity.Contracts;

/// <summary>
/// What a sign-up registered (Story 4.7): the User, new or an unverified one signing up again, and the password credential
/// it made for them, <c>pending</c> until a verification link activates it, or <c>active</c> at once where a Dev Tenant
/// turned verification off.
/// </summary>
public sealed record RegisteredUser(Guid UserId, Guid CredentialId);

/// <summary>A password credential as sign-up reads it back (Story 4.7): its User, whether it is active, and whether the User's email is verified.</summary>
public sealed record CredentialState(Guid UserId, bool Active, bool UserVerified);

/// <summary>
/// An email verification link's row (Story 4.7), found by the link's SHA-256 alone, whatever its state: its User, the pending
/// credential it activates, the Application its sign-up was for, its expiry, when it was used, and whether its User's email
/// is already verified. Times are in UTC.
/// </summary>
public sealed record VerificationLink(
    Guid TokenId,
    Guid UserId,
    Guid CredentialId,
    Guid? ApplicationId,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? UsedAt,
    bool UserVerified)
{
    /// <summary>Whether it can still be used at <paramref name="now"/>: unused and unexpired.</summary>
    public bool IsUsableAt(DateTimeOffset now) => UsedAt is null && ExpiresAt > now;
}

/// <summary>What using a verification link came to (Story 4.7).</summary>
public enum EmailVerificationStatus
{
    /// <summary>The link verified its User's email and activated its credential; every other pending credential is gone.</summary>
    Verified,

    /// <summary>The User's email was verified already: the link only marked itself used, and the active credential stays.</summary>
    AlreadyVerified,

    /// <summary>Malformed, another Tenant's, unknown, expired or used: nothing changed.</summary>
    Unusable,
}

/// <summary>A verification link's use (Story 4.7): how it ended, and for <see cref="EmailVerificationStatus.Verified"/> its User and credential.</summary>
public sealed record EmailVerification(EmailVerificationStatus Status, Guid? UserId = null, Guid? CredentialId = null);

/// <summary>
/// Identity's Users and their credentials (Story 4.7, AD-1): <c>"user"</c>, <c>password_credential</c>,
/// <c>one_time_token</c> and <c>password_history</c>. Every call runs in the caller's Tenant context and transaction. A
/// password reaches it only as an Argon2id PHC string, never in the clear, and a link only as the value it returns once.
/// </summary>
public interface IIdentity
{
    /// <summary>
    /// Registers a sign-up for <paramref name="email"/> (Story 4.7, FR-17), under the User row's lock. When no User has that
    /// address (compared case-insensitively) one is created with it, unverified. When one has it whose email is verified,
    /// or who already holds an active password, nothing is written and the result is null: a sign-up never changes an
    /// existing account. Otherwise a password credential with <paramref name="passwordHash"/> is added, made under
    /// <paramref name="connectionId"/>: <c>pending</c>, or with <paramref name="activate"/> (verification off) <c>active</c>,
    /// with every pending one deleted and the hash kept in the User's password history. It writes
    /// <see cref="IdentityEvents.UserSignedUp"/>, the User as target.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">The email or hash is empty or too long. Nothing is written.</exception>
    [StateChanging]
    Task<RegisteredUser?> RegisterAsync(
        CommandContext context,
        string email,
        Guid connectionId,
        string passwordHash,
        bool activate,
        CancellationToken cancellationToken);

    /// <summary>
    /// Issues an email verification link for the pending credential <paramref name="credentialId"/> of
    /// <paramref name="userId"/> (Story 4.7): <c>{tenantPublicId}.{base64url of 32 random bytes}</c>, of which only the
    /// SHA-256 of the whole value is stored. It lasts <c>SecurityLimits.EmailVerificationLinkLifetime</c> and works once. It
    /// replaces the credential's unused link, if any, so only the newest works. The value is returned once, for the email.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant, or no pending credential of that User has that ID. Nothing is written.</exception>
    [StateChanging]
    Task<Secret<string>> IssueVerificationLinkAsync(
        CommandContext context, Guid userId, Guid credentialId, Guid? applicationId, CancellationToken cancellationToken);

    /// <summary>The credential <paramref name="credentialId"/>'s state, or null when the context's Tenant has none. It writes nothing.</summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<CredentialState?> FindCredentialAsync(CommandContext context, Guid credentialId, CancellationToken cancellationToken);

    /// <summary>
    /// The verification link <paramref name="token"/> is, in any state, locked until the caller's transaction ends (Story 4.7).
    /// A value without a link's shape, or whose prefix isn't the context Tenant's public ID, is refused before any lookup:
    /// null, as for an unknown one. It writes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<VerificationLink?> FindVerificationLinkAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken);

    /// <summary>
    /// Uses the verification link <paramref name="token"/> (Story 4.7), in one command: it is marked used, and when its
    /// User's email isn't verified yet, the email is marked verified, the link's credential activated, the User's every
    /// other pending credential deleted (their links with them) and the new hash kept in the User's password history, with
    /// <see cref="IdentityEvents.UserEmailVerified"/>. For a User already verified the link only marks itself used. A
    /// malformed, foreign, unknown, expired or used link changes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<EmailVerification> VerifyEmailAsync(CommandContext context, Secret<string> token, CancellationToken cancellationToken);

    /// <summary>The User's newest <paramref name="count"/> earlier password hashes, newest first (Story 4.7, for the history rule). It writes nothing.</summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<IReadOnlyList<string>> ReadPasswordHistoryAsync(CommandContext context, Guid userId, int count, CancellationToken cancellationToken);
}
