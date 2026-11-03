using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.WebAuthn;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>What a registration step came to.</summary>
public enum CredentialRegistrationStatus
{
    /// <summary>
    /// Begun: the options are out and the challenge is pending. Taken: a live challenge was
    /// pending and is now used up. Finished: the credential is stored.
    /// </summary>
    Accepted,

    /// <summary>
    /// Refused: no pending challenge, an expired or used one, or a response the ceremony refused.
    /// Nothing was stored.
    /// </summary>
    Refused,

    /// <summary>The Admin already has their two credentials: there is nothing to register here.</summary>
    Complete,

    /// <summary>The Session ended after the request checks authenticated it.</summary>
    SessionEnded,
}

/// <summary>A begun registration: the creation options when it was <see cref="CredentialRegistrationStatus.Accepted"/>.</summary>
public sealed record CredentialRegistrationStart(CredentialRegistrationStatus Status, WebAuthnCreationOptions? Options);

/// <summary>
/// A taken challenge: when <see cref="Status"/> is <see cref="CredentialRegistrationStatus.Accepted"/>,
/// the SHA-256 of the live challenge that was pending, which is pending no longer.
/// </summary>
public sealed record CredentialRegistrationChallenge(CredentialRegistrationStatus Status, byte[]? ChallengeSha256)
{
    public static CredentialRegistrationChallenge None { get; } = new(CredentialRegistrationStatus.Refused, null);
}

/// <summary>
/// A finished registration: how many credentials the Admin has now, and whether that completed
/// setup. A refused one says why, for the caller's log only.
/// </summary>
public sealed record CredentialRegistrationOutcome(
    CredentialRegistrationStatus Status,
    int Credentials,
    bool SetupComplete,
    WebAuthnRefusal? Refusal = null);

/// <summary>
/// Registers an Admin's WebAuthn credentials (Story 1.22, FR-2, FR-46) through the Kernel
/// <see cref="IWebAuthnVerifier"/>. An Admin with fewer than <see cref="AdminsContract.RequiredCredentials"/>
/// can do nothing else; the one that brings them to it ends setup, in the same transaction: every
/// live setup Session of theirs becomes <c>full</c>, and <see cref="AdminsEvents.SetupCompleted"/>
/// is written after the <see cref="AdminsEvents.CredentialRegistered"/> of each credential. Every
/// step runs as <c>gk_admin</c>, in a Deployment scope, and locks the Admin's row first, so two
/// registrations for one Admin take turns. A finish is two transactions: the caller takes the
/// challenge in its own, so the challenge is used up whatever happens after, then verifies and
/// stores in another. The caller counts each attempt under
/// <see cref="AdminsContract.CredentialRegistrationPolicy"/> first, in its own transaction.
/// </summary>
public interface IAdminCredentialRegistration
{
    /// <summary>
    /// Starts a registration for <paramref name="session"/>'s Admin: their WebAuthn user handle
    /// (made once, 64 random bytes), their credentials and transports as the exclude list, and a
    /// fresh 32-byte challenge, stored on the Session as its SHA-256 for 5 minutes, replacing any
    /// earlier one. <see cref="CredentialRegistrationStatus.Complete"/>, with nothing written, once
    /// the Admin has their two; <see cref="CredentialRegistrationStatus.SessionEnded"/> if the
    /// Session has ended since it was authenticated.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<CredentialRegistrationStart> BeginAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        CancellationToken cancellationToken);

    /// <summary>
    /// Takes the Session's pending challenge: clears it, and returns its SHA-256 when it was still
    /// live. The caller keeps this write on its own, before anything is verified, so the challenge
    /// can never answer twice, whatever fails after.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<CredentialRegistrationChallenge> TakeChallengeAsync(
        CommandContext context,
        AdminSession session,
        CancellationToken cancellationToken);

    /// <summary>
    /// Verifies <paramref name="attestation"/> against the challenge <see cref="TakeChallengeAsync"/>
    /// took. A refused finish stores nothing. An accepted one stores the credential and appends
    /// its event; the second also ends setup.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<CredentialRegistrationOutcome> FinishAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        byte[] challengeSha256,
        WebAuthnAttestation attestation,
        CancellationToken cancellationToken);
}
