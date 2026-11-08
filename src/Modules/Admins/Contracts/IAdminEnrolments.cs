using System.Buffers.Text;
using System.Security.Cryptography;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// A <c>gatekeep recover-admin</c> enrolment's value (Story 1.32, AD-31): 32 CSPRNG bytes written as
/// 43 base64url characters with no padding. Only <see cref="Hash"/> of it is ever stored, in
/// <c>admin_enrolment.value_sha256</c>, as <see cref="BootstrapToken"/>'s hash is.
/// </summary>
public static class AdminEnrolmentValue
{
    /// <summary>The value's length in characters.</summary>
    public const int Length = 43;

    private const int Bytes = 32;

    /// <summary>A fresh value as its 43 characters. The caller holds it only until it is printed.</summary>
    public static Secret<string> Generate()
    {
        Span<byte> random = stackalloc byte[Bytes];
        try
        {
            RandomNumberGenerator.Fill(random);
            return new Secret<string>(Base64Url.EncodeToString(random));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    /// <summary>
    /// The SHA-256 of the 32 bytes <paramref name="submitted"/> spells, or null when it isn't a value:
    /// exactly 43 base64url characters in their one canonical spelling. It never throws on input.
    /// </summary>
    public static byte[]? Hash(string? submitted)
    {
        // Only the alphabet is decoded at all; anything else is refused unread.
        if (submitted is null
            || submitted.Length != Length
            || !submitted.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
        {
            return null;
        }

        Span<byte> raw = stackalloc byte[Bytes];
        try
        {
            if (!Base64Url.TryDecodeFromChars(submitted, raw, out var written) || written != Bytes)
            {
                return null;
            }

            // One spelling only: the last character's unused bits must be zero.
            Span<char> canonical = stackalloc char[Length];
            if (!Base64Url.TryEncodeToChars(raw, canonical, out var chars) || chars != Length || !canonical.SequenceEqual(submitted))
            {
                return null;
            }

            return SHA256.HashData(raw);
        }
        catch (FormatException)
        {
            // The decoder throws, rather than returning false, on a last character with its unused bits set.
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }
}

/// <summary>An Admin <c>recover-admin</c> may choose: their ID and their public <c>adm_</c> ID.</summary>
public sealed record EnrolmentCandidate(Guid AdminId, string PublicId);

/// <summary>What <c>recover-admin</c> reads before it sends anything: every Admin, oldest first, and the database's time now.</summary>
public sealed record EnrolmentCandidates(IReadOnlyList<EnrolmentCandidate> Admins, DateTimeOffset Now);

/// <summary>
/// One enrolment, decided before anything is sent: its ID, its Admin, and its issue and expiry
/// times from the database clock, 15 minutes apart. The alert and the record carry exactly these.
/// </summary>
public sealed record AdminEnrolment(Guid Id, Guid AdminId, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

/// <summary>
/// Issues <c>gatekeep recover-admin</c>'s enrolments (Story 1.32). It runs as <c>gk_cli</c>, in a
/// Deployment scope; only <c>Gatekeep.Cli</c> references it, and no HTTP route or job does.
/// </summary>
public interface IAdminEnrolmentIssuer
{
    /// <summary>Every Admin, oldest first, and the database's <c>clock_timestamp()</c>. No Admin means bootstrap isn't complete.</summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    Task<EnrolmentCandidates> ReadAsync(CommandContext context, CancellationToken cancellationToken);

    /// <summary>
    /// The enrolment for <paramref name="adminId"/> issued at <paramref name="issuedAt"/>, a time
    /// <see cref="ReadAsync"/> returned: a new UUIDv7 and the expiry <see cref="Kernel.Limits.SecurityLimits.AdminEnrolmentLifetime"/> later. Nothing is written.
    /// </summary>
    AdminEnrolment Plan(Guid adminId, DateTimeOffset issuedAt);

    /// <summary>
    /// Stores <paramref name="enrolment"/> with only the SHA-256 of <paramref name="value"/>
    /// (<see cref="AdminEnrolmentValue.Hash"/>) and appends <see cref="AdminsEvents.EnrolmentIssued"/>,
    /// in the context's Deployment transaction. The database refuses an issue time later than now
    /// or a lifetime ago, so a run slower than that issues nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    /// <exception cref="ArgumentException">The value isn't one <see cref="AdminEnrolmentValue.Generate"/> makes.</exception>
    [StateChanging]
    Task IssueAsync(CommandContext context, AdminEnrolment enrolment, Secret<string> value, CancellationToken cancellationToken);
}

/// <summary>A redeemed enrolment's Session, and whether its Admin meets the credential floor, by the rule the Session read uses.</summary>
public sealed record EnrolmentRedemption(AdminSessionGrant Session, bool SetupComplete);

/// <summary>
/// Redeems <c>recover-admin</c> enrolments at sign-in (Story 1.32). It runs as <c>gk_admin</c>, in
/// a Deployment scope.
/// </summary>
public interface IAdminEnrolments
{
    /// <summary>
    /// Redeems <paramref name="value"/>: when its SHA-256 names an unused enrolment that hasn't
    /// expired, locked <c>FOR UPDATE</c>, sets its <c>used_at</c> and that of every other unused
    /// enrolment of its Admin, ends every live Session of its
    /// Admin as <c>revoked</c> (<see cref="AdminsEvents.SessionRevoked"/> each), supersedes the live
    /// Session <paramref name="presentedSession"/> names as sign-in does, starts a setup Session
    /// for an Admin below the credential floor and a recovery Session otherwise, and appends
    /// <see cref="AdminsEvents.EnrolmentUsed"/>, all in the caller's transaction. Null, with
    /// nothing written, for any other value: unknown, used, expired or malformed.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<EnrolmentRedemption?> RedeemAsync(
        CommandContext context,
        Secret<string> value,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);
}
