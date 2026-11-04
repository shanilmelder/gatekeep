using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// An offline Admin Recovery Code's value (Story 1.26): 16 characters from Crockford's base32
/// alphabet (<c>0–9</c> and <c>A–Z</c> without <c>I L O U</c>), 80 bits, shown as
/// <c>XXXX-XXXX-XXXX-XXXX</c>. Input is normalized before any check: uppercase, hyphens and spaces removed,
/// <c>O</c> read as <c>0</c> and <c>I</c> and <c>L</c> as <c>1</c>.
/// </summary>
public static class AdminRecoveryCode
{
    public const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public const int Length = 16;

    /// <summary>The longest input read at all: anything longer is refused unread.</summary>
    public const int MaxInputLength = 64;

    /// <summary>
    /// <paramref name="input"/> normalized to its 16 alphabet characters, or null when it isn't one
    /// once normalized.
    /// </summary>
    public static string? Normalize(string? input)
    {
        if (input is null || input.Length > MaxInputLength)
        {
            return null;
        }

        var chars = new List<char>(Length);
        foreach (var c in input)
        {
            if (c is '-' or ' ')
            {
                continue;
            }

            var upper = char.ToUpperInvariant(c);
            var read = upper switch
            {
                'O' => '0',
                'I' or 'L' => '1',
                _ => upper,
            };
            if (Alphabet.IndexOf(read, StringComparison.Ordinal) < 0 || chars.Count == Length)
            {
                return null;
            }

            chars.Add(read);
        }

        return chars.Count == Length ? new string([.. chars]) : null;
    }

    /// <summary>A normalized code as it is shown: <c>XXXX-XXXX-XXXX-XXXX</c>.</summary>
    public static string Display(string normalized)
    {
        ArgumentNullException.ThrowIfNull(normalized);
        if (normalized.Length != Length)
        {
            throw new ArgumentException("A code is 16 characters.", nameof(normalized));
        }

        return string.Join('-', normalized.Chunk(4).Select(group => new string(group)));
    }
}

/// <summary>What an issue or a confirmation came to.</summary>
public enum RecoveryCodeStatus
{
    Accepted,

    /// <summary>Not allowed here: not a setup Session, the Deployment Owner, not exactly one credential, or a confirmed code already.</summary>
    Refused,

    /// <summary>The issue named isn't the Admin's current unconfirmed code: a later issue replaced it, or there is none. Nothing changed.</summary>
    Superseded,
}

/// <summary>
/// A newly issued code, shown once, and its issue's ID, which the confirmation names so it confirms
/// exactly this code. Only its HMAC was stored, unconfirmed.
/// </summary>
public sealed record RecoveryCodeIssue(RecoveryCodeStatus Status, Secret<string>? Code, Guid? IssueId = null);

/// <summary>A redeemed code's recovery Session, and whether its Admin meets the floor, by the rule the Session read uses.</summary>
public sealed record RecoveryCodeRedemption(AdminSessionGrant Session, bool SetupComplete);

/// <summary>
/// Admin Recovery Codes (Story 1.26, FR-46): one offline code an Admin who isn't the Deployment
/// Owner may take at setup instead of a second credential. It is stored only as
/// <c>HMAC(dep-hmac, "gatekeep-admin-recovery-code\0" + code)</c> with its key version, never as
/// the code or a ciphertext: Host.Admin decrypts nothing (AD-10). Redeemed once, it starts a
/// recovery Session, which reaches only credential registration. Every call runs as
/// <c>gk_admin</c>, in a Deployment scope. A key custody failure throws
/// <see cref="KeyCustodyException"/> before anything is written.
/// </summary>
public interface IAdminRecoveryCodes
{
    /// <summary>
    /// Issues a code to <paramref name="session"/>'s Admin, when <see cref="AdminSession.RecoveryCodeAllowed"/>
    /// still holds under the Admin's row lock: deletes their unconfirmed code, if any, and stores
    /// the new one's HMAC unconfirmed, in the caller's transaction. An unconfirmed code can't be
    /// redeemed; a new issue voids it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<RecoveryCodeIssue> IssueAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Confirms the Admin saved the code <paramref name="issueId"/> issued, when it is still their
    /// unconfirmed one, and otherwise changes nothing (<see cref="RecoveryCodeStatus.Superseded"/>): sets its <c>confirmed_at</c> and appends
    /// <see cref="AdminsEvents.RecoveryCodeIssued"/>. The Admin then meets the floor, so their setup
    /// and recovery Sessions become full and <see cref="AdminsEvents.SetupCompleted"/> is appended.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<RecoveryCodeStatus> ConfirmAsync(CommandContext context, AdminSession session, Guid issueId, CancellationToken cancellationToken);

    /// <summary>
    /// Redeems <paramref name="code"/>: when it normalizes, and its HMAC names a confirmed, unused
    /// code, marks it used, ends every live Session of its Admin as <c>revoked</c>
    /// (<see cref="AdminsEvents.SessionRevoked"/> each), supersedes the live Session
    /// <paramref name="presentedSession"/> names as sign-in does, starts a recovery Session and
    /// appends <see cref="AdminsEvents.RecoveryCodeUsed"/>, all in the caller's transaction. Null,
    /// with nothing written, for any other code: wrong, unconfirmed, used or malformed.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<RecoveryCodeRedemption?> RedeemAsync(
        CommandContext context,
        Secret<string> code,
        Secret<string>? presentedSession,
        CancellationToken cancellationToken);
}
