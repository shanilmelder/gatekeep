using System.Security.Cryptography;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Core;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// An Admin Session's kind. A setup Session may call only setup-allowed endpoints. Registering
/// the Admin's second credential makes it full (Story 1.22); sign-in starts a full one (Story 1.23).
/// </summary>
public enum AdminSessionKind
{
    Setup,
    Full,

    /// <summary>
    /// Started by redeeming a Recovery Code (Story 1.26): it reaches only the recovery-allowed
    /// endpoints, whatever the Admin holds, and a registration makes it full.
    /// </summary>
    Recovery,
}

/// <summary>
/// One authenticated Admin Session. Its CSRF token is derived from the Session ID
/// (<see cref="SessionSecrets.DeriveCsrf"/>), so it is the same in every tab and nothing about it
/// is stored; this keeps the derived bytes only, never the ID, and compares in constant time.
/// </summary>
public sealed class AdminSession
{
    private readonly byte[] _csrf;

    internal AdminSession(Guid id, Guid adminId, AdminSessionKind kind, bool deploymentOwner, int credentials, bool recoveryCode, byte[] csrf)
    {
        Id = id;
        AdminId = adminId;
        Kind = kind;
        DeploymentOwner = deploymentOwner;
        Credentials = credentials;
        RecoveryCode = recoveryCode;
        _csrf = csrf;
    }

    public Guid Id { get; }

    public Guid AdminId { get; }

    public AdminSessionKind Kind { get; }

    public bool DeploymentOwner { get; }

    /// <summary>The WebAuthn credentials the Admin had when the Session was authenticated.</summary>
    public int Credentials { get; }

    /// <summary>
    /// Whether the Admin held a confirmed, unused offline Recovery Code when the Session was
    /// authenticated (Story 1.26).
    /// </summary>
    public bool RecoveryCode { get; }

    /// <summary>
    /// Whether the Admin meets the credential floor (FR-2, FR-46): the
    /// <see cref="AdminsContract.RequiredCredentials"/> credentials, or exactly one and a confirmed,
    /// unused Recovery Code (Story 1.26). The <c>admin_credential</c> and <c>admin_recovery_code</c>
    /// rows are authoritative for this and for <see cref="Restricted"/>; <c>admin.setup_completed_at</c>
    /// is only a set-once stamp of when setup completed, for the record, and nothing reads it to
    /// decide access.
    /// </summary>
    public bool SetupComplete => MeetsFloor(Credentials, RecoveryCode);

    /// <summary>
    /// Whether the Session may reach only setup-allowed endpoints: a setup or recovery Session, and
    /// any Session of an Admin who doesn't meet the credential floor, whatever its kind. A recovery
    /// Session reaches only the recovery-allowed ones among them.
    /// </summary>
    public bool Restricted => Kind != AdminSessionKind.Full || !SetupComplete;

    /// <summary>
    /// Whether the Admin may take an offline Recovery Code instead of a second credential (Story
    /// 1.26): only in a setup Session, only for an Admin who isn't the Deployment Owner (FR-2), with
    /// exactly one credential and no confirmed, unused code.
    /// </summary>
    public bool RecoveryCodeAllowed =>
        Kind == AdminSessionKind.Setup && !DeploymentOwner && Credentials == 1 && !RecoveryCode;

    /// <summary>The credential floor: two credentials, or exactly one with a confirmed, unused Recovery Code.</summary>
    public static bool MeetsFloor(int credentials, bool recoveryCode) =>
        credentials >= AdminsContract.RequiredCredentials || (credentials == 1 && recoveryCode);

    /// <summary>The Session's CSRF token, for the Session endpoint to return.</summary>
    public Secret<string> CsrfToken => new(SessionSecrets.Encode(_csrf));

    /// <summary>Whether <paramref name="submitted"/> is this Session's CSRF token. A missing or malformed one isn't.</summary>
    public bool CsrfMatches(string? submitted)
    {
        Span<byte> decoded = stackalloc byte[SessionSecrets.Bytes];
        try
        {
            return SessionSecrets.TryDecode(submitted, decoded) && CryptographicOperations.FixedTimeEquals(decoded, _csrf);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    public override string ToString() => $"AdminSession {Id}";
}

/// <summary>
/// Admin Sessions (Story 1.21, PRD §5.2): 30 minutes idle, slid by each authenticated request,
/// and 8 hours absolute. They run as <c>gk_admin</c>, in a Deployment scope; times come from the
/// database clock.
/// </summary>
public interface IAdminSessions
{
    /// <summary>
    /// The Session whose ID is <paramref name="sessionToken"/>, with its idle expiry slid forward,
    /// never past the absolute one. Null for a malformed, unknown or ended Session, and for an
    /// expired one, which it ends with <c>expired</c>: the caller commits either way.
    /// </summary>
    [StateChanging]
    Task<AdminSession?> AuthenticateAsync(CommandContext context, Secret<string> sessionToken, CancellationToken cancellationToken);

    /// <summary>
    /// Ends the Session with <c>signed_out</c> and appends <see cref="AdminsEvents.SessionSignedOut"/>,
    /// in the caller's transaction, and returns true. Ending an ended Session changes nothing,
    /// audits nothing and returns false.
    /// </summary>
    [StateChanging]
    Task<bool> EndAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken);
}
