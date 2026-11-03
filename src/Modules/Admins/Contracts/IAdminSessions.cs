using System.Security.Cryptography;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Core;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// An Admin Session's kind. A setup Session may call only setup-allowed endpoints until the
/// Admin's credentials are registered (Story 1.22). A full Session comes from sign-in (Story 1.23).
/// </summary>
public enum AdminSessionKind
{
    Setup,
    Full,
}

/// <summary>
/// One authenticated Admin Session. Its CSRF token is derived from the Session ID
/// (<see cref="SessionSecrets.DeriveCsrf"/>), so it is the same in every tab and nothing about it
/// is stored; this keeps the derived bytes only, never the ID, and compares in constant time.
/// </summary>
public sealed class AdminSession
{
    private readonly byte[] _csrf;

    internal AdminSession(Guid id, Guid adminId, AdminSessionKind kind, bool deploymentOwner, bool setupComplete, byte[] csrf)
    {
        Id = id;
        AdminId = adminId;
        Kind = kind;
        DeploymentOwner = deploymentOwner;
        SetupComplete = setupComplete;
        _csrf = csrf;
    }

    public Guid Id { get; }

    public Guid AdminId { get; }

    public AdminSessionKind Kind { get; }

    public bool DeploymentOwner { get; }

    public bool SetupComplete { get; }

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

    /// <summary>Ends the Session with <c>signed_out</c>. Ending an ended Session changes nothing.</summary>
    [StateChanging]
    Task EndAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken);
}
