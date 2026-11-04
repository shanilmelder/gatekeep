using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.WebAuthn;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>
/// The actions a fresh WebAuthn assertion can confirm (Story 1.26, FR-46): every capability whose
/// <see cref="Capability.FreshAssertion"/> isn't <see cref="FreshAssertion.Never"/>, by its name,
/// and the self-service actions below. Nothing else is an action.
/// </summary>
public static class AdminFreshAssertions
{
    /// <summary>Registering another credential from Your credentials, in a full Session.</summary>
    public const string SelfCredentialsAdd = "self.credentials.add";

    /// <summary>Removing one of the Admin's own credentials, its row's public ID the target.</summary>
    public const string SelfCredentialsRemove = "self.credentials.remove";

    /// <summary>The self-service actions, which need only the Admin's Session.</summary>
    public static readonly IReadOnlyList<string> SelfActions = [SelfCredentialsAdd, SelfCredentialsRemove];

    /// <summary>Every action, the capabilities' in table order, then the self-service ones.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        .. AdminCapabilities.All.Where(c => c.FreshAssertion != FreshAssertion.Never).Select(c => c.Name),
        .. SelfActions,
    ];

    /// <summary>Whether <paramref name="action"/> is an action a fresh assertion can confirm.</summary>
    public static bool IsAction(string? action) => action is not null && All.Contains(action, StringComparer.Ordinal);

    /// <summary>The capability <paramref name="action"/> names, or null for a self-service action or none.</summary>
    public static Capability? CapabilityOf(string? action) =>
        action is null ? null : AdminCapabilities.All.FirstOrDefault(c => c.FreshAssertion != FreshAssertion.Never && c.Name == action);
}

/// <summary>
/// What one fresh assertion confirms: one action, in the path Tenant when there is one, on one
/// target exactly as the request names it, such as <c>acr_…</c>, never parsed. Its
/// <see cref="Hash"/>, <c>SHA-256(UTF-8(action + "\n" + tenantPublicId + "\n" + target))</c> with
/// empty strings for an absent Tenant or target, is the only form stored, and is made here only.
/// </summary>
public sealed record FreshAssertionBinding
{
    /// <exception cref="ArgumentException"><paramref name="action"/> isn't an action, or <paramref name="tenantId"/> is the empty UUID.</exception>
    public FreshAssertionBinding(string action, Guid? tenantId, string? target)
    {
        if (!AdminFreshAssertions.IsAction(action))
        {
            throw new ArgumentException("A fresh assertion binds only an action from AdminFreshAssertions.", nameof(action));
        }

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A path Tenant is never the empty UUID.", nameof(tenantId));
        }

        Action = action;
        TenantId = tenantId;
        Target = target;
    }

    public string Action { get; }

    public Guid? TenantId { get; }

    public string? Target { get; }

    /// <summary>The 32 bytes stored with the challenge and the grant.</summary>
    public byte[] Hash
    {
        get
        {
            var tenant = TenantId is { } id ? PublicId.Format(PublicIdType.Tenant, id) : string.Empty;
            return SHA256.HashData(Encoding.UTF8.GetBytes(Action + "\n" + tenant + "\n" + (Target ?? string.Empty)));
        }
    }

    /// <summary>Names the action only: the target goes in no log.</summary>
    public override string ToString() => $"FreshAssertionBinding {Action}";
}

/// <summary>A taken ceremony challenge: its SHA-256, and the binding it was begun for.</summary>
public sealed record FreshAssertionChallenge(byte[] ChallengeSha256, byte[] BindingHash);

/// <summary>What a fresh-assertion complete came to.</summary>
public enum FreshAssertionStatus
{
    /// <summary>Verified: the grant is stored and its event appended.</summary>
    Verified,

    /// <summary>
    /// Refused, with no grant. When <see cref="FreshAssertionOutcome.Audited"/>, the signature had
    /// verified over the Admin's own credential and its event was written in the caller's
    /// transaction, which the caller commits; otherwise nothing was written.
    /// </summary>
    Refused,
}

/// <summary>A finished ceremony: verified, or refused with why, for the caller's log only.</summary>
public sealed record FreshAssertionOutcome(FreshAssertionStatus Status, WebAuthnRefusal? Refusal, bool Audited)
{
    public static FreshAssertionOutcome Unattributed(WebAuthnRefusal refusal) => new(FreshAssertionStatus.Refused, refusal, false);
}

/// <summary>
/// Fresh WebAuthn assertions (Story 1.26, FR-46, §5.2's 5 minutes) over
/// <c>admin_fresh_assertion</c>. A grant is server-side: a row bound to one Admin Session and one
/// <see cref="FreshAssertionBinding"/>, made by an assertion with user verification from one of the
/// Session's Admin's own credentials, living 5 minutes from the database clock and used up by the
/// first request it matches. It never travels as a token. The ceremony is two calls: a begin that
/// stores one pending challenge for the Session, and a complete whose caller takes that challenge
/// in a transaction of its own and commits it, so it is used up whatever follows, then verifies
/// in another. Every step runs as <c>gk_admin</c>, in a Deployment scope. The caller counts each
/// begin and complete per Session under <see cref="AdminsContract.FreshAssertionPolicy"/> first.
/// </summary>
public interface IAdminFreshAssertions
{
    /// <summary>
    /// Begins a ceremony for <paramref name="binding"/>: in one transaction, deletes every expired
    /// row, the Session's pending challenge and any grant with the same binding, so only the newest
    /// confirmation counts, then stores a fresh 32-byte challenge as its SHA-256 with the binding.
    /// Returns the request options, user verification required and no credential listed.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<WebAuthnRequestOptions> BeginAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        FreshAssertionBinding binding,
        CancellationToken cancellationToken);

    /// <summary>
    /// Takes the Session's pending challenge: deletes it, expired or not, and returns it when it
    /// was still live. The caller commits this on its own, before anything is verified.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<FreshAssertionChallenge?> TakeChallengeAsync(CommandContext context, AdminSession session, CancellationToken cancellationToken);

    /// <summary>
    /// Verifies <paramref name="assertion"/> as sign-in does, locking the credential's row and its
    /// Admin's: the credential must be the Session's Admin's own, with their user handle, user
    /// verification, an unchanged BE flag and a counter that advances by compare-and-set, and its
    /// BS flag is stored. A pass stores the grant for 5 minutes and appends
    /// <see cref="AdminsEvents.FreshAssertionVerified"/>. A counter regression appends
    /// <see cref="AdminsEvents.CredentialSignCountRegressed"/> with the Session's Admin as Actor, a
    /// compare-and-set miss <see cref="AdminsEvents.FreshAssertionFailed"/>; every other refusal
    /// writes nothing and is only logged.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<FreshAssertionOutcome> FinishAsync(
        CommandContext context,
        AdminSession session,
        WebAuthnRelyingParty relyingParty,
        FreshAssertionChallenge challenge,
        WebAuthnAssertion assertion,
        CancellationToken cancellationToken);

    /// <summary>
    /// Uses up the Session's live grant for <paramref name="binding"/>, if there is one, and returns
    /// the row of the credential that made it, or null when there was none. The caller commits it before the action runs, so a grant is used up even
    /// when the action then fails, and a retried action needs a new confirmation (AD-30).
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has a Tenant.</exception>
    [StateChanging]
    Task<Guid?> ConsumeAsync(CommandContext context, AdminSession session, FreshAssertionBinding binding, CancellationToken cancellationToken);
}
