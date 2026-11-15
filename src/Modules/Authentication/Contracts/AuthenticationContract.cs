using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Modules.Authentication.Core;
using Gatekeep.Modules.Sessions.Contracts;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>What a composition root uses to wire Authentication.</summary>
public static class AuthenticationContract
{
    /// <summary>
    /// Token requests per Tenant (Story 2.5, PRD §5.2): 1200 in a fixed minute at one Tenant's token
    /// endpoint, under the one subject <see cref="TenantSubject"/>, counted before the client is authenticated.
    /// </summary>
    public static readonly RateLimitPolicy TokenRequestTenantPolicy = new(
        "authentication.token_request.tenant",
        SecurityLimits.TokenRequestTenantAttempts,
        SecurityLimits.TokenRequestWindow);

    /// <summary>
    /// Token requests per source (Story 2.5, PRD §5.2): 60 in a fixed minute from one IPv4 address or
    /// IPv6 /64 at one Tenant's token endpoint, counted with the Tenant's.
    /// </summary>
    public static readonly RateLimitPolicy TokenRequestSourcePolicy = new(
        "authentication.token_request.source",
        SecurityLimits.TokenRequestSourceAttempts,
        SecurityLimits.TokenRequestWindow);

    /// <summary>
    /// Unauthenticated cross-Tenant mismatches per source (Story 2.5, AD-9): every one is counted in the
    /// probed Tenant's counters, for an hour. It only measures; the mismatch is refused alike either way.
    /// </summary>
    public static readonly RateLimitPolicy CrossTenantMismatchPolicy = new(
        "authentication.cross_tenant.mismatch",
        SecurityLimits.CrossTenantMismatchCountedAttempts,
        SecurityLimits.CrossTenantMismatchLogWindow);

    /// <summary>
    /// Which unauthenticated cross-Tenant mismatches reach the probed Tenant's Log (Story 2.5, AD-9): the
    /// first per source per hour. Every later one in that hour is refused alike but only counted.
    /// </summary>
    public static readonly RateLimitPolicy CrossTenantMismatchLogPolicy = new(
        "authentication.cross_tenant.logged",
        1,
        SecurityLimits.CrossTenantMismatchLogWindow);

    /// <summary>The fixed subject a per-Tenant limit is counted under.</summary>
    public const string TenantSubject = "tenant";

    /// <summary>
    /// Sign-in over the Kernel audit port. <paramref name="time"/> sets every expiry. Sessions are issued through
    /// Sessions' own <c>ISessions</c>, and the step after Login's email is <paramref name="credentialStep"/>'s:
    /// <see cref="NoCredentialStep"/>, which offers none, unless one is given (only the tests give one, Story 4.2).
    /// </summary>
    public static IAuthentication CreateAuthentication(IAuditAppender audit, TimeProvider time, ICredentialStep? credentialStep = null) =>
        new AuthenticationService(audit, time, SessionsContract.CreateSessions(audit, time), credentialStep ?? NoCredentialStep);

    /// <summary>
    /// The release build's credential step (Story 4.2): it offers none, so a sign-in past Login's email can't
    /// continue until Story 4.9's password step. It is the only credential step in <c>src</c>.
    /// </summary>
    public static ICredentialStep NoCredentialStep { get; } = new NoCredentialStep();

    /// <summary>
    /// Login's email as a sign-in records it (Story 4.2): the input trimmed, when that is a valid address of at
    /// most 254 characters: one <c>@</c> with a local part and a dotted domain, and no whitespace or control
    /// character. False otherwise, and Login shows "Enter a valid email address." with nothing written.
    /// </summary>
    public static bool TryNormalizeEmail(string? input, out string email)
    {
        email = string.Empty;
        var trimmed = input?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > SecurityLimits.MaxEmailLength
            || trimmed.Any(static c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            return false;
        }

        var at = trimmed.LastIndexOf('@');
        if (at <= 0 || at != trimmed.IndexOf('@') || at == trimmed.Length - 1)
        {
            return false;
        }

        var domain = trimmed[(at + 1)..];
        if (!domain.Contains('.', StringComparison.Ordinal) || domain.StartsWith('.') || domain.EndsWith('.')
            || domain.Contains("..", StringComparison.Ordinal)
            || !System.Net.Mail.MailAddress.TryCreate(trimmed, out var parsed)
            || !string.Equals(parsed.Address, trimmed, StringComparison.Ordinal))
        {
            return false;
        }

        email = trimmed;
        return true;
    }

    /// <summary>
    /// The Kernel <see cref="IRateLimiter"/> for Tenant attempts, such as token requests (AD-14, Story
    /// 2.5). It counts in <c>tenant_attempt</c>, keyed by the context's Tenant, and serves a Tenant scope
    /// only: in a Deployment one it throws <see cref="InvalidOperationException"/> and writes nothing.
    /// It runs as <c>gk_hosted</c>, and as <c>gk_worker</c> for the email send job's per-recipient limit (Story 4.5): the
    /// only roles that count there.
    /// </summary>
    public static IRateLimiter CreateAttemptLimiter() => new TenantAttemptLimiter();

    /// <summary>
    /// Authentication's Tenant purge (Story 1.29, AD-30): deletes the context Tenant's
    /// <c>signin_transaction</c> and <c>tenant_attempt</c> rows.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new AuthenticationPurge();

    /// <summary>
    /// Authentication's purge of deleted Applications (Story 3.5, AD-30): deletes the context Tenant's
    /// <c>signin_transaction</c> rows of <paramref name="applicationIds"/>. Directory names the deleted Applications; an
    /// empty list deletes nothing. A second run deletes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task PurgeApplicationsAsync(CommandContext context, IReadOnlyCollection<Guid> applicationIds, CancellationToken cancellationToken) =>
        AuthenticationPurge.PurgeApplicationsAsync(context, applicationIds, cancellationToken);

    /// <summary>
    /// Authentication's purge of expired state (Story 4.3, FR-8, AD-12): deletes the context Tenant's
    /// <c>signin_transaction</c> rows whose <c>expires_at</c> is at least <see cref="SecurityLimits.SignInRestartRetention"/>
    /// before <paramref name="now"/>, completed or not, with the email each kept. A second run deletes nothing.
    /// </summary>
    /// <returns>How many transactions it deleted.</returns>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<int> PurgeExpiredStateAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken) =>
        AuthenticationExpiredStatePurge.PurgeAsync(context, now, cancellationToken);
}
