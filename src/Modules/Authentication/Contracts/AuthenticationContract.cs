using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Modules.Authentication.Core;

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

    /// <summary>Sign-in over the Kernel audit port. <paramref name="time"/> sets every expiry.</summary>
    public static IAuthentication CreateAuthentication(IAuditAppender audit, TimeProvider time) =>
        new AuthenticationService(audit, time);

    /// <summary>
    /// The Kernel <see cref="IRateLimiter"/> for Tenant attempts, such as token requests (AD-14, Story
    /// 2.5). It counts in <c>tenant_attempt</c>, keyed by the context's Tenant, and serves a Tenant scope
    /// only: in a Deployment one it throws <see cref="InvalidOperationException"/> and writes nothing.
    /// It runs as <c>gk_hosted</c>, the only role that counts there.
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
}
