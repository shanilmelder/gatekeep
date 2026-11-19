using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Identity.Core;

namespace Gatekeep.Modules.Identity.Contracts;

/// <summary>What composition roots and other modules use to reach Identity.</summary>
public static class IdentityContract
{
    /// <summary>
    /// Identity's Tenant purge (Story 1.29, AD-30): deletes the context Tenant's verification links, password credentials,
    /// password history and <c>user</c> rows. Tenant deletion calls it after Sessions' and Authentication's purges, whose
    /// rows reference them.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new IdentityPurge();

    /// <summary>
    /// The context Tenant's User's email address, read now, or null when there is no such User or it has no email
    /// (Story 4.5). It writes nothing. Host.Worker reads only the User's ID and email.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    public static Task<string?> ReadEmailAsync(CommandContext context, Guid userId, CancellationToken cancellationToken) =>
        UserEmails.ReadAsync(context, userId, cancellationToken);

    /// <summary>
    /// Users, their password credentials and their verification links (Story 4.7), with every event through
    /// <paramref name="audit"/> and every time from <paramref name="time"/>.
    /// </summary>
    public static IIdentity CreateIdentity(IAuditAppender audit, TimeProvider time) => new IdentityService(audit, time);

    /// <summary>
    /// Whether <paramref name="token"/> has a verification link's shape (Story 4.7): <c>{tenantPublicId}.{base64url of 32
    /// bytes}</c>, for any Tenant. A link page keeps only such a value, for "Send a new link".
    /// </summary>
    public static bool IsVerificationLinkShaped(string? token) => VerificationLinks.IsShaped(token);

    /// <summary>The SHA-256 a verification link <paramref name="token"/> is stored as: of the whole value's ASCII text.</summary>
    public static byte[] VerificationLinkHash(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        return VerificationLinks.Hash(token);
    }

    /// <summary>
    /// Identity's purge of expired state (Story 4.7, AD-12): deletes the context Tenant's verification links whose
    /// <c>expires_at</c> is at least <see cref="Gatekeep.Kernel.Limits.SecurityLimits.OneTimeTokenRetention"/> before
    /// <paramref name="now"/>, used or not. A second run deletes nothing.
    /// </summary>
    /// <returns>How many links it deleted.</returns>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<int> PurgeExpiredStateAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken) =>
        IdentityExpiredStatePurge.PurgeAsync(context, now, cancellationToken);
}
