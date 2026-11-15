using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Identity.Core;

namespace Gatekeep.Modules.Identity.Contracts;

/// <summary>What composition roots and other modules use to reach Identity.</summary>
public static class IdentityContract
{
    /// <summary>
    /// Identity's Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>user</c> rows.
    /// Tenant deletion calls it after Sessions' purge, whose rows reference them.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new IdentityPurge();

    /// <summary>
    /// The context Tenant's User's email address, read now, or null when there is no such User or it has no email
    /// (Story 4.5). It writes nothing. Host.Worker reads only the User's ID and email.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context isn't a Tenant's.</exception>
    public static Task<string?> ReadEmailAsync(CommandContext context, Guid userId, CancellationToken cancellationToken) =>
        UserEmails.ReadAsync(context, userId, cancellationToken);
}
