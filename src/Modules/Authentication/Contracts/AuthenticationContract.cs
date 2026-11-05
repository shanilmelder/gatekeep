using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Authentication.Core;

namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>What a composition root uses to wire Authentication.</summary>
public static class AuthenticationContract
{
    /// <summary>Sign-in over the Kernel audit port. <paramref name="time"/> sets every expiry.</summary>
    public static IAuthentication CreateAuthentication(IAuditAppender audit, TimeProvider time) =>
        new AuthenticationService(audit, time);

    /// <summary>Authentication's Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>signin_transaction</c> rows.</summary>
    public static ITenantPurge TenantPurge { get; } = new AuthenticationPurge();
}
