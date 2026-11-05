using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Core;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>What a composition root uses to wire Sessions.</summary>
public static class SessionsContract
{
    /// <summary>Sessions over the Kernel audit port. <paramref name="time"/> sets every expiry.</summary>
    public static ISessions CreateSessions(IAuditAppender audit, TimeProvider time) => new SessionService(audit, time);

    /// <summary>
    /// Sessions' Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>token</c>, then
    /// <c>authorization</c>, then <c>user_session</c> rows.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new SessionsPurge();
}
