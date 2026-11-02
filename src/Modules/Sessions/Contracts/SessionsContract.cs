using Gatekeep.Kernel.Audit;
using Gatekeep.Modules.Sessions.Core;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>What a composition root uses to wire Sessions.</summary>
public static class SessionsContract
{
    /// <summary>Sessions over the Kernel audit port. <paramref name="time"/> sets every expiry.</summary>
    public static ISessions CreateSessions(IAuditAppender audit, TimeProvider time) => new SessionService(audit, time);
}
