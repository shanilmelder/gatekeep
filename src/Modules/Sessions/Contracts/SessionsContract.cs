using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Adapters;
using Gatekeep.Modules.Sessions.Core;
using OpenIddict.Abstractions;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>What a composition root uses to wire Sessions.</summary>
public static class SessionsContract
{
    /// <summary>Sessions over the Kernel audit port. <paramref name="time"/> sets every expiry.</summary>
    public static ISessions CreateSessions(IAuditAppender audit, TimeProvider time) => new SessionService(audit, time);

    /// <summary>
    /// OpenIddict's token store (AD-8: each store lives in its owner), minimal for Client Credentials
    /// (Story 2.5): it makes and creates <c>token</c> rows in <paramref name="context"/>'s result, the
    /// request's own Tenant context, and refuses every other call until Story 2.9.
    /// </summary>
    public static IOpenIddictTokenStore<SessionsToken> CreateTokenStore(Func<CommandContext> context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return new TokenStore(context);
    }

    /// <summary>
    /// OpenIddict's authorization store, registered so its manager can be built: every call throws
    /// <see cref="NotSupportedException"/> until Story 2.9, as Client Credentials creates no authorization.
    /// </summary>
    public static IOpenIddictAuthorizationStore<SessionsAuthorization> CreateAuthorizationStore() => new AuthorizationStore();

    /// <summary>
    /// Sessions' Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>token</c>, then
    /// <c>authorization</c>, then <c>user_session</c> rows.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new SessionsPurge();
}
