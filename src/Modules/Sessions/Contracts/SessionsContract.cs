using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Sessions.Adapters;
using Gatekeep.Modules.Sessions.Core;
using OpenIddict.Abstractions;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>What a composition root uses to wire Sessions.</summary>
public static class SessionsContract
{
    /// <summary>
    /// The authorization property a new ad-hoc authorization names its Session in (Story 2.9, AD-13):
    /// the <c>user_session</c> ID, as text. The authorization store moves it into
    /// <c>authorization.user_session_id</c> and never stores it as a property; a create without it is refused.
    /// </summary>
    public const string SessionAnchorProperty = ".gatekeep_user_session_id";

    /// <summary>Sessions over the Kernel audit port. <paramref name="time"/> sets every expiry.</summary>
    public static ISessions CreateSessions(IAuditAppender audit, TimeProvider time) => new SessionService(audit, time);

    /// <summary>
    /// OpenIddict's token store (AD-8: each store lives in its owner), for Client Credentials (Story 2.5)
    /// and the code grant (Story 2.9), on <paramref name="request"/>'s Tenant context. A replayed code's
    /// family revocation goes to <paramref name="sessions"/>' <see cref="ISessions.RevokeAccessAsync"/>,
    /// recorded on the request first. Every call the code grant doesn't make throws.
    /// </summary>
    public static IOpenIddictTokenStore<SessionsToken> CreateTokenStore(StoreRequest request, ISessions sessions)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(sessions);
        return new TokenStore(request, sessions);
    }

    /// <summary>
    /// OpenIddict's authorization store (Story 2.9), on <paramref name="request"/>'s Tenant context: it
    /// creates the one ad-hoc authorization of a completed code flow, anchored to its Session by
    /// <see cref="SessionAnchorProperty"/>, and finds one. Every other call throws.
    /// </summary>
    public static IOpenIddictAuthorizationStore<SessionsAuthorization> CreateAuthorizationStore(StoreRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new AuthorizationStore(request);
    }

    /// <summary>
    /// Sessions' Tenant purge (Story 1.29, AD-30): deletes the context Tenant's <c>token</c>, then
    /// <c>authorization</c>, then <c>user_session</c> rows.
    /// </summary>
    public static ITenantPurge TenantPurge { get; } = new SessionsPurge();
}
