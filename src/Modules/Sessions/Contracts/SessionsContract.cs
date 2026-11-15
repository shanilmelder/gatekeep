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

    /// <summary>
    /// The authorization property a new Token Family keeps its sign-in's authentication time in (Story 4.2, OIDC Core
    /// §12.2): ISO 8601 UTC text. A refresh's ID token carries it, not the Session's, which a later sign-in rotating the
    /// Session replaces. A family created before has none, and reads the Session's.
    /// </summary>
    public const string FamilyAuthTimeProperty = ".gatekeep_auth_time";

    /// <summary>The authorization property a new Token Family keeps its sign-in's authentication methods in, as a JSON array (Story 4.2).</summary>
    public const string FamilyAmrProperty = ".gatekeep_amr";

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

    /// <summary>
    /// Sessions' purge of deleted Applications (Story 3.5, AD-30): deletes the context Tenant's <c>token</c> rows of
    /// <paramref name="applicationIds"/> or of their Token Families, then those <c>authorization</c> rows. It ends no
    /// Session. Directory names the deleted Applications; an empty list deletes nothing. A second run deletes nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task PurgeApplicationsAsync(CommandContext context, IReadOnlyCollection<Guid> applicationIds, CancellationToken cancellationToken) =>
        SessionsApplicationPurge.PurgeAsync(context, applicationIds, cancellationToken);

    /// <summary>
    /// Sessions' purge of expired state (Story 4.3, FR-8, AD-13): deletes the context Tenant's <c>token</c> rows whose
    /// <c>expiration_date</c> is at or before <paramref name="now"/>, then the <c>authorization</c> rows (Token Families)
    /// no token references, then the <c>user_session</c> rows that are over (ended, or idle or absolute expiry at or
    /// before <paramref name="now"/>) and that no family anchors. A live Session, and a family with any unexpired
    /// token, always stay. It writes no event: its caller writes <see cref="SessionsEvents.ExpiredStatePurged"/> once
    /// for its whole run. A second run deletes nothing.
    /// </summary>
    /// <returns>How many rows it deleted, over the three tables.</returns>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    public static Task<int> PurgeExpiredStateAsync(CommandContext context, DateTimeOffset now, CancellationToken cancellationToken) =>
        SessionsExpiredStatePurge.PurgeAsync(context, now, cancellationToken);
}
