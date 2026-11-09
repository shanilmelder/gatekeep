using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;

namespace Gatekeep.Modules.Sessions.Contracts;

/// <summary>
/// What a completed sign-in hands Sessions: the User, how they authenticated, when, and
/// through which Connection, if any.
/// </summary>
/// <param name="AuthTime">When the User authenticated. It is stored in UTC.</param>
public sealed record NewSession(Guid UserId, IReadOnlyList<string> Amr, DateTimeOffset AuthTime, Guid? ConnectionId = null);

/// <summary>
/// A started Session. <paramref name="Token"/> is the <c>__Host-gk_session</c> value: base64url
/// of 32 random bytes. Only its SHA-256 is stored, so it can't be read back. Times are in UTC,
/// truncated to the microseconds the row holds.
/// </summary>
public sealed record StartedSession(
    Guid SessionId,
    Secret<string> Token,
    DateTimeOffset AuthTime,
    DateTimeOffset IdleExpiresAt,
    DateTimeOffset AbsoluteExpiresAt);

/// <summary>
/// A Token Family (AD-13) as a refresh reads it (Story 2.10): its authorization's status and creation, from
/// which the absolute refresh limit counts, and the Session it is anchored to, whose User, authentication
/// methods and authentication time the refreshed tokens carry. Times are in UTC.
/// </summary>
/// <param name="IsValid">Whether the family's authorization is still <c>valid</c>, not revoked.</param>
/// <param name="CreatedAt">When the family's authorization was made, by its code flow.</param>
public sealed record TokenFamily(
    Guid AuthorizationId,
    bool IsValid,
    DateTimeOffset CreatedAt,
    Guid SessionId,
    Guid UserId,
    IReadOnlyList<string> Amr,
    DateTimeOffset AuthTime);

/// <summary>User Sessions (AD-12). Sessions owns <c>user_session</c>, <c>authorization</c> and <c>token</c>.</summary>
public interface ISessions
{
    /// <summary>
    /// The Token Family <paramref name="authorizationId"/> names in the context's Tenant, with its anchored
    /// Session, whether that Session has ended or expired or not: a Session's natural expiry doesn't end
    /// its families (AD-13), and its end revokes them. Null when there is none. Reads only.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant.</exception>
    Task<TokenFamily?> FindFamilyAsync(CommandContext context, Guid authorizationId, CancellationToken cancellationToken);

    /// <summary>
    /// Burns a presented refresh token (Story 2.10): a <c>valid</c> refresh token row becomes
    /// <c>redeemed</c>, as OpenIddict's redemption makes it, so it can never be used again. It is the effect
    /// a refresh refused after its token was redeemed keeps once the rest of its work is undone, since
    /// OpenIddict redeems the token before the new tokens are made. A row of another type, or not
    /// <c>valid</c>, doesn't change. Whether a row changed.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    [StateChanging]
    Task<bool> BurnRefreshTokenAsync(CommandContext context, Guid tokenId, CancellationToken cancellationToken);

    /// <summary>
    /// Writes a <c>user_session</c> row for the context's Tenant and one
    /// <c>sessions.session.started</c> audit event, both in the caller's context. Idle and
    /// absolute expiry are the §5.2 defaults from now.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException">The User ID is empty or no authentication method is given.</exception>
    /// <remarks>A User not in the context's Tenant fails on the foreign key, and the caller's scope must be discarded.</remarks>
    [StateChanging]
    Task<StartedSession> StartAsync(CommandContext context, NewSession session, CancellationToken cancellationToken);

    /// <summary>
    /// The one revocation path (AD-13, AR-23). Logout, every FR-48 trigger, refresh reuse, code
    /// replay, Application deletion and Tenant deletion all end access here, in the caller's
    /// context and only in its Tenant:
    /// <list type="bullet">
    /// <item><see cref="RevocationScope.Authorization"/>: that Token Family is set to <c>revoked</c>, with its tokens. No Session ends.</item>
    /// <item><see cref="RevocationScope.Session"/>: the Session ends, and every family anchored to it is revoked, with its tokens.</item>
    /// <item><see cref="RevocationScope.User"/>: every live Session of the User ends, and every family anchored to the User's
    /// Sessions is revoked, with its tokens. <paramref name="exceptSessionId"/>, the acting Session, and its families are left alone.</item>
    /// <item><see cref="RevocationScope.Application"/>: every family and every token of the Application is revoked. No Session ends.</item>
    /// <item><see cref="RevocationScope.Tenant"/>: every live Session ends, and every family and token is revoked.</item>
    /// </list>
    /// An ended Session gets <c>ended_at</c> and <paramref name="reason"/>'s code. A revoked family or token gets a new
    /// concurrency token, so an OpenIddict store holding the old row sees a conflict. Rows already ended or revoked
    /// don't change, so a repeated call returns zeros. Every call writes one <c>sessions.access.revoked</c> audit
    /// event by <paramref name="actor"/>, whose target is the User for User scope and absent otherwise. Access tokens
    /// are not revocable beyond their row's status. The method can run as the effect that a refused request keeps
    /// once the rest of its work is undone.
    /// </summary>
    /// <exception cref="InvalidOperationException">The context has no Tenant. Nothing is written.</exception>
    /// <exception cref="ArgumentException"><paramref name="exceptSessionId"/> is given with a scope other than User, or is empty.</exception>
    [StateChanging]
    Task<RevocationOutcome> RevokeAccessAsync(
        CommandContext context,
        RevocationScope scope,
        Guid? exceptSessionId,
        RevocationReason reason,
        Actor actor,
        CancellationToken cancellationToken);
}
