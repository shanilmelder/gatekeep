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

/// <summary>User Sessions (AD-12). Sessions owns <c>user_session</c>, <c>authorization</c> and <c>token</c>.</summary>
public interface ISessions
{
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
}
