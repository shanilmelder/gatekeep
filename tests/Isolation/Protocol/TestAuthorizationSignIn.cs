using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Gatekeep.Tests.Isolation.Sessions;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// The test host's sign-in (Story 2.9): it plugs <see cref="TestOnlyAuthenticator"/> into Protocol's
/// <see cref="IAuthorizationSignIn"/> port. It trusts the User ID a request names in
/// <see cref="UserHeader"/> and starts a Session for them, in the authorization request's own
/// transaction; a request naming none completes nothing, as the release build's sign-in does. Test only:
/// no <c>src</c> type implements the port but <see cref="UnavailableSignIn"/>.
/// </summary>
internal sealed class TestAuthorizationSignIn(TimeProvider time) : IAuthorizationSignIn
{
    /// <summary>The header a test names the signing-in User in.</summary>
    public const string UserHeader = "X-Test-User";

    public async ValueTask<AuthenticationResult?> CompleteAsync(
        CommandContext context,
        StartedSignIn signIn,
        HttpContext http,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(http.Request.Headers[UserHeader].ToString(), out var userId))
        {
            return null;
        }

        var authenticator = new TestOnlyAuthenticator(SessionsContract.CreateSessions(AuditContract.CreateAppender(), time), time);
        var (result, _) = await authenticator.AuthenticateAsync(context, signIn.TransactionId, userId, time.GetUtcNow(), cancellationToken);
        return result;
    }
}

/// <summary>
/// A clock that runs with the system's, offset by <see cref="Offset"/>, which a test moves on (Story 2.9):
/// wall-clock times jump, while timestamps and timers stay the system's, so a token's lifetime can pass
/// without waiting and a JWT still verifies against today's date.
/// </summary>
internal sealed class ShiftedTimeProvider : TimeProvider
{
    private long _offsetTicks;

    public TimeSpan Offset => TimeSpan.FromTicks(Interlocked.Read(ref _offsetTicks));

    public void Advance(TimeSpan by) => Interlocked.Add(ref _offsetTicks, by.Ticks);

    public override DateTimeOffset GetUtcNow() => System.GetUtcNow() + Offset;
}
