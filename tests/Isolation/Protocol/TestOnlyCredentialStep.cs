using System.Globalization;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Tests.Isolation.Sessions;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// The test host's credential step (Story 4.2), plugged into Authentication's <see cref="ICredentialStep"/> port by
/// <see cref="ProtocolHost"/>: it authenticates with no real factor the User an identifier of <see cref="Email"/>'s
/// form names, with the method <see cref="TestOnlyAuthenticator.Method"/>, now or at the time the identifier names.
/// Any other identifier gets no credential step, as the release build's default gives none. Test only: the one
/// <c>src</c> credential step is Authentication's empty default, and a test checks this type stays here.
/// </summary>
internal sealed class TestOnlyCredentialStep(TimeProvider time) : ICredentialStep
{
    /// <summary>The domain of every identifier this step authenticates.</summary>
    public const string Domain = "users.test-only.example";

    /// <summary>
    /// The identifier that signs <paramref name="user"/> in, authenticated at <paramref name="authTime"/> when one is
    /// given (to the millisecond), now otherwise.
    /// </summary>
    public static string Email(Guid user, DateTimeOffset? authTime = null) =>
        authTime is { } at
            ? string.Create(CultureInfo.InvariantCulture, $"{user:N}.{at.ToUnixTimeMilliseconds()}@{Domain}")
            : $"{user:N}@{Domain}";

    public ValueTask<CredentialAuthentication?> AfterIdentifierAsync(
        CommandContext context, SignInTransaction transaction, CancellationToken cancellationToken)
    {
        var identifier = transaction.Identifier ?? string.Empty;
        var at = identifier.LastIndexOf('@');
        if (at < 0 || !string.Equals(identifier[(at + 1)..], Domain, StringComparison.Ordinal))
        {
            return ValueTask.FromResult<CredentialAuthentication?>(null);
        }

        var local = identifier[..at].Split('.');
        if (!Guid.TryParseExact(local[0], "N", out var user))
        {
            return ValueTask.FromResult<CredentialAuthentication?>(null);
        }

        var authTime = local.Length == 2 && long.TryParse(local[1], NumberStyles.None, CultureInfo.InvariantCulture, out var milliseconds)
            ? DateTimeOffset.FromUnixTimeMilliseconds(milliseconds)
            : time.GetUtcNow();

        return ValueTask.FromResult<CredentialAuthentication?>(new CredentialAuthentication(user, [TestOnlyAuthenticator.Method], authTime));
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
