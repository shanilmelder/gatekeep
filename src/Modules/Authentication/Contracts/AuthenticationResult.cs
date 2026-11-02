namespace Gatekeep.Modules.Authentication.Contracts;

/// <summary>
/// What a completed sign-in gives Protocol (AD-8): the Session it started, the User, the
/// methods used and when. Protocol honours <c>prompt=login</c>, <c>max_age</c>,
/// <c>auth_time</c> and <c>amr</c> from it, and anchors the Token Family to the Session.
/// </summary>
public sealed record AuthenticationResult(Guid SessionId, Guid UserId, IReadOnlyList<string> Amr, DateTimeOffset AuthTime);
