using System.Diagnostics;
using System.Text.Json;

namespace Gatekeep.Host.Admin;

/// <summary>A refusal's body: a fixed code and the trace ID support asks for, and nothing else.</summary>
public sealed class ApiProblem
{
    /// <summary>A fixed code, one of the document's closed set, such as <c>access_denied</c> or <c>fresh_assertion_required</c>.</summary>
    public required string Code { get; init; }

    /// <summary>The request's W3C trace ID, which the host's log line for the refusal carries too.</summary>
    public required string TraceId { get; init; }
}

/// <summary>The responses every Admin API path shares, so equal cases are byte-identical.</summary>
internal static class AdminResponses
{
    public const string ProblemContentType = "application/problem+json";

    public const string BootstrapRefused = "bootstrap_refused";

    public const string RateLimited = "rate_limited";

    public const string CredentialRefused = "credential_refused";

    /// <summary>Every refused Admin sign-in complete (Story 1.23), whatever the reason: nothing says why.</summary>
    public const string SignInRefused = "signin_refused";

    /// <summary>
    /// Every capability refusal (Story 1.24), whatever the reason: a malformed, unknown or role-less
    /// path Tenant, too low a Tenant Role, and a Deployment capability for an Admin who isn't the
    /// Deployment Owner all send exactly this, so nothing says which Tenants exist.
    /// </summary>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// A sensitive action with no fresh assertion bound to its Session, action and target (Story
    /// 1.26): the Admin is allowed, only unconfirmed. Logged, never audited.
    /// </summary>
    public const string FreshAssertionRequired = "fresh_assertion_required";

    /// <summary>Every refused fresh-assertion begin or complete (Story 1.26), whatever the reason: nothing says why.</summary>
    public const string AssertionRefused = "assertion_refused";

    /// <summary>A removal that would leave the Admin fewer than two credentials (Story 1.26).</summary>
    public const string CredentialsMinimum = "credentials_minimum";

    /// <summary>A registration for an Admin who holds the most credentials allowed (Story 1.26).</summary>
    public const string CredentialsMaximum = "credentials_maximum";

    /// <summary>Every refused Recovery Code (Story 1.26): wrong, unconfirmed, used or malformed alike.</summary>
    public const string RecoveryCodeRefused = "recovery_code_refused";

    /// <summary>A Recovery Code confirmation naming an issue that isn't the Admin's current unconfirmed code (Story 1.26).</summary>
    public const string RecoveryCodeSuperseded = "recovery_code_superseded";

    /// <summary>The SQLSTATE the credential floor and maximum triggers raise, and nothing else (Story 1.26).</summary>
    public const string RaisedByTrigger = "GK001";

    /// <summary>A foreign key a write broke, such as a credential removed under a grant being stored.</summary>
    public const string ForeignKeyViolation = "23503";

    /// <summary>Every problem code a body can carry, for the OpenAPI document.</summary>
    public static readonly IReadOnlyList<string> ProblemCodes =
    [
        BootstrapRefused,
        CredentialRefused,
        SignInRefused,
        RateLimited,
        AccessDenied,
        FreshAssertionRequired,
        AssertionRefused,
        CredentialsMinimum,
        CredentialsMaximum,
        RecoveryCodeRefused,
        RecoveryCodeSuperseded,
    ];

    /// <summary>The Session cookie, expired: sent with a sign-out and a 401 for a stale cookie.</summary>
    public static readonly string ClearedSessionCookie =
        $"{AdminRequestChecks.SessionCookie}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0";

    /// <summary>
    /// The key a sign-in complete sets in <see cref="HttpContext.Items"/> once it has taken the
    /// challenge, so that even a 503 after it still clears the binding cookie.
    /// </summary>
    public const string SignInChallengeTaken = "Gatekeep:SignInChallengeTaken";

    /// <summary>The sign-in binding cookie, expired: every sign-in complete sends it once the challenge is taken, whatever the outcome.</summary>
    public static readonly string ClearedSignInCookie =
        $"{AdminRequestChecks.SignInCookie}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0";

    /// <summary>
    /// The sign-in binding cookie for <paramref name="binding"/>: host-only by its prefix, sent only
    /// over HTTPS, only same-site and never to script, for as long as the challenge lives.
    /// </summary>
    public static string SignInCookie(string binding) =>
        $"{AdminRequestChecks.SignInCookie}={binding}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={(long)Gatekeep.Kernel.Limits.SecurityLimits.WebAuthnChallengeLifetime.TotalSeconds}";

    /// <summary>
    /// An Admin Session cookie: a browser session cookie (no Domain, Expires or Max-Age), host-only
    /// by its prefix, sent only over HTTPS, only same-site and never to script.
    /// </summary>
    public static string SessionCookie(string token) =>
        $"{AdminRequestChecks.SessionCookie}={token}; Path=/; Secure; HttpOnly; SameSite=Strict";

    /// <summary>The request's trace ID: the W3C one when there is an Activity, Kestrel's otherwise.</summary>
    public static string TraceId(HttpContext context) =>
        Activity.Current is { } activity && activity.TraceId != default
            ? activity.TraceId.ToHexString()
            : context.TraceIdentifier;

    /// <summary>
    /// The one 404: an unknown API path, a claim with nothing to claim and the Bootstrap page once
    /// bootstrap is complete all send exactly this, so none reveals that bootstrap ever existed.
    /// </summary>
    public static Task NotFoundAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }

    /// <summary>
    /// No session, or one unknown, ended or expired: no body, so no detail. A cookie that was sent
    /// is cleared, so the browser stops sending it.
    /// </summary>
    public static Task UnauthorizedAsync(HttpContext context, bool clearCookie = false)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        if (clearCookie)
        {
            context.Response.Headers.SetCookie = ClearedSessionCookie;
            context.Response.Headers.CacheControl = "no-store";
        }

        return Task.CompletedTask;
    }

    /// <summary>A wrong Origin or CSRF token, or a setup Session past what setup allows: no body.</summary>
    public static Task ForbiddenAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    /// <summary>
    /// The database couldn't answer, or too many claims are in flight: no body, and nothing about
    /// why, and never cached. Anything an endpoint set for its own answer goes; the AD-21 headers stay.
    /// </summary>
    public static Task UnavailableAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.Remove("Set-Cookie");
        headers.Remove("Retry-After");

        // A sign-in's challenge, once taken, is gone whatever failed after: its cookie goes too.
        if (context.Items.ContainsKey(SignInChallengeTaken))
        {
            headers.SetCookie = ClearedSignInCookie;
        }

        headers.ContentType = default;
        headers.ContentLength = null;
        headers.CacheControl = "no-store";
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        return Task.CompletedTask;
    }

    /// <summary>A capability refusal: 403 with the one <c>access_denied</c> body and the trace ID, never cached.</summary>
    public static Task AccessDeniedAsync(HttpContext context) =>
        ProblemAsync(context, StatusCodes.Status403Forbidden, AccessDenied);

    /// <summary>A 429 with <c>Retry-After</c> in whole seconds, at least 1.</summary>
    public static Task RateLimitedAsync(HttpContext context, Gatekeep.Kernel.RateLimiting.RateLimitDecision decision)
    {
        context.Response.Headers.RetryAfter = Math.Max(1, (long)Math.Ceiling(decision.RetryAfter.TotalSeconds))
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        return ProblemAsync(context, StatusCodes.Status429TooManyRequests, RateLimited);
    }

    public static Task ProblemAsync(HttpContext context, int status, string code)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = ProblemContentType;
        context.Response.Headers.CacheControl = "no-store";
        return JsonAsync(context, new ApiProblem { Code = code, TraceId = TraceId(context) }, setContentType: false);
    }

    /// <summary>
    /// Writes <paramref name="value"/> as camel-case JSON, never cached, until the client goes
    /// unless <paramref name="cancellationToken"/> says otherwise.
    /// </summary>
    public static Task JsonAsync<T>(HttpContext context, T value, bool setContentType = true, CancellationToken? cancellationToken = null)
    {
        if (setContentType)
        {
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.Headers.CacheControl = "no-store";
        }

        return JsonSerializer.SerializeAsync(context.Response.Body, value, JsonSerializerOptions.Web, cancellationToken ?? context.RequestAborted);
    }
}
