using System.Diagnostics;
using System.Text.Json;

namespace Gatekeep.Host.Admin;

/// <summary>A refusal's body: a fixed code and the trace ID support asks for, and nothing else.</summary>
public sealed class ApiProblem
{
    /// <summary>A fixed code: <c>bootstrap_refused</c>, <c>credential_refused</c> or <c>rate_limited</c>.</summary>
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

    /// <summary>Every problem code a body can carry, for the OpenAPI document.</summary>
    public static readonly IReadOnlyList<string> ProblemCodes = [BootstrapRefused, CredentialRefused, RateLimited];

    /// <summary>The Session cookie, expired: sent with a sign-out and a 401 for a stale cookie.</summary>
    public static readonly string ClearedSessionCookie =
        $"{AdminRequestChecks.SessionCookie}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0";

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
        headers.ContentType = default;
        headers.ContentLength = null;
        headers.CacheControl = "no-store";
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        return Task.CompletedTask;
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
