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

    /// <summary>
    /// Only on <c>application_invalid</c> from an Application settings save (Story 3.2) or tokens save (Story 3.4):
    /// each refused line or field, never its value. Absent on every other problem.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<ApiProblemError>? Errors { get; init; }

    /// <summary>
    /// Only on <c>signing_key_not_ready</c> (Story 9.2): the whole seconds, rounded up, until the next Signing
    /// Key has been published for 15 minutes, the same value as the <c>Retry-After</c> header. Absent otherwise.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? RetryAfterSeconds { get; init; }
}

/// <summary>One refused line or field of an Application settings save (Story 3.2) or tokens save (Story 3.4).</summary>
public sealed class ApiProblemError
{
    /// <summary>
    /// A settings save's <c>callbackUrls</c>, <c>logoutUrls</c>, <c>webOrigins</c> or <c>grantTypes</c>; a tokens
    /// save's <c>accessTokenLifetime</c>, <c>idTokenLifetime</c>, <c>refreshTokenAbsoluteLifetime</c> or
    /// <c>refreshTokenInactivityLifetime</c>.
    /// </summary>
    public required string Field { get; init; }

    /// <summary>The line's 0-based position in the field's array, or null when the whole field is refused.</summary>
    public required int? Index { get; init; }

    /// <summary>
    /// A settings save's <c>not_absolute</c>, <c>wildcard</c>, <c>scheme_not_allowed</c>, <c>too_long</c>,
    /// <c>too_many</c>, <c>duplicate</c> or <c>not_allowed_for_type</c>; a tokens save's <c>below_minimum</c>
    /// or <c>above_maximum</c>.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Only with <c>above_maximum</c> (Story 3.4): the field's hard limit in seconds, so a client can say
    /// "Maximum is {limit}." Absent otherwise.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? Maximum { get; init; }
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

    /// <summary>Every refused recover-admin enrolment (Story 1.32): unknown, used, expired or malformed alike.</summary>
    public const string EnrolmentRefused = "enrolment_refused";

    /// <summary>A Recovery Code confirmation naming an issue that isn't the Admin's current unconfirmed code (Story 1.26).</summary>
    public const string RecoveryCodeSuperseded = "recovery_code_superseded";

    /// <summary>A Tenant create body, name, label or list cursor that is malformed (Story 1.27).</summary>
    public const string TenantInvalid = "tenant_invalid";

    /// <summary>
    /// Every refused Tenant Subdomain (Story 1.27): malformed, reserved and taken alike, a creation
    /// that lost a race included. Nothing says which.
    /// </summary>
    public const string SubdomainRefused = "subdomain_refused";

    /// <summary>A retry of an Operation that isn't failed (Story 1.27).</summary>
    public const string OperationNotFailed = "operation_not_failed";

    /// <summary>
    /// A state-changing Tenant request whose <c>X-Gatekeep-Tenant</c>, the page's Tenant, is missing,
    /// sent twice or isn't the path's (Story 1.28): nothing ran. Logged, never audited.
    /// </summary>
    public const string TenantMismatch = "tenant_mismatch";

    /// <summary>A label change on a Tenant that is still being created (Story 1.28).</summary>
    public const string TenantNotActive = "tenant_not_active";

    /// <summary>A deletion of a Tenant already being deleted, or deleted, or a creation retry of one (Story 1.29).</summary>
    public const string TenantDeleted = "tenant_deleted";

    /// <summary>A deletion of a Tenant whose creation Operation is still running (Story 1.29).</summary>
    public const string TenantBusy = "tenant_busy";

    /// <summary>A deletion whose typed confirmation isn't the Tenant's stored host, exactly (Story 1.29).</summary>
    public const string ConfirmationMismatch = "confirmation_mismatch";

    /// <summary>
    /// A Log search (Story 7.4) whose filter, cursor or range is malformed: an unknown parameter value,
    /// one sent twice, or a range that ends before it starts; from Story 3.1 also a malformed Applications
    /// list cursor. Nothing was read.
    /// </summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// An Application create body (Story 3.1) that is malformed: not JSON, over 4096 bytes, a field missing
    /// or of the wrong type, a name that is empty after trimming, longer than 200 characters or holds a
    /// control character, or a type that isn't spa, web, native or machine. Nothing was written.
    /// </summary>
    public const string ApplicationInvalid = "application_invalid";

    /// <summary>
    /// A Prod Tenant's Application settings save (Story 3.2) that adds a custom-scheme callback or logout URL
    /// without <c>acknowledgeCustomScheme: true</c>. Nothing was written.
    /// </summary>
    public const string CustomSchemeAcknowledgementRequired = "custom_scheme_acknowledgement_required";

    /// <summary>
    /// A client secret create for a <c>spa</c> or <c>native</c> Application (Story 3.3), which authenticates with
    /// no secret. Nothing was written.
    /// </summary>
    public const string ClientSecretNotApplicable = "client_secret_not_applicable";

    /// <summary>
    /// A client secret create or rotation while the Application already holds the most live secrets (Story 3.3):
    /// a rotated-out secret still overlaps, and must be ended or expire first. Nothing was written.
    /// </summary>
    public const string ClientSecretLimitReached = "client_secret_limit_reached";

    /// <summary>
    /// An API or Permission write (Story 3.6) that is malformed: not JSON, over its size cap, a field missing or of the
    /// wrong type (no errors), or a field that breaks a rule (errors name each). Nothing was written.
    /// </summary>
    public const string ApiInvalid = "api_invalid";

    /// <summary>An API create whose identifier another of the Tenant's APIs has, exactly (Story 3.6). Nothing was written.</summary>
    public const string ApiIdentifierTaken = "api_identifier_taken";

    /// <summary>A Permission add whose value the API already has (Story 3.6). Nothing was written.</summary>
    public const string PermissionTaken = "permission_taken";

    /// <summary>A Permission add to an API that already holds the most Permissions (Story 3.6). Nothing was written.</summary>
    public const string PermissionLimitReached = "permission_limit_reached";

    /// <summary>
    /// A Permission add or removal on the built-in Management API, whose Permissions are fixed (Story 3.6), and from Story
    /// 3.7 a grant on it, which only a Tenant Owner makes (Epic 17). Nothing was written.
    /// </summary>
    public const string ApiBuiltIn = "api_built_in";

    /// <summary>A grant on an API for an Application that isn't a machine-to-machine one (Story 3.7). Nothing was written.</summary>
    public const string ApplicationNotMachine = "application_not_machine";

    /// <summary>
    /// A Signing Key rotation on demand (Story 9.2) while the next key was published less than 15 minutes ago,
    /// the JWKS cache limit. The body's <c>retryAfterSeconds</c> and the <c>Retry-After</c> header say how long
    /// remains. Nothing was written.
    /// </summary>
    public const string SigningKeyNotReady = "signing_key_not_ready";

    /// <summary>Directory's guard SQLSTATE for a secret naming a Tenant's system Application (Story 2.8): a 404 on a secret create (Story 3.3).</summary>
    public const string SystemApplicationNamed = "GK011";

    /// <summary>Directory's guard SQLSTATE for an edit of a Tenant's system Application (Story 2.8): a 404 on the settings save (Story 3.2).</summary>
    public const string SystemApplicationEdited = "GK012";

    /// <summary>
    /// An object the path Tenant has none of by that ID (Story 3.1): unknown, malformed, another Tenant's and
    /// the hidden system Application alike, so nothing says which.
    /// </summary>
    public const string NotFound = "not_found";

    /// <summary>The Tenancy guard's SQLSTATE for a status change outside a Tenant's lifecycle (Story 1.29).</summary>
    public const string StatusRefused = "GK007";

    /// <summary>The role guard's SQLSTATE for Host.Admin deleting a role of a Tenant that isn't deleting (Story 1.29).</summary>
    public const string RoleDeleteRefused = "GK009";

    /// <summary>The SQLSTATE the credential floor and maximum triggers raise, and nothing else (Story 1.26).</summary>
    public const string RaisedByTrigger = "GK001";

    /// <summary>The Tenancy guard's SQLSTATE for a label change on a Tenant that isn't active (Story 1.28).</summary>
    public const string LabelRefused = "GK006";

    /// <summary>
    /// The Tenancy guards' own SQLSTATEs (Story 1.27): a host refused (<c>GK002</c>), a Tenant inserted
    /// as other than creating (<c>GK003</c>), a role refused (<c>GK004</c>), an activation without
    /// settings (<c>GK005</c>), from Story 1.28 a label change on a Tenant that isn't active
    /// (<c>GK006</c>), and from Story 1.29 a status change outside the lifecycle, such as a deletion
    /// start that lost a race (<c>GK007</c>), and a role delete of a Tenant that isn't deleting
    /// (<c>GK009</c>). Each is a refusal, never a 500. <c>GK008</c> reaches only the Worker.
    /// </summary>
    public static readonly IReadOnlyList<string> TenancyGuardStates = ["GK002", "GK003", "GK004", "GK005", LabelRefused, StatusRefused, RoleDeleteRefused];

    /// <summary>The guard states a deletion's start or retry maps to 409 <c>tenant_deleted</c> (Story 1.29).</summary>
    public static readonly IReadOnlyList<string> DeletionGuardStates = [StatusRefused, RoleDeleteRefused];

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
        EnrolmentRefused,
        TenantInvalid,
        SubdomainRefused,
        OperationNotFailed,
        TenantMismatch,
        TenantNotActive,
        TenantDeleted,
        TenantBusy,
        ConfirmationMismatch,
        InvalidRequest,
        ApplicationInvalid,
        NotFound,
        CustomSchemeAcknowledgementRequired,
        ClientSecretNotApplicable,
        ClientSecretLimitReached,
        ApiInvalid,
        ApiIdentifierTaken,
        PermissionTaken,
        PermissionLimitReached,
        ApiBuiltIn,
        SigningKeyNotReady,
        ApplicationNotMachine,
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

    public static Task ProblemAsync(HttpContext context, int status, string code) => ProblemAsync(context, status, code, errors: null);

    /// <summary>A problem with its <paramref name="errors"/>, when it carries any (Story 3.2's settings save).</summary>
    public static Task ProblemAsync(HttpContext context, int status, string code, IReadOnlyList<ApiProblemError>? errors) =>
        ProblemAsync(context, status, code, errors, retryAfterSeconds: null);

    /// <summary>
    /// A problem with its <paramref name="errors"/> or its <paramref name="retryAfterSeconds"/>, when it carries
    /// any; the seconds go in the <c>Retry-After</c> header too (Story 9.2).
    /// </summary>
    public static Task ProblemAsync(HttpContext context, int status, string code, IReadOnlyList<ApiProblemError>? errors, int? retryAfterSeconds)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = ProblemContentType;
        context.Response.Headers.CacheControl = "no-store";
        if (retryAfterSeconds is { } seconds)
        {
            context.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return JsonAsync(
            context,
            new ApiProblem { Code = code, TraceId = TraceId(context), Errors = errors, RetryAfterSeconds = retryAfterSeconds },
            setContentType: false);
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
