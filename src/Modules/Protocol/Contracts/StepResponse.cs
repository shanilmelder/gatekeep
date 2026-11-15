using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Modules.Protocol.Contracts;

/// <summary>
/// One Hosted Login step, as its page embeds it and the client renders it (AD-21, Story 4.1):
/// <c>{step, stepVersion, expiresInSeconds, data, csrfToken}</c>. <see cref="Step"/> is a snake_case step
/// name, the client's only key to its screen, and <see cref="Data"/> that screen's props. A new step is a
/// new data record and a factory here; the page writer serializes any of them unchanged.
/// </summary>
public sealed record StepResponse(string Step, int StepVersion, int? ExpiresInSeconds, object Data, string? CsrfToken)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        // The page writer makes the JSON safe inside its script element; nothing else is escaped here.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Generic error (FR-33): the Tenant's name, the error's code and the request's trace ID, and nothing
    /// else, since the request it answers isn't trusted. It never expires and holds no CSRF token.
    /// </summary>
    public static StepResponse GenericError(string tenant, string code, string traceId) =>
        new(StepNames.GenericError, 1, null, new GenericErrorData(tenant, code, traceId), null);

    /// <summary>
    /// Login (Story 4.2): the identifier step, at <paramref name="stepVersion"/>, with its remaining life and the
    /// transaction's CSRF token. <paramref name="email"/> is the email kept from an earlier attempt, if any, and
    /// <paramref name="error"/> a field error's code, such as <see cref="LoginErrors.EmailInvalid"/>.
    /// </summary>
    public static StepResponse Login(string tenant, int stepVersion, int expiresInSeconds, string csrfToken, string? email, string? error = null) =>
        new(StepNames.Login, stepVersion, expiresInSeconds, new LoginData(tenant, email, error), csrfToken);

    /// <summary>
    /// A redirect (Story 4.2): the client follows <paramref name="location"/>, a same-origin path, with a top-level
    /// GET. It leaves the step and needs no CSRF token.
    /// </summary>
    public static StepResponse Redirect(string tenant, int stepVersion, int? expiresInSeconds, string location) =>
        new(StepNames.Redirect, stepVersion, expiresInSeconds, new RedirectData(tenant, location), null);

    /// <summary>The step as JSON, with camelCase names and every field present, nulls included.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, Json);
}

/// <summary>The Hosted Login step names (snake_case) the client maps to screens.</summary>
public static class StepNames
{
    public const string GenericError = "generic_error";

    /// <summary>Login's identifier step (Story 4.2).</summary>
    public const string Login = "login";

    /// <summary>A step that leaves Hosted Login by a top-level GET (Story 4.2).</summary>
    public const string Redirect = "redirect";
}

/// <summary>The codes a Login field error is sent as; the client shows the catalogue's text for each.</summary>
public static class LoginErrors
{
    /// <summary>"Enter a valid email address."</summary>
    public const string EmailInvalid = "email_invalid";
}

/// <summary>Login's props (Story 4.2): the Tenant's display name, the email to fill in, if kept, and a field error's code.</summary>
public sealed record LoginData(string Tenant, string? Email, string? Error);

/// <summary>A redirect's props (Story 4.2): the Tenant's display name and the same-origin path the client goes to.</summary>
public sealed record RedirectData(string Tenant, string Location);

/// <summary>Generic error's props: the Tenant's display name, the error code and the trace ID.</summary>
public sealed record GenericErrorData(string Tenant, string Code, string TraceId);

/// <summary>
/// The host's Hosted Login step pages (AD-21, Story 4.1), the port Protocol shows a step through: the
/// built bundle's page with the step embedded as JSON and the Tenant's theme linked in <c>head</c>, sent
/// <c>no-store</c> with the host's AD-21 headers. Host.Hosted registers it with <c>AddGatekeepProtocol</c>.
/// </summary>
public interface IStepPages
{
    /// <summary>The request's trace ID, as the host reports it everywhere else.</summary>
    string TraceId(HttpContext http);

    /// <summary>Writes <paramref name="step"/>'s page as the whole response, with <paramref name="statusCode"/>.</summary>
    Task WriteAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken);

    /// <summary>
    /// Writes <paramref name="step"/> alone, as Hosted Login's API answers (Story 4.2): <c>application/json</c>,
    /// <c>no-store</c> and the same AD-21 headers, with <paramref name="statusCode"/>.
    /// </summary>
    Task WriteJsonAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken);
}
