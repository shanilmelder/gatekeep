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

    /// <summary>The step as JSON, with camelCase names and every field present, nulls included.</summary>
    public string ToJson() => JsonSerializer.Serialize(this, Json);
}

/// <summary>The Hosted Login step names (snake_case) the client maps to screens.</summary>
public static class StepNames
{
    public const string GenericError = "generic_error";
}

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
}
