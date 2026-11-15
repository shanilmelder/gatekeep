using System.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace Gatekeep.Adapters.Hosting;

/// <summary>
/// The request's trace ID, the one support asks for, defined once for every host: Host.Admin's
/// problem details and logs, and Host.Hosted's error pages (Story 4.1).
/// </summary>
public static class RequestTrace
{
    /// <summary>The W3C trace ID in hex when there is an Activity, Kestrel's own request ID otherwise.</summary>
    public static string Id(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Activity.Current is { } activity && activity.TraceId != default
            ? activity.TraceId.ToHexString()
            : context.TraceIdentifier;
    }
}
