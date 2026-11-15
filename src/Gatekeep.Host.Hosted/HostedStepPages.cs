using Gatekeep.Adapters.Hosting;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;

namespace Gatekeep.Host.Hosted;

/// <summary>
/// Hosted Login's step-page writer (AD-21, Story 4.1): the built bundle's <c>index.html</c> from the web
/// root, read once, with the step as JSON and the request's Tenant's theme stylesheet linked in
/// <c>head</c>, sent <c>no-store</c> with the AD-21 headers. The trace ID is the shared one.
/// </summary>
internal sealed class HostedStepPages(StepPageTemplate template) : IStepPages
{
    public string TraceId(HttpContext http) => RequestTrace.Id(http);

    public Task WriteAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(step);
        var tenant = http.Features.Get<ResolvedTenant>() ?? throw new InvalidOperationException("A step page needs a resolved Tenant.");
        return template.WriteAsync(http, statusCode, TenancyContract.Theme(tenant).Href, step.ToJson(), cancellationToken);
    }

    public Task WriteJsonAsync(HttpContext http, int statusCode, StepResponse step, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(step);
        return StepPageTemplate.WriteJsonAsync(http, statusCode, step.ToJson(), cancellationToken);
    }
}
