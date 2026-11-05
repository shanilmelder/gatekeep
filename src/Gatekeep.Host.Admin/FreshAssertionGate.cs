using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>
/// The one fresh-assertion gate a handler calls (Story 1.26, AD-20), for a requirement its
/// declaration says the handler enforces: a <c>When…</c> capability once its predicate holds, or
/// a self-service action whose need depends on the Session. The request checks use the same
/// binding and the same 403 for the requirements they enforce themselves.
/// </summary>
internal static class FreshAssertionGate
{
    /// <summary>
    /// Uses up the Session's grant for this endpoint's action, in the path Tenant and on its target
    /// route value, in a transaction of its own committed before the action runs. Without one it
    /// writes the 403 <c>fresh_assertion_required</c> and returns false: the handler then stops.
    /// </summary>
    /// <exception cref="InvalidOperationException">The endpoint declares no handler-enforced requirement.</exception>
    public static async Task<bool> RequireAsync(HttpContext context, AdminApiServices services, CancellationToken cancellationToken)
    {
        var requirement = Requirement(context);
        var session = AdminRequestChecks.Session(context);
        Guid? tenant = context.Features.Get<PathTenantFeature>()?.TenantId;
        var binding = new FreshAssertionBinding(requirement.Action, tenant, Target(context, requirement));

        Guid? consumed;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            consumed = await services.FreshAssertions.ConsumeAsync(scope.CreateCommandContext(), session, binding, cancellationToken);

            // Used up now, kept even if the client goes: the action that follows can't give it back.
            await scope.CommitAsync(CancellationToken.None);
        }

        if (consumed is not { } confirmedWith)
        {
            await RequiredAsync(context, requirement);
            return false;
        }

        context.Features.Set(new FreshAssertionFeature(confirmedWith));
        return true;
    }

    /// <summary>
    /// Uses up, unused, any grant this Session holds for this endpoint's handler-enforced action,
    /// path Tenant and target (Story 1.28), in a transaction of its own: a change made without
    /// needing the grant replaces what the grant was earned for, so it mustn't serve a later one.
    /// </summary>
    /// <exception cref="InvalidOperationException">The endpoint declares no handler-enforced requirement.</exception>
    public static async Task DiscardAsync(HttpContext context, AdminApiServices services, CancellationToken cancellationToken)
    {
        var requirement = Requirement(context);
        var session = AdminRequestChecks.Session(context);
        Guid? tenant = context.Features.Get<PathTenantFeature>()?.TenantId;
        var binding = new FreshAssertionBinding(requirement.Action, tenant, Target(context, requirement));

        await using var scope = await services.BeginAsync(cancellationToken);
        await services.FreshAssertions.ConsumeAsync(scope.CreateCommandContext(), session, binding, cancellationToken);
        await scope.CommitAsync(cancellationToken);
    }

    private static FreshAssertionRequirement Requirement(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        var requirement = (endpoint is null ? null : AccessDeclaration.Of(endpoint.Metadata, (endpoint as RouteEndpoint)?.RoutePattern.RawText))
            ?.FreshAssertion;
        return requirement is { EnforcedBy: FreshAssertionEnforcement.Handler }
            ? requirement
            : throw new InvalidOperationException("The gate is only for an endpoint whose handler enforces its fresh assertion.");
    }

    /// <summary>The target route value exactly as the request names it, never parsed. Null when the requirement names none.</summary>
    public static string? Target(HttpContext context, FreshAssertionRequirement requirement) =>
        requirement.TargetRouteValue is { } name ? context.GetRouteValue(name) as string : null;

    /// <summary>The 403 for a sensitive action with no grant: logged with its action, and not audited, as the Admin is allowed.</summary>
    public static Task RequiredAsync(HttpContext context, FreshAssertionRequirement requirement)
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation(
                "An Admin request was refused with {Problem} for {Action}, trace {TraceId}.",
                AdminResponses.FreshAssertionRequired,
                requirement.Action,
                AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status403Forbidden, AdminResponses.FreshAssertionRequired);
    }
}
