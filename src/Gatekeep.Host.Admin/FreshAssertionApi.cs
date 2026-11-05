using System.Buffers.Text;
using System.Data.Common;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.WebAuthn;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>What the Admin is about to confirm: an action, and the target exactly as the action's request will name it.</summary>
public sealed class FreshAssertionBeginRequest
{
    /// <summary>A capability name whose fresh assertion isn't never, or <c>self.credentials.add</c> or <c>self.credentials.remove</c>.</summary>
    public required string Action { get; init; }

    /// <summary>The action's target route value, such as <c>acr_…</c>, or null when it has none.</summary>
    public string? Target { get; init; }
}

/// <summary>
/// Fresh WebAuthn assertions (Story 1.26, FR-46): begin and complete, self-service, full Sessions
/// only. Each is counted per Session under <see cref="AdminsContract.FreshAssertionPolicy"/>, in
/// its own committed transaction, before it runs. The Relying Party is the Admin origin's, as at
/// sign-in. A verified complete leaves a grant on the Session for 5 minutes, bound to the begin's
/// action and target, which the action's own request then uses up: nothing reaches the browser.
/// </summary>
internal static class FreshAssertionApi
{
    /// <summary>A begin body bigger than this is refused unread past it.</summary>
    private const int MaxBeginBody = 4096;

    private const int MaxActionLength = 128;

    /// <summary>The longest target named: a route value is a public ID or shorter.</summary>
    private const int MaxTargetLength = 256;

    private const string UniqueViolation = "23505";

    private const string CheckViolation = "23514";

    public static async Task BeginAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, session))
        {
            return;
        }

        var body = await AdminApi.ReadJsonAsync<FreshAssertionBeginRequest>(context.Request, MaxBeginBody, cancellationToken);
        if (body?.Action is not { Length: > 0 and <= MaxActionLength } action
            || body.Target is { Length: > MaxTargetLength }
            || !AdminFreshAssertions.IsAction(action))
        {
            await RefusedAsync(context, "unknown action");
            return;
        }

        var capability = AdminFreshAssertions.CapabilityOf(action);
        if (capability?.Scope == CapabilityScope.Tenant)
        {
            // Tenant actions begin on the Tenant surface, with the Tenant from its path.
            await RefusedAsync(context, "tenant action");
            return;
        }

        WebAuthnRequestOptions? options = null;
        var denied = false;
        var audited = false;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            var command = scope.CreateCommandContext();
            if (capability is not null)
            {
                // A Deployment action needs the capability itself, decided exactly as the checks decide it.
                var principal = AdminRequestChecks.Principal(context);
                var decision = await services.Authorization.AuthorizeAsync(command, principal, capability, tenantId: null, cancellationToken);
                if (!decision.Allowed)
                {
                    denied = true;
                    audited = await AdminRequestChecks.DenyAsync(command, services, principal, pathTenant: null, cancellationToken);
                }
            }

            if (!denied)
            {
                options = await services.FreshAssertions.BeginAsync(
                    command, session, SignInApi.RelyingParty(context), new FreshAssertionBinding(action, null, body!.Target), cancellationToken);
            }

            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (e.SqlState == UniqueViolation)
        {
            // Two begins in one Session take turns on its row, so this is defence in depth: refused.
            AdminRequestChecks.Log(context, e);
            await RefusedAsync(context, "constraint");
            return;
        }

        if (denied || options is null)
        {
            Logger(context).LogInformation(
                "An Admin request was refused with {Problem} for {Capability}, audited {Audited}, trace {TraceId}.",
                AdminResponses.AccessDenied,
                capability!.Name,
                audited,
                AdminResponses.TraceId(context));
            await AdminResponses.AccessDeniedAsync(context);
            return;
        }

        await OptionsAsync(context, options);
    }

    /// <summary>
    /// The Tenant-surface begin (Story 1.28): a Tenant capability action whose fresh assertion isn't
    /// never, bound to the path Tenant, which is the only Tenant source. The route needs any Tenant
    /// Role; the action's own capability is then decided from the grant the request checks read,
    /// with no second read, and a refusal is counted and audited against the path Tenant. The
    /// Deployment complete finishes it: the challenge already carries the binding.
    /// </summary>
    public static async Task BeginForTenantAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, session))
        {
            return;
        }

        var body = await AdminApi.ReadJsonAsync<FreshAssertionBeginRequest>(context.Request, MaxBeginBody, cancellationToken);
        if (body?.Action is not { Length: > 0 and <= MaxActionLength } action
            || body.Target is { Length: > MaxTargetLength }
            || !AdminFreshAssertions.IsAction(action))
        {
            await RefusedAsync(context, "unknown action");
            return;
        }

        // A self-service action, a Deployment capability and a never capability begin elsewhere, or not at all.
        if (AdminFreshAssertions.CapabilityOf(action) is not { Scope: CapabilityScope.Tenant } capability)
        {
            await RefusedAsync(context, "not a tenant action");
            return;
        }

        // A target only an action whose route names one can carry: any other could never be used.
        if (body!.Target is not null && !TargetedActions(context).Contains(action))
        {
            await RefusedAsync(context, "stray target");
            return;
        }

        var principal = AdminRequestChecks.Principal(context);
        var allowed = AdminCapabilities.Allows(capability, principal, path.Grant, path.TenantId);

        WebAuthnRequestOptions? options = null;
        var audited = false;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            var command = scope.CreateCommandContext();
            if (!allowed)
            {
                audited = await AdminRequestChecks.DenyAsync(command, services, principal, path.TenantId, cancellationToken);
            }
            else
            {
                options = await services.FreshAssertions.BeginAsync(
                    command,
                    session,
                    SignInApi.RelyingParty(context),
                    new FreshAssertionBinding(action, path.TenantId, body!.Target),
                    cancellationToken);
            }

            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (e.SqlState == UniqueViolation)
        {
            AdminRequestChecks.Log(context, e);
            await RefusedAsync(context, "constraint");
            return;
        }

        if (!allowed || options is null)
        {
            Logger(context).LogInformation(
                "An Admin request was refused with {Problem} for {Capability}, audited {Audited}, trace {TraceId}.",
                AdminResponses.AccessDenied,
                capability.Name,
                audited,
                AdminResponses.TraceId(context));
            await AdminResponses.AccessDeniedAsync(context);
            return;
        }

        await OptionsAsync(context, options);
    }

    /// <summary>The actions some mapped route's fresh-assertion requirement binds to a target route value.</summary>
    private static HashSet<string> TargetedActions(HttpContext context) =>
        [
            .. context.RequestServices.GetRequiredService<EndpointDataSource>().Endpoints
                .Select(e => AccessDeclaration.Of(e.Metadata, (e as RouteEndpoint)?.RoutePattern.RawText)?.FreshAssertion)
                .Where(f => f?.TargetRouteValue is not null)
                .Select(f => f!.Action),
        ];

    /// <summary>The request options for navigator.credentials.get, as sign-in sends them.</summary>
    private static Task OptionsAsync(HttpContext context, WebAuthnRequestOptions options) =>
        AdminResponses.JsonAsync(context, new AdminSignInOptionsResponse
        {
            Challenge = Base64Url.EncodeToString(options.Challenge),
            RpId = options.RpId,
            Timeout = options.TimeoutMilliseconds,
            UserVerification = options.UserVerification,
            AllowCredentials =
            [
                .. options.AllowCredentials.Select(c => new RegistrationExcludedCredential
                {
                    Type = c.Type,
                    Id = Base64Url.EncodeToString(c.Id),
                    Transports = c.Transports,
                }),
            ],
        });

    public static async Task CompleteAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;
        if (!await CountAsync(context, services, session))
        {
            return;
        }

        // Counted, so the challenge is taken now, before the body is read, in a transaction of its
        // own, kept even if the client goes: it is used up whatever happens next.
        FreshAssertionChallenge? challenge;
        await using (var take = await services.BeginAsync(cancellationToken))
        {
            challenge = await services.FreshAssertions.TakeChallengeAsync(take.CreateCommandContext(), session, CancellationToken.None);
            await take.CommitAsync(CancellationToken.None);
        }

        var assertion = AdminApi.IsJson(context.Request) ? await SignInApi.ReadAssertionAsync(context.Request, cancellationToken) : null;
        if (challenge is null || assertion is null)
        {
            await RefusedAsync(context, assertion is null ? nameof(WebAuthnRefusal.Malformed) : nameof(WebAuthnRefusal.ChallengeMismatch));
            return;
        }

        FreshAssertionOutcome outcome;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            outcome = await services.FreshAssertions.FinishAsync(
                scope.CreateCommandContext(), session, SignInApi.RelyingParty(context), challenge, assertion, cancellationToken);

            // The grant, or a refusal's event: either is kept once decided, if the client goes now.
            await scope.CommitAsync(CancellationToken.None);
        }
        catch (DbException e) when (e.SqlState is UniqueViolation or CheckViolation or AdminResponses.ForeignKeyViolation)
        {
            // A value a constraint refuses: rolled back, so no grant, and the challenge is already gone.
            AdminRequestChecks.Log(context, e);
            await RefusedAsync(context, "constraint");
            return;
        }

        if (outcome.Status != FreshAssertionStatus.Verified)
        {
            await RefusedAsync(context, outcome.Refusal?.ToString() ?? nameof(WebAuthnRefusal.Invalid), outcome.Audited);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
        context.Response.Headers.CacheControl = "no-store";
    }

    /// <summary>Counts the call per Session in its own committed transaction, and answers 429 when it is over the limit.</summary>
    private static async Task<bool> CountAsync(HttpContext context, AdminApiServices services, AdminSession session)
    {
        var cancellationToken = context.RequestAborted;
        RateLimitDecision decision;
        await using (var count = await services.BeginAsync(cancellationToken))
        {
            decision = await services.Limiter.AttemptAsync(
                count.CreateCommandContext(), AdminsContract.FreshAssertionPolicy, session.Id.ToString("N"), cancellationToken);
            await count.CommitAsync(cancellationToken);
        }

        if (decision.Allowed)
        {
            return true;
        }

        Logger(context).LogInformation(
            "A fresh assertion was refused with {Problem}, trace {TraceId}.",
            AdminResponses.RateLimited,
            AdminResponses.TraceId(context));
        await AdminResponses.RateLimitedAsync(context, decision);
        return false;
    }

    private static Task RefusedAsync(HttpContext context, string reason, bool audited = false)
    {
        // The reason is a fixed name, and only here: the response never says why.
        Logger(context).LogInformation(
            "A fresh assertion was refused with {Problem} ({Refusal}, audited {Audited}), trace {TraceId}.",
            AdminResponses.AssertionRefused,
            reason,
            audited,
            AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.AssertionRefused);
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");
}
