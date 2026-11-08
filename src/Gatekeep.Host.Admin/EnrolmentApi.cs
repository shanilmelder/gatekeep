using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Microsoft.Extensions.Primitives;

namespace Gatekeep.Host.Admin;

/// <summary>
/// A <c>gatekeep recover-admin</c> enrolment to redeem: the value from the link's fragment, which
/// the Recover page reads and clears before it sends it here.
/// </summary>
public sealed class EnrolmentRedeemRequest
{
    public required string Enrolment { get; init; }
}

/// <summary>
/// <c>recover-admin</c> enrolment redemption (Story 1.32, AD-31): sessionless on Admin sign-in, as
/// a Recovery Code is. This host never issues an enrolment; only the Cli does, after its Security
/// Alert and off-server record are confirmed. The value is held only as its SHA-256, so nothing
/// here touches key custody.
/// </summary>
internal static class EnrolmentApi
{
    /// <summary>A redeem body bigger than this is refused unread past it.</summary>
    private const int MaxBody = 1024;

    public static async Task RedeemAsync(HttpContext context, AdminApiServices services)
    {
        if (AdminRequestChecks.Client(context) is not { } client)
        {
            // Not countable on its own, so not served: nothing is counted, read or used.
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        var cancellationToken = context.RequestAborted;
        // This client first, then the Deployment: a client past its own 5 spends none of the Deployment's 50,
        // so it can't shut the break-glass path for everyone. Past either, nothing more is counted or read.
        RateLimitDecision decision;
        await using (var count = await services.BeginAsync(cancellationToken))
        {
            var command = count.CreateCommandContext();
            decision = await services.Limiter.AttemptAsync(command, AdminsContract.EnrolmentPolicy, client, cancellationToken);
            if (decision.Allowed)
            {
                decision = await services.Limiter.AttemptAsync(command, AdminsContract.EnrolmentDeploymentPolicy, AdminsContract.DeploymentSubject, cancellationToken);
            }

            await count.CommitAsync(cancellationToken);
        }

        if (!decision.Allowed)
        {
            Logger(context).LogInformation(
                "An enrolment was refused with {Problem}, trace {TraceId}.",
                AdminResponses.RateLimited,
                AdminResponses.TraceId(context));
            await AdminResponses.RateLimitedAsync(context, decision);
            return;
        }

        // Counted, so read now: a malformed body is refused like an unknown value, and stays counted.
        var body = await AdminApi.ReadJsonAsync<EnrolmentRedeemRequest>(context.Request, MaxBody, cancellationToken);
        if (body?.Enrolment is not { Length: AdminEnrolmentValue.Length } value)
        {
            await RefusedAsync(context);
            return;
        }

        EnrolmentRedemption? redemption;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            redemption = await services.Enrolments.RedeemAsync(
                scope.CreateCommandContext(),
                new Secret<string>(value),
                SignInApi.Cookie(context, AdminRequestChecks.SessionCookie),
                cancellationToken);

            // The enrolment used up, the Sessions it ended and the new one: kept once decided.
            await scope.CommitAsync(CancellationToken.None);
        }

        if (redemption is not { Session: { } session })
        {
            await RefusedAsync(context);
            return;
        }

        // Committed: the Session cookie goes out even if the client has gone.
        context.Response.Headers.SetCookie = new StringValues(session.SessionToken.Use(AdminResponses.SessionCookie));
        await AdminResponses.JsonAsync(
            context,
            new AdminSignInResponse
            {
                AdminId = session.AdminId,
                CsrfToken = session.CsrfToken.Use(static t => t),
                // The floor, as the Session read says it: a setup or recovery Session reaches only registration either way.
                SetupComplete = redemption.SetupComplete,
            },
            cancellationToken: CancellationToken.None);
    }

    private static Task RefusedAsync(HttpContext context)
    {
        // No Admin is known from a value that didn't match, so this is only logged.
        Logger(context).LogInformation(
            "An enrolment was refused with {Problem}, trace {TraceId}.",
            AdminResponses.EnrolmentRefused,
            AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.EnrolmentRefused);
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");
}
