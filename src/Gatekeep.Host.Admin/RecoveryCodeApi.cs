using System.Data.Common;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Microsoft.Extensions.Primitives;

namespace Gatekeep.Host.Admin;

/// <summary>
/// A newly issued offline Recovery Code, shown this once (AD-24): <c>XXXX-XXXX-XXXX-XXXX</c>. It is
/// never stored, and a reload can't show it again: the Admin issues a new one, which voids it.
/// </summary>
public sealed class AdminRecoveryCodeResponse
{
    public required RevealOnce<string> Code { get; init; }

    /// <summary>This issue, which the confirmation names, so it confirms exactly this code and no later one.</summary>
    public required Guid IssueId { get; init; }
}

/// <summary>The issue the Admin saved the code of: the <c>issueId</c> its response named.</summary>
public sealed class RecoveryCodeConfirmRequest
{
    public required Guid IssueId { get; init; }
}

/// <summary>A Recovery Code to redeem, as the Admin typed it: case, hyphens and spaces don't matter.</summary>
public sealed class RecoveryCodeRedeemRequest
{
    public required string Code { get; init; }
}

/// <summary>
/// Admin Recovery Codes (Story 1.26, FR-46): issue and confirm, self-service in a setup Session,
/// and redeem, sessionless on Admin sign-in. The code is held only as an HMAC under the Deployment
/// <c>hmac</c> key, which this host's key custody computes; a custody failure is 503 with nothing
/// stored or used.
/// </summary>
internal static class RecoveryCodeApi
{
    /// <summary>A redeem body bigger than this is refused unread past it.</summary>
    private const int MaxRedeemBody = 1024;

    private const string UniqueViolation = "23505";

    public static async Task IssueAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;
        if (context.RequestServices.GetService<IKeyCustody>() is not { } custody)
        {
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        RecoveryCodeIssue issue;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            issue = await services.RecoveryCodes(custody).IssueAsync(scope.CreateCommandContext(), session, cancellationToken);
            await scope.CommitAsync(CancellationToken.None);
        }
        catch (KeyCustodyException e)
        {
            CustodyFailed(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }
        catch (DbException e) when (e.SqlState == UniqueViolation)
        {
            // Another Admin's code with the same HMAC, or a race with a second issue: nothing stored.
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (issue is not { Status: RecoveryCodeStatus.Accepted, Code: { } code, IssueId: { } issueId })
        {
            await AdminResponses.ForbiddenAsync(context);
            return;
        }

        // Committed: the one response that ever holds the code, never cached.
        await AdminResponses.JsonAsync(
            context,
            new AdminRecoveryCodeResponse { Code = code.Use(static c => new RevealOnce<string>(c)), IssueId = issueId },
            cancellationToken: CancellationToken.None);
    }

    public static async Task ConfirmAsync(HttpContext context, AdminApiServices services)
    {
        var session = AdminRequestChecks.Session(context);
        var cancellationToken = context.RequestAborted;
        if (context.RequestServices.GetService<IKeyCustody>() is not { } custody)
        {
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        // An issue that isn't named, or can't be read, is no current code: the same 409, nothing changed.
        var body = await AdminApi.ReadJsonAsync<RecoveryCodeConfirmRequest>(context.Request, MaxRedeemBody, cancellationToken);
        RecoveryCodeStatus status = RecoveryCodeStatus.Superseded;
        if (body is not null)
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            status = await services.RecoveryCodes(custody).ConfirmAsync(scope.CreateCommandContext(), session, body.IssueId, cancellationToken);
            await scope.CommitAsync(CancellationToken.None);
        }

        if (status == RecoveryCodeStatus.Refused)
        {
            await AdminResponses.ForbiddenAsync(context);
            return;
        }

        if (status == RecoveryCodeStatus.Superseded)
        {
            Logger(context).LogInformation(
                "A Recovery Code confirmation was refused with {Problem}, trace {TraceId}.",
                AdminResponses.RecoveryCodeSuperseded,
                AdminResponses.TraceId(context));
            await AdminResponses.ProblemAsync(context, StatusCodes.Status409Conflict, AdminResponses.RecoveryCodeSuperseded);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
        context.Response.Headers.CacheControl = "no-store";
    }

    public static async Task RedeemAsync(HttpContext context, AdminApiServices services)
    {
        if (AdminRequestChecks.Client(context) is not { } client)
        {
            // Not countable on its own, so not served: nothing is counted, read or used.
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        var cancellationToken = context.RequestAborted;
        // Deployment-wide first, then this client: past either, nothing more is counted or read.
        RateLimitDecision decision;
        await using (var count = await services.BeginAsync(cancellationToken))
        {
            var command = count.CreateCommandContext();
            decision = await services.Limiter.AttemptAsync(command, AdminsContract.RecoveryCodeDeploymentPolicy, AdminsContract.DeploymentSubject, cancellationToken);
            if (decision.Allowed)
            {
                decision = await services.Limiter.AttemptAsync(command, AdminsContract.RecoveryCodePolicy, client, cancellationToken);
            }

            await count.CommitAsync(cancellationToken);
        }

        if (!decision.Allowed)
        {
            Logger(context).LogInformation(
                "A Recovery Code was refused with {Problem}, trace {TraceId}.",
                AdminResponses.RateLimited,
                AdminResponses.TraceId(context));
            await AdminResponses.RateLimitedAsync(context, decision);
            return;
        }

        if (context.RequestServices.GetService<IKeyCustody>() is not { } custody)
        {
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        // Counted, so read now: a malformed body is refused like a wrong code, and stays counted.
        var body = await AdminApi.ReadJsonAsync<RecoveryCodeRedeemRequest>(context.Request, MaxRedeemBody, cancellationToken);
        if (body?.Code is not { Length: > 0 and <= AdminRecoveryCode.MaxInputLength } typed)
        {
            await RefusedAsync(context);
            return;
        }

        RecoveryCodeRedemption? redemption;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            redemption = await services.RecoveryCodes(custody).RedeemAsync(
                scope.CreateCommandContext(),
                new Secret<string>(typed),
                SignInApi.Cookie(context, AdminRequestChecks.SessionCookie),
                cancellationToken);

            // The code used up, the Sessions it ended and the new one: kept once decided.
            await scope.CommitAsync(CancellationToken.None);
        }
        catch (KeyCustodyException e)
        {
            CustodyFailed(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
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
                // The floor, as the Session read says it: a recovery Session reaches only registration either way.
                SetupComplete = redemption.SetupComplete,
            },
            cancellationToken: CancellationToken.None);
    }

    private static Task RefusedAsync(HttpContext context)
    {
        // No Admin is known from a code that didn't match, so this is only logged.
        Logger(context).LogInformation(
            "A Recovery Code was refused with {Problem}, trace {TraceId}.",
            AdminResponses.RecoveryCodeRefused,
            AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.RecoveryCodeRefused);
    }

    /// <summary>The key, operation and kind of failure only: a custody failure carries nothing else.</summary>
    private static void CustodyFailed(HttpContext context, KeyCustodyException e) =>
        Logger(context).LogWarning(
            "Key custody failed for a Recovery Code on {Operation} with {Failure}, trace {TraceId}.",
            e.Operation,
            e.Failure,
            AdminResponses.TraceId(context));

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Host.Admin");
}
