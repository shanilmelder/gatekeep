using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>A Tenant settings save (Story 4.6): every member, replacing what is stored. A null clears a URL or the audience.</summary>
public sealed class SetTenantSettingsRequest
{
    /// <summary>The terms a sign-up links to: an absolute https URL with no userinfo, at most 2048 characters, or null for none.</summary>
    public string? TermsUrl { get; init; }

    /// <summary>Whether new Users skip email verification: true is refused unless the Tenant is Dev.</summary>
    public bool? EmailVerificationOff { get; init; }

    /// <summary>The identifier of one of the Tenant's APIs, other than the built-in Management API, that User tokens are for by default; or null.</summary>
    public string? DefaultAudience { get; init; }
}

/// <summary>A Tenant's settings a sign-up reads (Story 4.6).</summary>
public sealed class TenantSettingsResponse
{
    /// <summary>The terms URL, or null.</summary>
    public required string? TermsUrl { get; init; }

    /// <summary>Whether email verification is off: never true unless the Tenant is Dev now.</summary>
    public required bool EmailVerificationOff { get; init; }

    /// <summary>Whether email verification may be turned off: only in a Dev Tenant.</summary>
    public required bool EmailVerificationOffAvailable { get; init; }

    /// <summary>The default audience, an API identifier, or null.</summary>
    public required string? DefaultAudience { get; init; }
}

/// <summary>
/// A Tenant's settings a sign-up reads (Story 4.6): read with any Tenant Role and saved by Editors and Owners, in the path
/// Tenant's own scope, with Management deciding the capability again from the same grant. A save writes its state and one
/// event together, and only when a value changed.
/// </summary>
internal static class TenantSettingsApi
{
    /// <summary>The largest save body: room for a 2048-character URL with every character escaped. Anything bigger is 400 <c>tenant_settings_invalid</c>.</summary>
    public const int MaxBody = 16384;

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        TenantSettingsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.TenantSettings.GetAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AnswerAsync(context, result);
    }

    public static async Task SetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        var body = await AdminApi.ReadJsonAsync<SetTenantSettingsRequest>(context.Request, MaxBody, cancellationToken);
        if (body is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantSettingsInvalid);
            return;
        }

        TenantSettingsResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.TenantSettings.SaveAsync(
                scope.CreateCommandContext(),
                principal,
                path.Grant,
                path.TenantId,
                new TenantSettingsSaveInput(body.TermsUrl, body.EmailVerificationOff, body.DefaultAudience),
                cancellationToken);

            if (result.Status == ConnectionStatus.Done)
            {
                // The settings and their event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AnswerAsync(context, result);
    }

    private static async Task AnswerAsync(HttpContext context, TenantSettingsResult result)
    {
        switch (result.Status)
        {
            case ConnectionStatus.Done:
                var settings = result.Settings!;
                await AdminResponses.JsonAsync(
                    context,
                    new TenantSettingsResponse
                    {
                        TermsUrl = settings.TermsUrl,
                        EmailVerificationOff = settings.EmailVerificationOff,
                        EmailVerificationOffAvailable = settings.EmailVerificationOffAvailable,
                        DefaultAudience = settings.DefaultAudience,
                    },
                    cancellationToken: CancellationToken.None);
                return;

            case ConnectionStatus.Invalid:
                LogRefusal(context, AdminResponses.TenantSettingsInvalid);
                await AdminResponses.ProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AdminResponses.TenantSettingsInvalid,
                    [.. result.Errors.Select(e => new ApiProblemError { Field = e.Field, Index = null, Reason = e.Reason, Detail = e.Detail })]);
                return;

            case ConnectionStatus.NotActive:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantNotActive);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    /// <summary>A refusal, logged under its fixed code only: never a URL or an identifier.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        LogRefusal(context, problem);
        return AdminResponses.ProblemAsync(context, status, problem);
    }

    private static void LogRefusal(HttpContext context, string problem) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("A Tenant settings request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
}
