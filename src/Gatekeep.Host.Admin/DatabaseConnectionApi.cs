using System.Data.Common;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>A database Connection's settings save (Story 4.6): whether Users may sign up.</summary>
public sealed class SetDatabaseConnectionSettingsRequest
{
    /// <summary>When false, the Sign up link is hidden and no one can create an account.</summary>
    public bool? SignupEnabled { get; init; }
}

/// <summary>A database Connection's password policy save (Story 4.6): every member, replacing what is stored.</summary>
public sealed class SetPasswordPolicyRequest
{
    /// <summary>The shortest password allowed: 12 to 64 characters. Below 12 is refused with "Minimum is 12 characters.".</summary>
    public int? MinLength { get; init; }

    /// <summary>
    /// <c>good</c>: the minimum length and at least 3 of lower case, upper case, number and special. <c>excellent</c>: the
    /// same, and no more than 2 identical characters in a row.
    /// </summary>
    public string? Strength { get; init; }

    /// <summary>How many of a User's earlier passwords may not be reused: 0 to 24, 0 turning the rule off.</summary>
    public int? HistoryCount { get; init; }

    /// <summary>Whether common dictionary words are refused.</summary>
    public bool? Dictionary { get; init; }

    /// <summary>Whether a password containing the User's own data, such as the email address, is refused.</summary>
    public bool? PersonalData { get; init; }
}

/// <summary>A database Connection's password policy (Story 4.6).</summary>
public sealed class PasswordPolicyResponse
{
    public required int MinLength { get; init; }

    /// <summary><c>good</c> or <c>excellent</c>.</summary>
    public required string Strength { get; init; }

    /// <summary>0 when the history rule is off.</summary>
    public required int HistoryCount { get; init; }

    public required bool Dictionary { get; init; }

    public required bool PersonalData { get; init; }
}

/// <summary>A Tenant's database Connection (Story 4.6): its kind and fixed name, its switches, its password policy and its last change.</summary>
public sealed class DatabaseConnectionResponse
{
    /// <summary>Always <c>database</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>Always <c>Username-Password</c>.</summary>
    public required string Name { get; init; }

    public required bool Enabled { get; init; }

    /// <summary>When false, the Sign up link is hidden and no one can create an account.</summary>
    public required bool SignupEnabled { get; init; }

    public required PasswordPolicyResponse PasswordPolicy { get; init; }

    /// <summary>When it was last changed, ISO 8601 in UTC.</summary>
    public required string UpdatedAt { get; init; }
}

/// <summary>
/// A Tenant's database Connection (Story 4.6, FR-17, FR-18): read with any Tenant Role; sign-up toggled by Editors and
/// Owners; the password policy saved by Tenant Owners only. Each runs in the path Tenant's own scope, and Management decides
/// the capability again from the same grant. A save writes its state and one event together, and only when a value changed.
/// </summary>
internal static class DatabaseConnectionApi
{
    /// <summary>The largest save body: anything bigger is 400 <c>connection_invalid</c>, unread past it.</summary>
    public const int MaxBody = 4096;

    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var cancellationToken = context.RequestAborted;

        DatabaseConnectionResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await services.DatabaseConnections.GetAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), path.Grant, path.TenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AnswerAsync(context, result, CancellationToken.None);
    }

    public static async Task SetSettingsAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        var body = await AdminApi.ReadJsonAsync<SetDatabaseConnectionSettingsRequest>(context.Request, MaxBody, cancellationToken);
        if (body is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ConnectionInvalid);
            return;
        }

        await SaveAsync(
            context,
            services,
            (scope, ct) => services.DatabaseConnections.SetSettingsAsync(scope, principal, path.Grant, path.TenantId, body.SignupEnabled, ct));
    }

    public static async Task SetPasswordPolicyAsync(HttpContext context, AdminApiServices services)
    {
        var path = AdminRequestChecks.PathTenantGrant(context);
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        var body = await AdminApi.ReadJsonAsync<SetPasswordPolicyRequest>(context.Request, MaxBody, cancellationToken);
        if (body is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ConnectionInvalid);
            return;
        }

        var input = new PasswordPolicySaveInput(body.MinLength, body.Strength, body.HistoryCount, body.Dictionary, body.PersonalData);
        await SaveAsync(
            context,
            services,
            (scope, ct) => services.DatabaseConnections.SetPasswordPolicyAsync(scope, principal, path.Grant, path.TenantId, input, ct));
    }

    private static async Task SaveAsync(
        HttpContext context,
        AdminApiServices services,
        Func<CommandContext, CancellationToken, Task<DatabaseConnectionResult>> save)
    {
        var cancellationToken = context.RequestAborted;

        DatabaseConnectionResult result;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            result = await save(scope.CreateCommandContext(), cancellationToken);

            if (result.Status == ConnectionStatus.Done)
            {
                // The row and its event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AnswerAsync(context, result, CancellationToken.None);
    }

    private static async Task AnswerAsync(HttpContext context, DatabaseConnectionResult result, CancellationToken cancellationToken)
    {
        switch (result.Status)
        {
            case ConnectionStatus.Done:
                await AdminResponses.JsonAsync(context, Response(result.Connection!), cancellationToken: cancellationToken);
                return;

            case ConnectionStatus.Invalid:
                LogRefusal(context, AdminResponses.ConnectionInvalid);
                await AdminResponses.ProblemAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    AdminResponses.ConnectionInvalid,
                    [.. result.Errors.Select(e => new ApiProblemError { Field = e.Field, Index = null, Reason = e.Reason, Detail = e.Detail })]);
                return;

            case ConnectionStatus.NotActive:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantNotActive);
                return;

            case ConnectionStatus.NotFound:
                await RefuseAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied);
                return;
        }
    }

    private static DatabaseConnectionResponse Response(ManagedDatabaseConnection connection) =>
        new()
        {
            Kind = "database",
            Name = connection.Name,
            Enabled = connection.Enabled,
            SignupEnabled = connection.SignupEnabled,
            PasswordPolicy = new PasswordPolicyResponse
            {
                MinLength = connection.PasswordPolicy.MinLength,
                Strength = connection.PasswordPolicy.Strength,
                HistoryCount = connection.PasswordPolicy.HistoryCount,
                Dictionary = connection.PasswordPolicy.Dictionary,
                PersonalData = connection.PasswordPolicy.PersonalData,
            },
            UpdatedAt = ApplicationsApi.Timestamp(connection.UpdatedAt),
        };

    /// <summary>A refusal, logged under its fixed code only: never a value.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem)
    {
        LogRefusal(context, problem);
        return AdminResponses.ProblemAsync(context, status, problem);
    }

    private static void LogRefusal(HttpContext context, string problem) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("A database Connection request was refused with {Problem}, trace {TraceId}.", problem, AdminResponses.TraceId(context));
}
