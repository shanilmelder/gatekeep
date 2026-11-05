using System.Data.Common;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Management.Contracts;

namespace Gatekeep.Host.Admin;

/// <summary>The create body (Story 1.27). The only request in the API that takes a Tenant Subdomain.</summary>
public sealed class CreateTenantRequest
{
    /// <summary>The Admin-facing name: trimmed, then 1 to 100 characters with no control character.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// The Tenant Subdomain, exactly as typed: 3 to 63 lower-case letters, digits and hyphens, not
    /// starting or ending with a hyphen. It can't be changed later, and is never reused.
    /// </summary>
    public required string Subdomain { get; init; }

    /// <summary><c>dev</c>, <c>staging</c> or <c>prod</c>.</summary>
    public required string Label { get; init; }
}

/// <summary>A creating Tenant's creation Operation.</summary>
public sealed class TenantCreation
{
    /// <summary>The Operation's public ID: <c>opr_</c> and 26 base32 characters.</summary>
    public required string OperationId { get; init; }

    /// <summary><c>running</c>, or <c>failed</c> when it can be retried.</summary>
    public required string Status { get; init; }
}

/// <summary>A deleting Tenant's deletion Operation (Story 1.29).</summary>
public sealed class TenantDeletion
{
    /// <summary>The Operation's public ID: <c>opr_</c> and 26 base32 characters.</summary>
    public required string OperationId { get; init; }

    /// <summary><c>running</c>, or <c>failed</c> when it can be retried.</summary>
    public required string Status { get; init; }
}

/// <summary>
/// The delete body (Story 1.29): the Tenant's host typed exactly as the Tenants list shows it. The
/// only request in the API with a confirmation.
/// </summary>
public sealed class DeleteTenantRequest
{
    /// <summary>The Tenant's stored host, such as <c>acme.id.example.com</c>, compared exactly: no trimming or case folding.</summary>
    public required string Confirmation { get; init; }
}

/// <summary>A Tenant as the Tenants list shows it: its stored host, never a subdomain split from it (AD-6).</summary>
public sealed class TenantResponse
{
    /// <summary>The Tenant's public ID: <c>ten_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary>The Tenant's host, <c>{subdomain}.{zone}</c>, as stored at creation.</summary>
    public required string Host { get; init; }

    /// <summary><c>dev</c>, <c>staging</c> or <c>prod</c>.</summary>
    public required string Label { get; init; }

    /// <summary>
    /// <c>creating</c> until its creation Operation succeeds, then <c>active</c>; <c>deleting</c> from its
    /// deletion's start until its deletion Operation succeeds, when it leaves the list.
    /// </summary>
    public required string Status { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Its creation Operation while the Tenant is <c>creating</c>; otherwise null.</summary>
    public required TenantCreation? Creation { get; init; }

    /// <summary>Its deletion Operation while the Tenant is <c>deleting</c>; otherwise null.</summary>
    public required TenantDeletion? Deletion { get; init; }
}

/// <summary>One page of the Deployment's Tenants, oldest first, and the Tenant zone their hosts sit under.</summary>
public sealed class TenantListResponse
{
    public required string TenantZone { get; init; }

    public required IReadOnlyList<TenantResponse> Tenants { get; init; }

    /// <summary>The cursor for the next page, the last Tenant's ID, or null when this is the last page.</summary>
    public required string? NextCursor { get; init; }
}

/// <summary>One Operation step: codes and IDs only (AD-30), never its row ID.</summary>
public sealed class OperationStepResponse
{
    public required string Stage { get; init; }

    /// <summary>The step's Tenant's public ID, or null for a Deployment step.</summary>
    public required string? TenantId { get; init; }

    /// <summary><c>pending</c>, <c>running</c>, <c>succeeded</c> or <c>failed</c>.</summary>
    public required string Status { get; init; }

    /// <summary>The step's fixed result code, such as <c>custody_unavailable</c>, once it has one.</summary>
    public required string? ResultCode { get; init; }

    public required int Attempts { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }
}

/// <summary>An Operation (AD-30), with the steps the reader may see.</summary>
public sealed class OperationResponse
{
    /// <summary>The Operation's public ID: <c>opr_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    public required string Type { get; init; }

    /// <summary>The public ID of the Tenant it is scoped to, or null for a Deployment Operation.</summary>
    public required string? TenantId { get; init; }

    /// <summary><c>running</c>, <c>failed</c> or <c>succeeded</c>.</summary>
    public required string Status { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }

    public required DateTimeOffset? FinishedAt { get; init; }

    public required IReadOnlyList<OperationStepResponse> Steps { get; init; }
}

/// <summary>A started creation: the Tenant, still <c>creating</c>, and the Operation that finishes it.</summary>
public sealed class TenantCreatedResponse
{
    public required TenantResponse Tenant { get; init; }

    public required OperationResponse Operation { get; init; }
}

/// <summary>A Tenant the current Admin holds a Tenant Role in, as the Tenant switcher shows it (Story 1.28). Never the role.</summary>
public sealed class AdminTenantResponse
{
    /// <summary>The Tenant's public ID: <c>ten_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    public required string Name { get; init; }

    /// <summary>The Tenant's host, <c>{subdomain}.{zone}</c>, as stored at creation.</summary>
    public required string Host { get; init; }

    /// <summary><c>dev</c>, <c>staging</c> or <c>prod</c>.</summary>
    public required string Label { get; init; }
}

/// <summary>The active Tenants the current Admin holds a Tenant Role in, oldest first, with no paging.</summary>
public sealed class AdminTenantListResponse
{
    public required IReadOnlyList<AdminTenantResponse> Tenants { get; init; }
}

/// <summary>
/// Creating and listing Tenants, and reading and retrying their creation (Story 1.27). The request
/// checks have decided each request's capability before these run; Management decides it again.
/// </summary>
internal static class TenantsApi
{
    /// <summary>The route value naming an Operation.</summary>
    public const string OperationRouteValue = "operationId";

    /// <summary>The list's query parameter: the previous page's <c>nextCursor</c>.</summary>
    public const string CursorQuery = "cursor";

    /// <summary>The largest create body read: anything bigger is 400 <c>tenant_invalid</c>, unread past it.</summary>
    public const int MaxCreateBody = 4096;

    /// <summary>Tenants per page (Conventions).</summary>
    public const int PageSize = 50;

    public static readonly IReadOnlyList<string> Labels = ["dev", "staging", "prod"];

    /// <summary>The route value naming the Tenant a Deployment route acts on (Story 1.29): never <c>tenantId</c>, which only the Tenant surface has.</summary>
    public const string TargetTenantRouteValue = "targetTenantId";

    /// <summary>The largest delete body read: anything bigger is 400 <c>tenant_invalid</c>, unread past it.</summary>
    public const int MaxDeleteBody = 4096;

    /// <summary>The statuses the Tenants list shows: a deleted Tenant never appears.</summary>
    public static readonly IReadOnlyList<string> TenantStatuses = ["creating", "active", "deleting"];

    /// <summary>The statuses a label read returns: only a Tenant someone holds a role in is read, so never a deleting one.</summary>
    public static readonly IReadOnlyList<string> LabelStatuses = ["creating", "active"];

    public static readonly IReadOnlyList<string> CreationStatuses = ["running", "failed"];

    public static readonly IReadOnlyList<string> OperationStatuses = ["running", "failed", "succeeded"];

    public static readonly IReadOnlyList<string> StepStatuses = ["pending", "running", "succeeded", "failed"];

    /// <summary>
    /// The Tenant switcher's list (Story 1.28): the active Tenants the current Admin holds a Tenant
    /// Role in, oldest first. Self-service, so no capability is checked, and no role is returned.
    /// </summary>
    public static async Task ListMineAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        IReadOnlyList<AdminTenant> tenants;
        try
        {
            await using var read = await services.BeginAsync(cancellationToken);
            tenants = await services.Tenants.ListForAdminAsync(read.CreateCommandContext(), principal, cancellationToken);
            await read.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, new AdminTenantListResponse
        {
            Tenants =
            [
                .. tenants.Select(t => new AdminTenantResponse
                {
                    Id = PublicId.Format(PublicIdType.Tenant, t.Id),
                    Name = t.Name,
                    Host = t.Host,
                    Label = t.Label,
                }),
            ],
        });
    }

    public static async Task ListAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        Guid? after = null;
        if (context.Request.Query.TryGetValue(CursorQuery, out var cursors))
        {
            // One canonical ten_ ID, or nothing: anything else names no page.
            if (cursors.Count != 1 || !PublicId.TryParse(PublicIdType.Tenant, cursors[0], out var cursor))
            {
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantInvalid, "A Tenants read");
                return;
            }

            after = cursor;
        }

        TenantPage? page;
        await using (var read = await services.BeginAsync(cancellationToken))
        {
            page = await services.Tenants.ListAsync(read.CreateCommandContext(), principal, after, PageSize, cancellationToken);
            await read.CommitAsync(cancellationToken);
        }

        if (page is null)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "A Tenants read");
            return;
        }

        await AdminResponses.JsonAsync(context, new TenantListResponse
        {
            TenantZone = services.Tenants.TenantZone,
            Tenants = [.. page.Tenants.Select(Tenant)],
            NextCursor = page.NextAfter is { } next ? PublicId.Format(PublicIdType.Tenant, next) : null,
        });
    }

    public static async Task CreateAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        // Under a deadline and a size cap, as application/json only: anything else is malformed.
        var body = await AdminApi.ReadJsonAsync<CreateTenantRequest>(context.Request, MaxCreateBody, cancellationToken);
        if (body is null || body.Name is null || body.Subdomain is null || body.Label is null)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantInvalid, "A Tenant creation");
            return;
        }

        TenantCreationResult result;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            result = await services.Tenants.CreateAsync(
                scope.CreateCommandContext(),
                principal,
                new CreateTenantInput(body.Name, body.Subdomain, body.Label),
                cancellationToken);

            if (result.Status == TenantCreationStatus.Created)
            {
                // Every row and the event are written: a client gone now mustn't undo them.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (AdminResponses.TenancyGuardStates.Contains(e.SqlState) && !context.Response.HasStarted)
        {
            // A guard the code's own checks should have met first: the same refusal, rolled back.
            AdminRequestChecks.Log(context, e);
            await RefuseAsync(
                context,
                StatusCodes.Status400BadRequest,
                e.SqlState == "GK002" ? AdminResponses.SubdomainRefused : AdminResponses.TenantInvalid,
                "A Tenant creation");
            return;
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case TenantCreationStatus.Created:
                var tenant = Tenant(result.Tenant!);
                var operation = Operation(result.Operation!);
                context.Response.StatusCode = StatusCodes.Status202Accepted;
                context.Response.Headers.Location = $"/api/v1/tenants/{tenant.Id}/operations/{operation.Id}";
                await AdminResponses.JsonAsync(
                    context,
                    new TenantCreatedResponse { Tenant = tenant, Operation = operation },
                    cancellationToken: CancellationToken.None);
                return;

            case TenantCreationStatus.Forbidden:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "A Tenant creation");
                return;

            case TenantCreationStatus.SubdomainRefused:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.SubdomainRefused, "A Tenant creation");
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantInvalid, "A Tenant creation");
                return;
        }
    }

    public static async Task RetryAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        // A malformed ID names no Operation: the same 404 as an unknown one.
        if (!PublicId.TryParse(PublicIdType.Operation, context.GetRouteValue(OperationRouteValue) as string, out var operationId))
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        OperationRetryResult result;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            result = await services.Tenants.RetryCreationAsync(scope.CreateCommandContext(), principal, operationId, cancellationToken);

            if (result.Status == OperationRetryStatus.Retried)
            {
                // The steps reopened, the run job enqueued and the event written: kept once decided.
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case OperationRetryStatus.Retried:
                context.Response.StatusCode = StatusCodes.Status202Accepted;
                await AdminResponses.JsonAsync(context, Operation(result.Operation!), cancellationToken: CancellationToken.None);
                return;

            case OperationRetryStatus.Forbidden:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "An Operation retry");
                return;

            case OperationRetryStatus.NotFailed:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.OperationNotFailed, "An Operation retry");
                return;

            case OperationRetryStatus.TenantDeleted:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantDeleted, "An Operation retry");
                return;

            default:
                await AdminResponses.NotFoundAsync(context);
                return;
        }
    }

    /// <summary>
    /// Starts a Tenant's deletion (Story 1.29). The request checks have used up the fresh assertion
    /// for <c>deployment.tenants.delete</c> on this Tenant before this runs, so from here nothing may
    /// stop the write a client going away: the transaction and the answer take no request token.
    /// </summary>
    public static async Task StartDeletionAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);

        // A malformed ID names no Tenant: the same 404 as an unknown one.
        if (!PublicId.TryParse(PublicIdType.Tenant, context.GetRouteValue(TargetTenantRouteValue) as string, out var tenantId))
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        // Under a deadline and a size cap, as application/json only: anything else is malformed.
        // A client gone before its body arrives has nothing started to finish.
        var body = await AdminApi.ReadJsonAsync<DeleteTenantRequest>(context.Request, MaxDeleteBody, context.RequestAborted);
        if (body?.Confirmation is not { } confirmation)
        {
            await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.TenantInvalid, "A Tenant deletion");
            return;
        }

        TenantDeletionResult result;
        try
        {
            await using var scope = await services.BeginAsync(CancellationToken.None);
            result = await services.Tenants.DeleteAsync(scope.CreateCommandContext(), principal, tenantId, confirmation, CancellationToken.None);

            if (result.Status == TenantDeletionStatus.Started)
            {
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (AdminResponses.DeletionGuardStates.Contains(e.SqlState) && !context.Response.HasStarted)
        {
            // A concurrent start that won the race, or the role guard: the same refusal, rolled back.
            AdminRequestChecks.Log(context, e);
            await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantDeleted, "A Tenant deletion");
            return;
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case TenantDeletionStatus.Started:
                context.Response.StatusCode = StatusCodes.Status202Accepted;
                context.Response.Headers.Location = DeletionLocation(tenantId);
                await AdminResponses.JsonAsync(context, Operation(result.Operation!), cancellationToken: CancellationToken.None);
                return;

            case TenantDeletionStatus.Forbidden:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "A Tenant deletion");
                return;

            case TenantDeletionStatus.NotFound:
                await AdminResponses.NotFoundAsync(context);
                return;

            case TenantDeletionStatus.AlreadyDeleted:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantDeleted, "A Tenant deletion");
                return;

            case TenantDeletionStatus.Busy:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.TenantBusy, "A Tenant deletion");
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status400BadRequest, AdminResponses.ConfirmationMismatch, "A Tenant deletion");
                return;
        }
    }

    /// <summary>The Tenant's newest deletion Operation, with every step (Story 1.29): a plain read, taking no lock.</summary>
    public static async Task GetDeletionAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);
        var cancellationToken = context.RequestAborted;

        if (!PublicId.TryParse(PublicIdType.Tenant, context.GetRouteValue(TargetTenantRouteValue) as string, out var tenantId))
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        TenantDeletionRead read;
        try
        {
            await using var scope = await services.BeginAsync(cancellationToken);
            read = await services.Tenants.GetDeletionAsync(scope.CreateCommandContext(), principal, tenantId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (!read.Allowed)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "A Tenant deletion read");
            return;
        }

        if (read.Operation is not { } operation)
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, Operation(operation));
    }

    /// <summary>
    /// Retries a failed deletion's failed steps (Story 1.29), after a new fresh assertion the request
    /// checks used up, so, as the start, it finishes whatever the client does.
    /// </summary>
    public static async Task RetryDeletionAsync(HttpContext context, AdminApiServices services)
    {
        var principal = AdminRequestChecks.Principal(context);

        if (!PublicId.TryParse(PublicIdType.Tenant, context.GetRouteValue(TargetTenantRouteValue) as string, out var tenantId))
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        OperationRetryResult result;
        try
        {
            await using var scope = await services.BeginAsync(CancellationToken.None);
            result = await services.Tenants.RetryDeletionAsync(scope.CreateCommandContext(), principal, tenantId, CancellationToken.None);

            if (result.Status == OperationRetryStatus.Retried)
            {
                await scope.CommitAsync(CancellationToken.None);
            }
        }
        catch (DbException e) when (AdminResponses.DeletionGuardStates.Contains(e.SqlState) && !context.Response.HasStarted)
        {
            // A Tenancy guard a concurrent change met first: nothing to retry, rolled back.
            AdminRequestChecks.Log(context, e);
            await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.OperationNotFailed, "A Tenant deletion retry");
            return;
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        switch (result.Status)
        {
            case OperationRetryStatus.Retried:
                context.Response.StatusCode = StatusCodes.Status202Accepted;
                context.Response.Headers.Location = DeletionLocation(tenantId);
                await AdminResponses.JsonAsync(context, Operation(result.Operation!), cancellationToken: CancellationToken.None);
                return;

            case OperationRetryStatus.Forbidden:
                await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "A Tenant deletion retry");
                return;

            case OperationRetryStatus.NotFound:
                await AdminResponses.NotFoundAsync(context);
                return;

            default:
                await RefuseAsync(context, StatusCodes.Status409Conflict, AdminResponses.OperationNotFailed, "A Tenant deletion retry");
                return;
        }
    }

    private static string DeletionLocation(Guid tenantId) =>
        $"/api/v1/deployment/tenants/{PublicId.Format(PublicIdType.Tenant, tenantId)}/deletion";

    /// <summary>
    /// The path Tenant's view of one Operation: only its own steps. Another Tenant's Operation, an
    /// unknown one and a malformed ID are the same unknown-path 404.
    /// </summary>
    public static async Task GetTenantOperationAsync(HttpContext context, AdminApiServices services)
    {
        var tenantId = AdminRequestChecks.PathTenant(context);
        var cancellationToken = context.RequestAborted;

        if (!PublicId.TryParse(PublicIdType.Operation, context.GetRouteValue(OperationRouteValue) as string, out var operationId))
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        TenantOperationRead read;
        await using (var scope = await services.BeginAsync(cancellationToken))
        {
            read = await services.Tenants.GetOperationAsync(
                scope.CreateCommandContext(), AdminRequestChecks.Principal(context), tenantId, operationId, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        if (!read.Allowed)
        {
            await RefuseAsync(context, StatusCodes.Status403Forbidden, AdminResponses.AccessDenied, "An Operation read");
            return;
        }

        if (read.Operation is not { } operation)
        {
            await AdminResponses.NotFoundAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, Operation(operation));
    }

    private static TenantResponse Tenant(ManagedTenant tenant) => new()
    {
        Id = PublicId.Format(PublicIdType.Tenant, tenant.Id),
        Name = tenant.Name,
        Host = tenant.Host,
        Label = tenant.Label,
        Status = tenant.Status,
        CreatedAt = tenant.CreatedAt,
        Creation = tenant.Creation is { } creation
            ? new TenantCreation
            {
                OperationId = PublicId.Format(PublicIdType.Operation, creation.OperationId),
                Status = creation.Status == ManagedOperationStatus.Failed ? "failed" : "running",
            }
            : null,
        Deletion = tenant.Deletion is { } deletion
            ? new TenantDeletion
            {
                OperationId = PublicId.Format(PublicIdType.Operation, deletion.OperationId),
                Status = deletion.Status == ManagedOperationStatus.Failed ? "failed" : "running",
            }
            : null,
    };

    private static OperationResponse Operation(ManagedOperation operation) => new()
    {
        Id = PublicId.Format(PublicIdType.Operation, operation.Id),
        Type = operation.Type,
        TenantId = operation.TenantId is { } tenant ? PublicId.Format(PublicIdType.Tenant, tenant) : null,
        Status = Status(operation.Status),
        CreatedAt = operation.CreatedAt,
        UpdatedAt = operation.UpdatedAt,
        FinishedAt = operation.FinishedAt,
        Steps =
        [
            .. operation.Steps.Select(s => new OperationStepResponse
            {
                Stage = s.Stage,
                TenantId = s.TenantId is { } stepTenant ? PublicId.Format(PublicIdType.Tenant, stepTenant) : null,
                Status = s.Status switch
                {
                    ManagedOperationStepStatus.Pending => "pending",
                    ManagedOperationStepStatus.Running => "running",
                    ManagedOperationStepStatus.Succeeded => "succeeded",
                    _ => "failed",
                },
                ResultCode = s.ResultCode,
                Attempts = s.Attempts,
                UpdatedAt = s.UpdatedAt,
            }),
        ],
    };

    private static string Status(ManagedOperationStatus status) => status switch
    {
        ManagedOperationStatus.Running => "running",
        ManagedOperationStatus.Failed => "failed",
        _ => "succeeded",
    };

    /// <summary>A refusal, logged under its fixed code only: never the name, subdomain or host.</summary>
    private static Task RefuseAsync(HttpContext context, int status, string problem, string what)
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation("{Request} was refused with {Problem}, trace {TraceId}.", what, problem, AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, status, problem);
    }
}
