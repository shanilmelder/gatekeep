using System.Data.Common;
using System.Globalization;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Microsoft.Extensions.Primitives;

namespace Gatekeep.Host.Admin;

/// <summary>Who caused an event, or what it acted on, as a Log shows it: a kind and an ID, never a name or an email.</summary>
public sealed class LogReference
{
    /// <summary><c>system</c>, <c>anonymous</c>, <c>admin</c>, <c>user</c> or <c>client</c> (an Application), or <c>tenant</c> or <c>api</c> (Story 3.6) as a target.</summary>
    public required string Kind { get; init; }

    /// <summary>
    /// The internal reference: a UUID for an Admin, a User or an Application, the <c>ten_</c> public ID
    /// for a Tenant, the <c>api_</c> public ID for an API (Story 3.6), and null for <c>system</c> and <c>anonymous</c>.
    /// </summary>
    public required string? Id { get; init; }
}

/// <summary>One event in a Tenant's Log: its envelope and its catalogue summary, and nothing from its detail.</summary>
public sealed class TenantLogEventResponse
{
    /// <summary>The event's public ID: <c>evt_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    /// <summary>When the database recorded it.</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>Its type code, <c>{domain}.{object}.{action}</c>, as <c>docs/audit-events.md</c> publishes it.</summary>
    public required string Type { get; init; }

    /// <summary><c>success</c> or <c>failure</c>, from the type's catalogue entry; null for a code no catalogue declares.</summary>
    public required string? Outcome { get; init; }

    /// <summary>The type's one-line catalogue summary; null for a code no catalogue declares.</summary>
    public required string? Summary { get; init; }

    public required LogReference Actor { get; init; }

    /// <summary>What it acted on, or null when it names nothing.</summary>
    public required LogReference? Target { get; init; }
}

/// <summary>One page of a Tenant's Log, newest first.</summary>
public sealed class TenantLogsResponse
{
    public required IReadOnlyList<TenantLogEventResponse> Events { get; init; }

    /// <summary>The cursor for the next, older page, the last event's ID, or null when this is the last page.</summary>
    public required string? NextCursor { get; init; }
}

/// <summary>An event's seal as raw detail shows it: its place in the chain and its hashes in lowercase hex.</summary>
public sealed class TenantLogSealResponse
{
    /// <summary>Its sequence number in the Tenant's chain.</summary>
    public required long Seq { get; init; }

    /// <summary>The previous event's hash, lowercase hex; null for the chain's first event.</summary>
    public required string? PrevHash { get; init; }

    /// <summary>This event's hash, <c>SHA-256(prevHash || canonical envelope)</c>, lowercase hex.</summary>
    public required string Hash { get; init; }
}

/// <summary>An event's detail row: the personal data kept outside the hash.</summary>
public sealed class TenantLogRawDetailResponse
{
    /// <summary>The client's IP address, when one was recorded.</summary>
    public required string? IpAddress { get; init; }

    /// <summary>The client's User-Agent, when one was recorded.</summary>
    public required string? UserAgent { get; init; }

    /// <summary>The email the event concerns, when one was recorded.</summary>
    public required string? Email { get; init; }
}

/// <summary>An event's raw detail (Story 7.5): its envelope as the search shows it, its seal and its detail row.</summary>
public sealed class TenantLogRawResponse
{
    /// <summary>The event's public ID: <c>evt_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    /// <summary>When the database recorded it.</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>Its type code.</summary>
    public required string Type { get; init; }

    public required LogReference Actor { get; init; }

    /// <summary>What it acted on, or null when it names nothing.</summary>
    public required LogReference? Target { get; init; }

    /// <summary>Its seal, or null while it is unsealed.</summary>
    public required TenantLogSealResponse? Seal { get; init; }

    /// <summary>Its detail row, or null when it has none.</summary>
    public required TenantLogRawDetailResponse? Detail { get; init; }
}

/// <summary>
/// One event of a Tenant's Log, opened (Story 7.5): the same fields as a search row, and its raw
/// detail only for a caller who holds <c>tenant.log_detail.read</c>.
/// </summary>
public sealed class TenantLogEventDetailResponse
{
    /// <summary>The event's public ID: <c>evt_</c> and 26 base32 characters.</summary>
    public required string Id { get; init; }

    /// <summary>When the database recorded it.</summary>
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>Its type code, <c>{domain}.{object}.{action}</c>, as <c>docs/audit-events.md</c> publishes it.</summary>
    public required string Type { get; init; }

    /// <summary><c>success</c> or <c>failure</c>, from the type's catalogue entry; null for a code no catalogue declares.</summary>
    public required string? Outcome { get; init; }

    /// <summary>The type's one-line catalogue summary; null for a code no catalogue declares.</summary>
    public required string? Summary { get; init; }

    public required LogReference Actor { get; init; }

    /// <summary>What it acted on, or null when it names nothing.</summary>
    public required LogReference? Target { get; init; }

    /// <summary>The raw detail: in a Tenant's Log, null unless the caller holds <c>tenant.log_detail.read</c> in this Tenant; always set in the Deployment Log.</summary>
    public required TenantLogRawResponse? Raw { get; init; }
}

/// <summary>
/// A Tenant's Log search (Story 7.4, FR-40): read-only, in the path Tenant's own scope, so
/// row-level security holds it to that Tenant. Every parameter is optional, sent at most once and
/// ANDed: an event type, a User by UUID or email, an Application by UUID, an outcome and a time
/// range, each on an indexed envelope column. Anything malformed is 400 <c>invalid_request</c>,
/// before anything is read. A response holds the envelope and the catalogue summary only: no IP
/// address, User-Agent or email. Reading a Log isn't audited.
/// </summary>
internal static partial class TenantLogsApi
{
    public const string TypeQuery = "type";

    public const string UserQuery = "user";

    public const string ApplicationQuery = "application";

    public const string OutcomeQuery = "outcome";

    public const string FromQuery = "from";

    public const string ToQuery = "to";

    public const string CursorQuery = "cursor";

    /// <summary>The route value that names one event: its <c>evt_</c> public ID.</summary>
    public const string EventRouteValue = "eventId";

    /// <summary>Events per page (Conventions).</summary>
    public const int PageSize = TenantLogQuery.MaxLimit;

    /// <summary>The outcome values, as the API spells them.</summary>
    public static readonly IReadOnlyList<string> Outcomes = ["success", "failure"];

    /// <summary>The reference kinds an Actor or target can have, as the API spells them.</summary>
    public static readonly IReadOnlyList<string> ReferenceKinds = ["system", "anonymous", "admin", "user", "client", "tenant", "api"];

    private const int MaxEmailLength = 320;

    public static async Task SearchAsync(HttpContext context, AdminApiServices services)
    {
        var cancellationToken = context.RequestAborted;
        if (Parse(context.Request.Query) is not { } query)
        {
            await RefuseAsync(context);
            return;
        }

        TenantLogPage page;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            page = await services.LogSearch.SearchAsync(scope.CreateCommandContext(), query, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        await AdminResponses.JsonAsync(context, Page(page));
    }

    /// <summary>
    /// One event, opened (Story 7.5). The route needs <c>tenant.logs.read</c>; the raw detail is
    /// decided here, by <c>tenant.log_detail.read</c>, and without it <c>audit_detail</c> isn't read.
    /// Another Tenant's event is the same 404 as an unknown one. Reading isn't audited.
    /// </summary>
    public static async Task GetAsync(HttpContext context, AdminApiServices services)
    {
        var cancellationToken = context.RequestAborted;
        if (!PublicId.TryParse(PublicIdType.AuditEvent, context.GetRouteValue(EventRouteValue) as string, out var eventId))
        {
            await RefuseEventAsync(context, StatusCodes.Status400BadRequest, AdminResponses.InvalidRequest);
            return;
        }

        var path = AdminRequestChecks.PathTenantGrant(context);
        var withDetail = AdminCapabilities.Allows(
            AdminCapabilities.TenantLogDetailRead, AdminRequestChecks.Principal(context), path.Grant, path.TenantId);

        TenantLogEvent? found;
        try
        {
            await using var scope = await TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), cancellationToken);
            found = await services.LogEvents.FindAsync(scope.CreateCommandContext(), eventId, withDetail, cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }
        catch (DbException e) when (!context.Response.HasStarted)
        {
            AdminRequestChecks.Log(context, e);
            await AdminResponses.UnavailableAsync(context);
            return;
        }

        if (found is null)
        {
            await RefuseEventAsync(context, StatusCodes.Status404NotFound, AdminResponses.NotFound);
            return;
        }

        await AdminResponses.JsonAsync(context, Opened(found, withDetail));
    }

    /// <summary>A page of a Log as the API answers it: shared by the Tenant and the Deployment Log (Story 7.7).</summary>
    internal static TenantLogsResponse Page(TenantLogPage page) => new()
    {
        Events = [.. page.Events.Select(Event)],
        NextCursor = page.NextAfter is { } next ? PublicId.Format(PublicIdType.AuditEvent, next) : null,
    };

    /// <summary>An opened event as the API answers it, with <c>raw</c> only when <paramref name="withRaw"/>.</summary>
    internal static TenantLogEventDetailResponse Opened(TenantLogEvent found, bool withRaw)
    {
        var summary = Event(found.Entry);
        return new TenantLogEventDetailResponse
        {
            Id = summary.Id,
            OccurredAt = summary.OccurredAt,
            Type = summary.Type,
            Outcome = summary.Outcome,
            Summary = summary.Summary,
            Actor = summary.Actor,
            Target = summary.Target,
            Raw = withRaw ? Raw(summary, found) : null,
        };
    }

    /// <summary>The search a query string names, or null when any parameter in it is malformed.</summary>
    internal static TenantLogQuery? Parse(IQueryCollection parameters)
    {
        if (ParseShared(parameters) is not { } shared
            || !Single(parameters, UserQuery, out var user)
            || !Single(parameters, ApplicationQuery, out var application))
        {
            return null;
        }

        var query = new TenantLogQuery
        {
            Types = shared.Types,
            OutcomeTypes = shared.OutcomeTypes,
            From = shared.From,
            To = shared.To,
            After = shared.After,
        };

        if (user is not null)
        {
            if (IsUuid(user, out var userId))
            {
                query = query with { UserId = userId };
            }
            else if (IsEmail(user))
            {
                query = query with { UserEmail = user };
            }
            else
            {
                return null;
            }
        }

        if (application is not null)
        {
            if (!IsUuid(application, out var applicationId))
            {
                return null;
            }

            query = query with { ApplicationId = applicationId };
        }

        return query with { Limit = PageSize };
    }

    /// <summary>
    /// The filters every Log search takes (Stories 7.4 and 7.7): an event type, an outcome, a time
    /// range and a cursor, or null when any of them is malformed.
    /// </summary>
    internal static LogFilters? ParseShared(IQueryCollection parameters)
    {
        if (!Single(parameters, TypeQuery, out var type)
            || !Single(parameters, OutcomeQuery, out var outcome)
            || !Single(parameters, FromQuery, out var from)
            || !Single(parameters, ToQuery, out var to)
            || !Single(parameters, CursorQuery, out var cursor))
        {
            return null;
        }

        var filters = new LogFilters();

        if (type is not null)
        {
            if (!IsCode(type))
            {
                return null;
            }

            filters = filters with { Types = [new AuditTypeCode(type)] };
        }

        if (outcome is not null)
        {
            var wanted = outcome switch
            {
                "success" => AuditOutcome.Success,
                "failure" => AuditOutcome.Failure,
                _ => (AuditOutcome?)null,
            };
            if (wanted is not { } value)
            {
                return null;
            }

            filters = filters with { OutcomeTypes = LogCatalogue.CodesWith(value) };
        }

        if (from is not null)
        {
            if (!IsInstant(from, out var since))
            {
                return null;
            }

            filters = filters with { From = since };
        }

        if (to is not null)
        {
            if (!IsInstant(to, out var until))
            {
                return null;
            }

            filters = filters with { To = until };
        }

        if (filters.From is { } start && filters.To is { } end && start >= end)
        {
            return null;
        }

        if (cursor is not null)
        {
            if (!PublicId.TryParse(PublicIdType.AuditEvent, cursor, out var after))
            {
                return null;
            }

            filters = filters with { After = after };
        }

        return filters;
    }

    private static TenantLogEventResponse Event(TenantLogEntry entry)
    {
        var definition = LogCatalogue.Find(entry.Type.Value);
        return new TenantLogEventResponse
        {
            Id = PublicId.Format(PublicIdType.AuditEvent, entry.Id),
            OccurredAt = entry.OccurredAt,
            Type = entry.Type.Value,
            Outcome = definition is null ? null : definition.Outcome == AuditOutcome.Failure ? "failure" : "success",
            Summary = definition?.Summary,
            Actor = new LogReference { Kind = Stored(entry.ActorKind), Id = entry.ActorId?.ToString("D") },
            Target = entry.TargetKind is { } kind
                ? new LogReference
                {
                    Kind = Stored(kind),
                    Id = kind switch
                    {
                        AuditTargetKind.Tenant => PublicId.Format(PublicIdType.Tenant, entry.TargetId!.Value),
                        AuditTargetKind.Api => PublicId.Format(PublicIdType.Api, entry.TargetId!.Value),
                        _ => entry.TargetId!.Value.ToString("D"),
                    },
                }
                : null,
        };
    }

    private static TenantLogRawResponse Raw(TenantLogEventResponse summary, TenantLogEvent found) => new()
    {
        Id = summary.Id,
        OccurredAt = summary.OccurredAt,
        Type = summary.Type,
        Actor = summary.Actor,
        Target = summary.Target,
        Seal = found.Seal is { } seal
            ? new TenantLogSealResponse
            {
                Seq = seal.Seq,
                PrevHash = seal.PrevHash is { } previous ? Convert.ToHexStringLower(previous) : null,
                Hash = Convert.ToHexStringLower(seal.Hash),
            }
            : null,
        Detail = found.Detail is { } detail
            ? new TenantLogRawDetailResponse { IpAddress = detail.IpAddress, UserAgent = detail.UserAgent, Email = detail.Email }
            : null,
    };

    private static string Stored<TKind>(TKind kind)
        where TKind : struct, Enum =>
        kind.ToString().ToLowerInvariant();

    /// <summary>A parameter sent at most once, with a value: sent twice, or empty, is malformed.</summary>
    internal static bool Single(IQueryCollection parameters, string name, out string? value)
    {
        value = null;
        if (!parameters.TryGetValue(name, out StringValues values))
        {
            return true;
        }

        if (values.Count != 1 || string.IsNullOrEmpty(values[0]))
        {
            return false;
        }

        value = values[0];
        return true;
    }

    private static bool IsCode(string value)
    {
        try
        {
            _ = new AuditTypeCode(value);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>A UUID in its hyphenated form only, as every internal reference is written.</summary>
    internal static bool IsUuid(string value, out Guid id) =>
        Guid.TryParseExact(value, "D", out id) && id != Guid.Empty;

    /// <summary>One <c>@</c> between a local part and a domain, with no space or control character: a filter, not a validation.</summary>
    private static bool IsEmail(string value) =>
        value.Length <= MaxEmailLength && Email().IsMatch(value);

    /// <summary>An ISO 8601 date and time with seconds optional and an explicit <c>Z</c> or offset: an instant, never a local time.</summary>
    private static bool IsInstant(string value, out DateTimeOffset instant)
    {
        instant = default;
        return Instant().IsMatch(value)
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out instant);
    }

    internal static Task RefuseAsync(HttpContext context)
    {
        // The fixed code only: never a parameter's value, which may be an email.
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation(
                "A Log search was refused with {Problem}, trace {TraceId}.",
                AdminResponses.InvalidRequest,
                AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, StatusCodes.Status400BadRequest, AdminResponses.InvalidRequest);
    }

    internal static Task RefuseEventAsync(HttpContext context, int status, string problem)
    {
        // The fixed code only: never the route value.
        context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Gatekeep.Host.Admin")
            .LogInformation(
                "A Log event read was refused with {Problem}, trace {TraceId}.",
                problem,
                AdminResponses.TraceId(context));
        return AdminResponses.ProblemAsync(context, status, problem);
    }

    [GeneratedRegex(@"\A[^@\s\p{C}]+@[^@\s\p{C}]+\z")]
    private static partial Regex Email();

    [GeneratedRegex(@"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,7})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})\z")]
    private static partial Regex Instant();
}

/// <summary>The filters every Log search shares: an event type, an outcome's codes, a time range and a cursor.</summary>
internal sealed record LogFilters
{
    public IReadOnlyCollection<AuditTypeCode>? Types { get; init; }

    public IReadOnlyCollection<AuditTypeCode>? OutcomeTypes { get; init; }

    public DateTimeOffset? From { get; init; }

    public DateTimeOffset? To { get; init; }

    public Guid? After { get; init; }
}
