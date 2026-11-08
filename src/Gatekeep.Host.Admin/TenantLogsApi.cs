using System.Data.Common;
using System.Globalization;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Microsoft.Extensions.Primitives;

namespace Gatekeep.Host.Admin;

/// <summary>Who caused an event, or what it acted on, as a Log shows it: a kind and an ID, never a name or an email.</summary>
public sealed class LogReference
{
    /// <summary><c>system</c>, <c>anonymous</c>, <c>admin</c>, <c>user</c> or <c>client</c> (an Application), or <c>tenant</c> as a target.</summary>
    public required string Kind { get; init; }

    /// <summary>
    /// The internal reference: a UUID for an Admin, a User or an Application, the <c>ten_</c> public ID
    /// for a Tenant, and null for <c>system</c> and <c>anonymous</c>.
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

    /// <summary>Events per page (Conventions).</summary>
    public const int PageSize = TenantLogQuery.MaxLimit;

    /// <summary>The outcome values, as the API spells them.</summary>
    public static readonly IReadOnlyList<string> Outcomes = ["success", "failure"];

    /// <summary>The reference kinds an Actor or target can have, as the API spells them.</summary>
    public static readonly IReadOnlyList<string> ReferenceKinds = ["system", "anonymous", "admin", "user", "client", "tenant"];

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

        await AdminResponses.JsonAsync(context, new TenantLogsResponse
        {
            Events = [.. page.Events.Select(Event)],
            NextCursor = page.NextAfter is { } next ? PublicId.Format(PublicIdType.AuditEvent, next) : null,
        });
    }

    /// <summary>The search a query string names, or null when any parameter in it is malformed.</summary>
    internal static TenantLogQuery? Parse(IQueryCollection parameters)
    {
        var query = new TenantLogQuery();

        if (!Single(parameters, TypeQuery, out var type)
            || !Single(parameters, UserQuery, out var user)
            || !Single(parameters, ApplicationQuery, out var application)
            || !Single(parameters, OutcomeQuery, out var outcome)
            || !Single(parameters, FromQuery, out var from)
            || !Single(parameters, ToQuery, out var to)
            || !Single(parameters, CursorQuery, out var cursor))
        {
            return null;
        }

        if (type is not null)
        {
            if (!IsCode(type))
            {
                return null;
            }

            query = query with { Types = [new AuditTypeCode(type)] };
        }

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

            query = query with { OutcomeTypes = LogCatalogue.CodesWith(value) };
        }

        if (from is not null)
        {
            if (!IsInstant(from, out var since))
            {
                return null;
            }

            query = query with { From = since };
        }

        if (to is not null)
        {
            if (!IsInstant(to, out var until))
            {
                return null;
            }

            query = query with { To = until };
        }

        if (query.From is { } start && query.To is { } end && start >= end)
        {
            return null;
        }

        if (cursor is not null)
        {
            if (!PublicId.TryParse(PublicIdType.AuditEvent, cursor, out var after))
            {
                return null;
            }

            query = query with { After = after };
        }

        return query with { Limit = PageSize };
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
                    Id = kind == AuditTargetKind.Tenant
                        ? PublicId.Format(PublicIdType.Tenant, entry.TargetId!.Value)
                        : entry.TargetId!.Value.ToString("D"),
                }
                : null,
        };
    }

    private static string Stored<TKind>(TKind kind)
        where TKind : struct, Enum =>
        kind.ToString().ToLowerInvariant();

    /// <summary>A parameter sent at most once, with a value: sent twice, or empty, is malformed.</summary>
    private static bool Single(IQueryCollection parameters, string name, out string? value)
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
    private static bool IsUuid(string value, out Guid id) =>
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

    private static Task RefuseAsync(HttpContext context)
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

    [GeneratedRegex(@"\A[^@\s\p{C}]+@[^@\s\p{C}]+\z")]
    private static partial Regex Email();

    [GeneratedRegex(@"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,7})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})\z")]
    private static partial Regex Instant();
}
