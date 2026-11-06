using Gatekeep.Kernel.Audit;

namespace Gatekeep.Kernel.Alerts;

/// <summary>
/// A Security Alert's code and the fixed summary that goes with it (AD-17). Codes are
/// <c>{domain}.{object}.{action}</c>, and each summary is code-owned text, so an alert never
/// carries text from a request, a User or an error.
/// </summary>
public sealed record SecurityAlertCode
{
    private const int MaxSummaryLength = 200;

    private SecurityAlertCode(AuditTypeCode code, string summary)
    {
        Code = code;
        Summary = summary;
    }

    /// <summary>
    /// Sent by <c>gatekeep alerts test</c> (Story 1.30), so the Operator can prove at install that
    /// the channel reaches someone. Nothing happened and nothing needs doing.
    /// </summary>
    public static SecurityAlertCode Test { get; } = Define(
        "operations.alert.test",
        "Test alert sent by gatekeep alerts test. Nothing happened and nothing needs doing.");

    public AuditTypeCode Code { get; }

    public string Summary { get; }

    /// <summary>
    /// Defines a code and its summary. Only code-owned constants call this: Story 11.1's alert table
    /// in Notifications is the other place codes come from.
    /// </summary>
    public static SecurityAlertCode Define(string code, string summary)
    {
        ArgumentNullException.ThrowIfNull(summary);

        if (summary.Length is 0 or > MaxSummaryLength
            || summary.Any(c => char.IsControl(c))
            || summary.Contains("://", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "A Security Alert summary is one line of fixed text, at most 200 characters, with no address.",
                nameof(summary));
        }

        return new SecurityAlertCode(new AuditTypeCode(code), summary);
    }

    public override string ToString() => Code.Value;
}

/// <summary>
/// The Deployment an alert comes from, named by its Admin hostname: lower-case DNS labels, at
/// least two, as Caddy's Admin site checks it. Never a URL.
/// </summary>
public sealed record AlertDeployment
{
    private const int MaxLength = 253;
    private const int MaxLabelLength = 63;

    public AlertDeployment(string name)
    {
        if (!IsValid(name))
        {
            throw new ArgumentException("A Deployment is named by its Admin hostname: lower-case DNS labels, at least two.", nameof(name));
        }

        Name = name;
    }

    public string Name { get; }

    /// <summary>Whether <paramref name="name"/> is a lower-case DNS name of two labels or more, not an IP address.</summary>
    public static bool IsValid(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxLength)
        {
            return false;
        }

        var labels = name.Split('.');
        if (labels.Length < 2 || labels[^1].All(char.IsAsciiDigit))
        {
            return false;
        }

        return labels.All(label =>
            label.Length is > 0 and <= MaxLabelLength
            && label[0] != '-'
            && label[^1] != '-'
            && label.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-'));
    }

    public override string ToString() => Name;
}

/// <summary>
/// One Security Alert (AD-17): only these fields ever leave the Deployment. It holds no personal
/// data, credential, token, URL query or free text: the summary comes from <see cref="Code"/>, and
/// the Tenant and event are internal IDs.
/// </summary>
public sealed record SecurityAlert
{
    public SecurityAlert(
        SecurityAlertCode code,
        Guid alertId,
        DateTimeOffset raisedAt,
        AlertDeployment deployment,
        Guid? tenantId = null,
        Guid? eventId = null)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(deployment);

        if (alertId == Guid.Empty || alertId.Version != 7)
        {
            throw new ArgumentException("An alert ID is a UUIDv7.", nameof(alertId));
        }

        if (tenantId == Guid.Empty || eventId == Guid.Empty)
        {
            throw new ArgumentException("An empty ID names no Tenant or event.");
        }

        Code = code;
        AlertId = alertId;
        RaisedAt = raisedAt.ToUniversalTime();
        Deployment = deployment;
        TenantId = tenantId;
        EventId = eventId;
    }

    public SecurityAlertCode Code { get; }

    public Guid AlertId { get; }

    /// <summary>When it was raised, in UTC.</summary>
    public DateTimeOffset RaisedAt { get; }

    public AlertDeployment Deployment { get; }

    public Guid? TenantId { get; }

    public Guid? EventId { get; }

    /// <summary>The fixed summary for <see cref="Code"/>.</summary>
    public string Summary => Code.Summary;

    /// <summary>A new alert, with a fresh UUIDv7 and the time now.</summary>
    public static SecurityAlert Raise(
        SecurityAlertCode code,
        AlertDeployment deployment,
        TimeProvider time,
        Guid? tenantId = null,
        Guid? eventId = null)
    {
        ArgumentNullException.ThrowIfNull(time);

        var now = time.GetUtcNow();
        return new SecurityAlert(code, Guid.CreateVersion7(now), now, deployment, tenantId, eventId);
    }
}
