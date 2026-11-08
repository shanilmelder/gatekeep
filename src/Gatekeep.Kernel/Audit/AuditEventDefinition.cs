namespace Gatekeep.Kernel.Audit;

/// <summary>The event classes FR-40 says a Tenant's Log covers.</summary>
public enum TenantLogClass
{
    SignIn,
    PasswordReset,
    EmailChange,
    Factor,
    RecoveryCode,
    SessionRevocation,
    AdminChange,
    KeyOperation,
    ManagementApiGrant,
    TokenFamilyRevocation,
    CrossTenantRejection,
}

/// <summary>
/// Whether an event records something done as asked (<see cref="Success"/>), or a refusal, a
/// denial, a failure or a death (<see cref="Failure"/>). Code-owned and never stored: it isn't in
/// the hash envelope, so a Log search by outcome is a search by the codes that have it (Story 7.4).
/// </summary>
public enum AuditOutcome
{
    Success,
    Failure,
}

/// <summary>
/// One published audit event: its code, a one-line summary, its outcome and the FR-40 class it
/// proves, if any. Each module declares its own in a <c>{Module}Events</c> class in its contract, and
/// <c>docs/audit-events.md</c> is generated from them. A code is a public contract: removing
/// or renaming one is a contract break.
/// </summary>
public sealed record AuditEventDefinition
{
    public const int MaxSummaryLength = 200;

    public AuditEventDefinition(AuditTypeCode code, string summary, AuditOutcome outcome, TenantLogClass? tenantLogClass = null)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(summary);

        if (summary.Length > MaxSummaryLength || summary.Contains('\n') || summary.Contains('\r') || summary.Contains('|'))
        {
            throw new ArgumentException(
                $"A summary is one line of at most {MaxSummaryLength} characters, with no '|'.",
                nameof(summary));
        }

        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        if (tenantLogClass is { } value && !Enum.IsDefined(value))
        {
            throw new ArgumentOutOfRangeException(nameof(tenantLogClass));
        }

        Code = code;
        Summary = summary;
        Outcome = outcome;
        TenantLogClass = tenantLogClass;
    }

    public AuditTypeCode Code { get; }

    public string Summary { get; }

    /// <summary>Whether the event is a success or a failure: a Log shows it, and searches by it.</summary>
    public AuditOutcome Outcome { get; }

    /// <summary>The FR-40 Tenant Log class this event proves, or null when it proves none.</summary>
    public TenantLogClass? TenantLogClass { get; }
}
