using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// The audit events Audit writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class AuditEvents
{
    /// <summary>Written by a retention cut. Only <c>gk_retention</c> can insert one, and its checkpoint columns are set exactly on it.</summary>
    public static readonly AuditEventDefinition RetentionCheckpoint = new(
        new AuditTypeCode("audit.retention.checkpoint"),
        "Retention deleted a chain's sealed prefix past the Log period. Names the last deleted row's epoch, seq and hash.",
        AuditOutcome.Success);
}
