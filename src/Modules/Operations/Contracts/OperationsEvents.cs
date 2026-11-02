using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Operations.Contracts;

/// <summary>
/// The audit events Operations writes. Codes are a public contract, published in
/// <c>docs/audit-events.md</c>: removing or renaming one is a contract break.
/// </summary>
public static class OperationsEvents
{
    /// <summary>Written by the job runner in the job's own chain, with a <c>system</c> Actor, as the job goes dead.</summary>
    public static readonly AuditEventDefinition JobDead = new(
        new AuditTypeCode("operations.job.dead"),
        "A job used its last attempt and went dead. Only its fixed failure code is kept.");
}
