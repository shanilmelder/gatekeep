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
        "A job used its last attempt and went dead. Only its fixed failure code is kept.",
        AuditOutcome.Failure);

    /// <summary>
    /// Written on the Deployment chain when an Admin retries a failed Operation (Story 1.27), in the
    /// transaction that reopens its failed steps. The Actor is the Admin; the target the Operation's
    /// Tenant, when it has one: the envelope has no Operation target kind.
    /// </summary>
    public static readonly AuditEventDefinition OperationRetried = new(
        new AuditTypeCode("operations.operation.retried"),
        "An Admin retried a failed Operation's failed steps. Names the Operation's Tenant only, when it has one.",
        AuditOutcome.Success);
}
