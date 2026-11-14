using Gatekeep.Kernel.Audit;

namespace Gatekeep.Modules.Audit.Core;

/// <summary>
/// The Actor and target kinds as both chains store them. The tables' <c>CHECK</c> constraints
/// allow only these spellings, so an unknown one is a broken invariant, not a caller's error.
/// </summary>
internal static class StoredKinds
{
    public static ActorKind ActorKindOf(string stored) => stored switch
    {
        "system" => ActorKind.System,
        "anonymous" => ActorKind.Anonymous,
        "admin" => ActorKind.Admin,
        "user" => ActorKind.User,
        "client" => ActorKind.Client,
        _ => throw new InvalidOperationException("An audit event has an unknown Actor kind."),
    };

    public static AuditTargetKind TargetKindOf(string stored) => stored switch
    {
        "tenant" => AuditTargetKind.Tenant,
        "admin" => AuditTargetKind.Admin,
        "user" => AuditTargetKind.User,
        "client" => AuditTargetKind.Client,
        "api" => AuditTargetKind.Api,
        _ => throw new InvalidOperationException("An audit event has an unknown target kind."),
    };
}
