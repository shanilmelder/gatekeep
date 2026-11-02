namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// The hashed part of one sealed audit row (AD-16), with the kinds as stored. Detail is never
/// part of it. <paramref name="TenantId"/> is null on the Deployment chain.
/// </summary>
public sealed record ChainEnvelope(
    Guid? TenantId,
    Guid Id,
    DateTimeOffset OccurredAt,
    string TypeCode,
    string ActorKind,
    Guid? ActorId,
    string? TargetKind,
    Guid? TargetId,
    long Epoch,
    long Seq);
