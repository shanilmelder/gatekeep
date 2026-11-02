namespace Gatekeep.Modules.Audit.Contracts;

/// <summary>
/// The hashed part of one sealed audit row (AD-16), with the kinds as stored. Detail is never
/// part of it. <paramref name="TenantId"/> is null on the Deployment chain. The three
/// checkpoint members are set on a retention checkpoint only, naming the last row retention
/// deleted, and the canonical envelope holds each only when it's set, so every other row's
/// envelope is the ten members alone.
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
    long Seq,
    long? CheckpointEpoch = null,
    long? CheckpointSeq = null,
    byte[]? CheckpointHash = null);
