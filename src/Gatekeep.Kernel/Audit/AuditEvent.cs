namespace Gatekeep.Kernel.Audit;

public enum AuditTargetKind
{
    Tenant,
    Admin,
    User,
    Client,
}

/// <summary>
/// The audit envelope: a validated code and internal references only (AD-16). It has
/// no free-form string or object property, and an architecture test holds it to that.
/// Personal data goes in <see cref="AuditDetail"/>.
/// </summary>
public sealed class AuditEvent
{
    public AuditEvent(AuditTypeCode type, Actor actor, AuditTargetKind? targetKind = null, Guid? targetId = null)
    {
        ArgumentNullException.ThrowIfNull(type);
        ArgumentNullException.ThrowIfNull(actor);

        if (targetKind.HasValue != targetId.HasValue)
        {
            throw new ArgumentException("A target has both a kind and an ID, or neither.", nameof(targetId));
        }

        if (targetId == Guid.Empty)
        {
            throw new ArgumentException("A target ID can't be empty.", nameof(targetId));
        }

        Type = type;
        Actor = actor;
        TargetKind = targetKind;
        TargetId = targetId;
    }

    public AuditTypeCode Type { get; }

    public Actor Actor { get; }

    public AuditTargetKind? TargetKind { get; }

    public Guid? TargetId { get; }
}
