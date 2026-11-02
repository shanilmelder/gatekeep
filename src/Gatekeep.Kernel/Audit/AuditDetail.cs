using System.Net;

namespace Gatekeep.Kernel.Audit;

/// <summary>
/// Personal data beside an event, stored apart from the envelope so erasure can act on
/// it alone (AD-16). Only <see cref="ToString"/> is masked: the properties still hold
/// the values, and serializing this record writes them.
/// </summary>
public sealed record AuditDetail(IPAddress? IpAddress, string? UserAgent, string? Email)
{
    public override string ToString() => nameof(AuditDetail);
}
