namespace Gatekeep.Kernel.Retention;

/// <summary>
/// The PRD §5.2 retention values, the one place any of them is declared:
/// <code>
/// | Log retention | 90 days | 90-day floor in Prod Tenants |
///
/// v1 has no setting for Signing Key maximum age, client secret overlap or Log retention.
/// Each is fixed at its default, and only a release can change it, within the hard limit.
/// </code>
/// These are constants, so no setting, route or Cli argument can change them, and an
/// architecture test holds <see cref="LogDays"/> to at least <see cref="LogFloorDays"/>.
/// </summary>
public static class RetentionPeriods
{
    /// <summary>How long an audit event is kept, in days, before retention may delete it (NFR-15, AD-16).</summary>
    public const int LogDays = 90;

    /// <summary>The §5.2 floor <see cref="LogDays"/> can't go below. The floor can't be lowered.</summary>
    public const int LogFloorDays = 90;
}
