using Gatekeep.Kernel.Limits;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 3.3 (PRD §5.2): a rotated-out client secret overlaps its replacement for a fixed default that is
/// never configurable and never beyond its hard limit, and an Application holds at most its current secret
/// and one rotated-out one.
/// </summary>
public class ClientSecretLimitTests
{
    [Fact]
    public void The_overlap_is_24_hours_within_the_7_day_hard_limit()
    {
        Assert.Equal(TimeSpan.FromHours(24), SecurityLimits.ClientSecretOverlap);
        Assert.Equal(TimeSpan.FromDays(7), SecurityLimits.HardClientSecretOverlap);
        Assert.True(SecurityLimits.ClientSecretOverlap <= SecurityLimits.HardClientSecretOverlap);
        Assert.True(SecurityLimits.ClientSecretOverlap > TimeSpan.Zero);
    }

    [Fact]
    public void An_Application_holds_at_most_a_current_and_one_rotated_out_secret()
    {
        Assert.Equal(2, SecurityLimits.MaxLiveClientSecrets);
    }
}
