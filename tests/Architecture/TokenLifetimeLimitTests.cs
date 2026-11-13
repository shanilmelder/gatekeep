using System.Globalization;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Limits;
using Xunit;

namespace Gatekeep.Tests.Architecture;

/// <summary>
/// Story 3.4 (PRD §5.2): the token lifetimes an Application may hold. The table's CHECKs and defaults, written as
/// literal seconds in the migration that adds them, are the <see cref="SecurityLimits"/> constants: a hard limit or
/// default changed in one place but not the other fails here. No hard limit is above PRD §5.2's, and each default
/// is within its limit.
/// </summary>
public class TokenLifetimeLimitTests
{
    private const string Migration = "src/Adapters/Postgres/Migrations/Migration20261116000000SetTokenLifetimes.cs";

    private static readonly string Root = EdgeList.FindRepositoryRoot(AppContext.BaseDirectory);

    public static TheoryData<string, int, int> Columns => new()
    {
        { "access_token_lifetime", Seconds(SecurityLimits.DefaultAccessTokenLifetime), Seconds(SecurityLimits.HardSignedTokenLifetime) },
        { "id_token_lifetime", Seconds(SecurityLimits.DefaultIdentityTokenLifetime), Seconds(SecurityLimits.HardSignedTokenLifetime) },
        { "refresh_token_absolute_lifetime", Seconds(SecurityLimits.RefreshTokenAbsoluteLifetime), Seconds(SecurityLimits.HardRefreshTokenAbsoluteLifetime) },
        { "refresh_token_inactivity_lifetime", Seconds(SecurityLimits.RefreshTokenInactivityLifetime), Seconds(SecurityLimits.HardRefreshTokenInactivityLifetime) },
    };

    [Theory]
    [MemberData(nameof(Columns))]
    public void The_migrations_default_and_CHECK_are_the_limits_files(string column, int defaultSeconds, int maximumSeconds)
    {
        var source = File.ReadAllText(Path.Combine(Root, Migration));

        var added = Regex.Match(source, $@"ADD COLUMN {column} integer NOT NULL DEFAULT (\d+);");
        Assert.True(added.Success, $"{column} isn't added as integer NOT NULL with a default.");
        Assert.Equal(defaultSeconds, int.Parse(added.Groups[1].Value, CultureInfo.InvariantCulture));

        var check = Regex.Match(source, $@"CHECK \({column} BETWEEN (\d+) AND (\d+)\)");
        Assert.True(check.Success, $"{column} has no BETWEEN CHECK.");
        Assert.Equal(1, int.Parse(check.Groups[1].Value, CultureInfo.InvariantCulture));
        Assert.Equal(maximumSeconds, int.Parse(check.Groups[2].Value, CultureInfo.InvariantCulture));
    }

    [Fact]
    public void The_hard_limits_are_PRD_5_2s_and_each_default_is_within_its_limit()
    {
        Assert.Equal(TimeSpan.FromHours(1), SecurityLimits.HardSignedTokenLifetime);
        Assert.Equal(TimeSpan.FromDays(90), SecurityLimits.HardRefreshTokenAbsoluteLifetime);
        Assert.Equal(TimeSpan.FromDays(30), SecurityLimits.HardRefreshTokenInactivityLifetime);

        Assert.Equal(TimeSpan.FromMinutes(15), SecurityLimits.DefaultAccessTokenLifetime);
        Assert.Equal(TimeSpan.FromMinutes(15), SecurityLimits.DefaultIdentityTokenLifetime);
        Assert.Equal(TimeSpan.FromDays(30), SecurityLimits.RefreshTokenAbsoluteLifetime);
        Assert.Equal(TimeSpan.FromDays(7), SecurityLimits.RefreshTokenInactivityLifetime);

        Assert.True(SecurityLimits.DefaultAccessTokenLifetime <= SecurityLimits.HardSignedTokenLifetime);
        Assert.True(SecurityLimits.DefaultIdentityTokenLifetime <= SecurityLimits.HardSignedTokenLifetime);
        Assert.True(SecurityLimits.RefreshTokenAbsoluteLifetime <= SecurityLimits.HardRefreshTokenAbsoluteLifetime);
        Assert.True(SecurityLimits.RefreshTokenInactivityLifetime <= SecurityLimits.HardRefreshTokenInactivityLifetime);

        // A signing key retires once every token it signed has expired: the longest access or ID token is the hard limit.
        Assert.Equal(SecurityLimits.HardSignedTokenLifetime + TimeSpan.FromMinutes(15), SecurityLimits.SigningKeyRetirementDelay);
    }

    private static int Seconds(TimeSpan lifetime) => checked((int)lifetime.TotalSeconds);
}
