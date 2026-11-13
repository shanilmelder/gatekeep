using Gatekeep.Modules.Directory.Contracts;

namespace Gatekeep.Modules.Directory.Core;

/// <summary>
/// The limits of an Application's token lifetimes (Story 3.4, PRD §5.2): each 1 second to its
/// <see cref="Gatekeep.Kernel.Limits.SecurityLimits"/> hard limit. The table's CHECKs hold the same numbers.
/// </summary>
internal static class ApplicationLifetimeRules
{
    /// <summary>Every lifetime outside its limits, each naming its field, its reason and, when above, its maximum; empty when the save may go ahead.</summary>
    public static IReadOnlyList<ApplicationLifetimeProblem> Check(ApplicationLifetimes lifetimes)
    {
        ArgumentNullException.ThrowIfNull(lifetimes);
        var maximums = ApplicationLifetimes.Maximums;
        var problems = new List<ApplicationLifetimeProblem>();
        Field(problems, ApplicationLifetimeFields.AccessTokenLifetime, lifetimes.AccessTokenLifetime, maximums.AccessTokenLifetime);
        Field(problems, ApplicationLifetimeFields.IdTokenLifetime, lifetimes.IdTokenLifetime, maximums.IdTokenLifetime);
        Field(problems, ApplicationLifetimeFields.RefreshTokenAbsoluteLifetime, lifetimes.RefreshTokenAbsoluteLifetime, maximums.RefreshTokenAbsoluteLifetime);
        Field(problems, ApplicationLifetimeFields.RefreshTokenInactivityLifetime, lifetimes.RefreshTokenInactivityLifetime, maximums.RefreshTokenInactivityLifetime);
        return problems;
    }

    private static void Field(List<ApplicationLifetimeProblem> problems, string field, int value, int maximum)
    {
        if (value < ApplicationLifetimes.Minimum)
        {
            problems.Add(new ApplicationLifetimeProblem(field, ApplicationLifetimeReasons.BelowMinimum, null));
        }
        else if (value > maximum)
        {
            problems.Add(new ApplicationLifetimeProblem(field, ApplicationLifetimeReasons.AboveMaximum, maximum));
        }
    }
}
