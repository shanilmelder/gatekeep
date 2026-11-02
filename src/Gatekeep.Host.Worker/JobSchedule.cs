using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Host.Worker;

/// <summary>
/// The code-owned schedule (AD-15). Each entry is enqueued through the enqueuer and runs
/// through the runner like any other job.
/// </summary>
internal static class JobSchedule
{
    public static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);

    public static readonly IReadOnlyList<ScheduleEntry> Entries =
    [
        new(OperationsContract.PurgeJobs, TimeSpan.FromDays(1)),
    ];
}
