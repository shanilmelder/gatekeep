using Gatekeep.Kernel.Jobs;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>The production job registry (AD-15). The migration holds the guard rendered from it.</summary>
internal static class ProductionJobs
{
    public static readonly TimeSpan PurgeAge = TimeSpan.FromDays(30);

    public static readonly JobType Purge = new("operations.job.purge");

    public static readonly JobRegistry Registry = new(
    [
        new JobDefinition(
            Purge,
            JobScope.DeploymentWide,
            enqueuingRoles: [JobRole.Worker],
            runAs: JobRole.Worker,
            maxAttempts: 5,
            handler: PurgeAsync,
            review: new JobReview(
                "Story 1.8 build review",
                new DateOnly(2026, 11, 2),
                "Touches only the control table job, deleting done rows finished more than 30 days ago. "
                + "It takes no parameter, and no Tenant table is read or written.")),
    ]);

    private const string DeleteDone =
        """
        DELETE FROM job
        WHERE status = 'done' AND finished_at < now() - make_interval(secs => @age_seconds)
        """;

    private static async Task PurgeAsync(JobRun run, CancellationToken cancellationToken)
    {
        await using var command = run.Context.CreateCommand();
        command.CommandText = DeleteDone;
        Sql.Add(command, "age_seconds", PurgeAge.TotalSeconds);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
