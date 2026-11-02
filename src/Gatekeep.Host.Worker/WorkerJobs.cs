using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Host.Worker;

/// <summary>
/// The connection settings <c>Host.Worker</c> needs. Story 1.10 supplies them. A missing one
/// refuses startup, naming only the setting.
/// </summary>
internal static class WorkerSettings
{
    public const string Dispatch = "ConnectionStrings:Dispatch";
    public const string Worker = "ConnectionStrings:Worker";
    public const string Sealer = "ConnectionStrings:Sealer";
    public const string Retention = "ConnectionStrings:Retention";

    public static readonly IReadOnlyList<string> All = [Dispatch, Worker, Sealer, Retention];

    public static IReadOnlyList<string> Missing(IConfiguration configuration) =>
        [.. All.Where(name => string.IsNullOrWhiteSpace(configuration[name]))];

    public static JobDatabases Databases(IConfiguration configuration) =>
        new(configuration[Dispatch]!, configuration[Worker]!, configuration[Sealer]!, configuration[Retention]!);
}

internal static class WorkerJobs
{
    /// <summary>
    /// Registers the runner and the schedule. Both are built only when the host starts, so a
    /// host refused for missing settings never builds them. No key custody is wired here
    /// (Story 1.10), so a job carrying a credential fails with a fixed reason code.
    /// </summary>
    public static IServiceCollection AddGatekeepJobs(this IServiceCollection services)
    {
        services.AddSingleton(provider => OperationsContract.CreateRunner(
            OperationsContract.ProductionRegistry,
            WorkerSettings.Databases(provider.GetRequiredService<IConfiguration>()),
            options: null,
            custody: null,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Jobs")));

        services.AddSingleton(provider => OperationsContract.CreateScheduleRunner(
            OperationsContract.ProductionRegistry,
            JobSchedule.Entries,
            provider.GetRequiredService<IConfiguration>()[WorkerSettings.Worker]!,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Jobs.Schedule")));

        services.AddHostedService<JobRunnerService>();
        services.AddHostedService<JobScheduleService>();
        return services;
    }
}

internal sealed class JobRunnerService(IJobRunner runner) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => runner.RunAsync(stoppingToken);
}

internal sealed class JobScheduleService(IJobScheduleRunner schedule) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        schedule.RunAsync(JobSchedule.TickInterval, stoppingToken);
}
