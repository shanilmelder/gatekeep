using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Host.Worker;

/// <summary>
/// The connections <c>Host.Worker</c> needs, one per role. The shared startup check refuses
/// a missing, empty or default one, naming only the setting.
/// </summary>
internal static class WorkerSettings
{
    public const string Dispatch = "Dispatch";
    public const string Worker = "Worker";
    public const string Sealer = "Sealer";
    public const string Retention = "Retention";

    public static readonly HostProfile Profile = new(
        "Host.Worker",
        [Dispatch, Worker, Sealer, Retention],
        HasPublicEndpoint: false,
        // The alert channel and the off-server bucket are required, though nothing calls them until
        // Story 11.1 and Story 7.2, so no Deployment runs without them (Story 1.30).
        UsesOffServer: true);

    public static JobDatabases Databases(HostDatabases databases) =>
        new(databases[Dispatch], databases[Worker], databases[Sealer], databases[Retention]);
}

internal static class WorkerJobs
{
    /// <summary>
    /// Registers the runner, the schedule and the audit seal loop. Each is built only when the host starts, so a
    /// host refused at startup never builds them. With key custody configured, the runner
    /// decrypts credential payloads through it. Without it, such a job fails with a fixed
    /// reason code.
    /// </summary>
    public static IServiceCollection AddGatekeepJobs(this IServiceCollection services)
    {
        services.AddSingleton(provider => OperationsContract.CreateRunner(
            OperationsContract.ProductionRegistry,
            WorkerSettings.Databases(provider.GetRequiredService<HostDatabases>()),
            options: null,
            custody: provider.GetService<IKeyCustody>(),
            provider.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Jobs")));

        services.AddSingleton(provider => OperationsContract.CreateScheduleRunner(
            OperationsContract.ProductionRegistry,
            JobSchedule.Entries,
            provider.GetRequiredService<HostDatabases>()[WorkerSettings.Worker],
            provider.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Jobs.Schedule")));

        services.AddSingleton(provider => OperationsContract.CreateSealLoop(
            provider.GetRequiredService<HostDatabases>()[WorkerSettings.Sealer],
            AuditSealService.Interval,
            provider.GetRequiredService<ILoggerFactory>().CreateLogger("Gatekeep.Audit.Sealer")));

        services.AddHostedService<JobRunnerService>();
        services.AddHostedService<JobScheduleService>();
        services.AddHostedService<AuditSealService>();
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

/// <summary>Seals every audit chain about once a second, as <c>gk_sealer</c> (AD-16).</summary>
internal sealed class AuditSealService(IAuditSealLoop loop) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => loop.RunAsync(stoppingToken);
}
