using System.Globalization;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;

namespace Gatekeep.Host.Admin;

/// <summary>
/// What the Admin API runs on: the <c>gk_admin</c> data source and the Admins commands. The data
/// source is made on first use, so building the OpenAPI document needs no database setting.
/// </summary>
internal sealed class AdminApiServices : IAsyncDisposable
{
    /// <summary>
    /// How long a claim waits for the bootstrap row lock, in milliseconds: 5 seconds unless set,
    /// at most a minute. A claim that waits longer is a 503.
    /// </summary>
    public const string LockTimeoutSetting = "Gatekeep:BootstrapLockTimeoutMs";

    /// <summary>
    /// Claims one process runs at once. Each holds a pooled connection while it waits for the row
    /// lock, so a flood beyond this is refused at once with 503 rather than draining the pool.
    /// </summary>
    public const int MaxConcurrentClaims = 4;

    private static readonly TimeSpan DefaultLockTimeout = TimeSpan.FromSeconds(5);

    private readonly Lazy<NpgsqlDataSource> _dataSource;

    // Bootstrap never reopens, so once it's seen complete the database needn't be asked again.
    // A restore of the database to before the claim needs Host.Admin restarted to be seen.
    private volatile bool _bootstrapComplete;

    public AdminApiServices(HostDatabases databases, IConfiguration configuration)
    {
        _dataSource = new(() => NpgsqlDataSource.Create(databases["Admin"]));
        Claimer = AdminsContract.CreateBootstrapClaimer(AuditContract.CreateAppender(), LockTimeout(configuration));
    }

    public IRateLimiter Limiter { get; } = AdminsContract.CreateAttemptLimiter();

    public IAdminSessions Sessions { get; } = AdminsContract.CreateSessions();

    public IBootstrapClaimer Claimer { get; }

    /// <summary>The claims in flight in this process: <see cref="MaxConcurrentClaims"/> slots.</summary>
    public SemaphoreSlim ClaimSlots { get; } = new(MaxConcurrentClaims, MaxConcurrentClaims);

    public Task<DeploymentScope> BeginAsync(CancellationToken cancellationToken) =>
        DeploymentScope.BeginAsync(_dataSource.Value, cancellationToken);

    /// <summary>Whether there is a bootstrap to claim: a token issued and bootstrap not complete.</summary>
    public async Task<bool> IsBootstrapOpenAsync(CancellationToken cancellationToken)
    {
        if (_bootstrapComplete)
        {
            return false;
        }

        BootstrapOpenness state;
        await using (var scope = await BeginAsync(cancellationToken))
        {
            state = await Claimer.ReadStateAsync(scope.CreateCommandContext(), cancellationToken);
            await scope.CommitAsync(cancellationToken);
        }

        if (state == BootstrapOpenness.Complete)
        {
            _bootstrapComplete = true;
        }

        return state == BootstrapOpenness.Open;
    }

    /// <summary>Records a claim this host committed.</summary>
    public void BootstrapCompleted() => _bootstrapComplete = true;

    public async ValueTask DisposeAsync()
    {
        ClaimSlots.Dispose();
        if (_dataSource.IsValueCreated)
        {
            await _dataSource.Value.DisposeAsync();
        }
    }

    /// <summary>Host.Admin's own settings that are malformed, by name, refused at startup with the host's others.</summary>
    public static IEnumerable<string> RefusedSettings(IConfiguration configuration) =>
        TryLockTimeout(configuration, out _) ? [] : [LockTimeoutSetting];

    private static TimeSpan LockTimeout(IConfiguration configuration) =>
        TryLockTimeout(configuration, out var timeout)
            ? timeout
            : throw new InvalidOperationException($"{LockTimeoutSetting} is a whole number of milliseconds from 1 to 60000.");

    private static bool TryLockTimeout(IConfiguration configuration, out TimeSpan timeout)
    {
        timeout = DefaultLockTimeout;
        var text = configuration[LockTimeoutSetting];
        if (text is null)
        {
            return true;
        }

        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var milliseconds) || milliseconds is < 1 or > 60_000)
        {
            return false;
        }

        timeout = TimeSpan.FromMilliseconds(milliseconds);
        return true;
    }
}
