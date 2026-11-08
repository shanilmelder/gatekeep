using System.Globalization;
using Gatekeep.Adapters.Fido2;
using Gatekeep.Adapters.Hosting;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
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
    /// The Tenant zone every Tenant Subdomain sits under (Story 1.27, AD-6), such as
    /// <c>gatekeep.example.com</c>: required, lower-case LDH labels separated by dots, at least two,
    /// at most 200 characters, and never the Admin hostname or above it.
    /// </summary>
    public const string TenantZoneSetting = "Gatekeep:TenantZone";

    /// <summary>The HTTPS port Tenant hosts are reached on, which a new Tenant's issuer names when it isn't 443: optional, 1 to 65535.</summary>
    public const string TenantHttpsPortSetting = "Gatekeep:TenantHttpsPort";

    /// <summary>
    /// Claims one process runs at once. Each holds a pooled connection while it waits for the row
    /// lock, so a flood beyond this is refused at once with 503 rather than draining the pool.
    /// </summary>
    public const int MaxConcurrentClaims = 4;

    private static readonly TimeSpan DefaultLockTimeout = TimeSpan.FromSeconds(5);

    private readonly Lazy<NpgsqlDataSource> _dataSource;

    private readonly Lazy<ITenantManagement> _tenants;

    // Bootstrap never reopens, so once it's seen complete the database needn't be asked again.
    // A restore of the database to before the claim needs Host.Admin restarted to be seen.
    private volatile bool _bootstrapComplete;

    public AdminApiServices(HostDatabases databases, IConfiguration configuration)
    {
        _dataSource = new(() => NpgsqlDataSource.Create(databases["Admin"]));
        Claimer = AdminsContract.CreateBootstrapClaimer(AuditContract.CreateAppender(), LockTimeout(configuration));
        Registration = AdminsContract.CreateCredentialRegistration(AuditContract.CreateAppender(), Fido2WebAuthn.Create());
        Sessions = AdminsContract.CreateSessions(AuditContract.CreateAppender());
        SignIn = AdminsContract.CreateSignIn(AuditContract.CreateAppender(), Fido2WebAuthn.Create());
        Authorization = AdminsContract.CreateAuthorization(AuditContract.CreateAppender());
        FreshAssertions = AdminsContract.CreateFreshAssertions(AuditContract.CreateAppender(), Fido2WebAuthn.Create());
        Credentials = AdminsContract.CreateCredentials(AuditContract.CreateAppender());
        Enrolments = AdminsContract.CreateEnrolments(AuditContract.CreateAppender());

        // Built on first use: the OpenAPI document build has no Tenant zone.
        _tenants = new(() => ManagementContract.CreateTenants(
            AuditContract.CreateAppender(),
            TryAddressing(configuration, out var addressing)
                ? addressing
                : throw new InvalidOperationException($"{TenantZoneSetting} or {TenantHttpsPortSetting} is malformed.")));
    }

    /// <summary>Creating and listing Tenants (Story 1.27), under the configured Tenant zone and HTTPS port.</summary>
    public ITenantManagement Tenants => _tenants.Value;

    public IRateLimiter Limiter { get; } = AdminsContract.CreateAttemptLimiter();

    public IAdminSessions Sessions { get; }

    public IBootstrapClaimer Claimer { get; }

    /// <summary>Admin WebAuthn credential registration (Story 1.22), verified by the stateless Fido2 adapter.</summary>
    public IAdminCredentialRegistration Registration { get; }

    /// <summary>Admin sign-in with WebAuthn (Story 1.23), verified by the same stateless adapter.</summary>
    public IAdminSignIn SignIn { get; }

    /// <summary>The capability authorizer (Story 1.24): every capability route is decided by it, reading Tenant Roles on each request.</summary>
    public IAdminAuthorization Authorization { get; }

    /// <summary>Fresh WebAuthn assertions for sensitive actions (Story 1.26): the ceremony and the grants the checks use up.</summary>
    public IAdminFreshAssertions FreshAssertions { get; }

    /// <summary>A Tenant's Log search (Story 7.4), run in the path Tenant's scope only.</summary>
    public ITenantLogSearch LogSearch { get; } = AuditContract.CreateLogSearch();

    /// <summary>Your credentials (Story 1.26): the Admin's own list, and removal under the floor.</summary>
    public IAdminCredentials Credentials { get; }

    /// <summary>
    /// <c>recover-admin</c> enrolment redemption (Story 1.32). This host only redeems: the issuer
    /// is the Cli's alone, and no route here issues one.
    /// </summary>
    public IAdminEnrolments Enrolments { get; }

    /// <summary>
    /// Admin Recovery Codes (Story 1.26), over this host's key custody, which computes the
    /// Deployment HMAC and decrypts nothing. Made per call: custody is resolved from the request.
    /// </summary>
    public IAdminRecoveryCodes RecoveryCodes(IKeyCustody custody) =>
        AdminsContract.CreateRecoveryCodes(AuditContract.CreateAppender(), custody);

    /// <summary>The claims in flight in this process: <see cref="MaxConcurrentClaims"/> slots.</summary>
    public SemaphoreSlim ClaimSlots { get; } = new(MaxConcurrentClaims, MaxConcurrentClaims);

    public Task<DeploymentScope> BeginAsync(CancellationToken cancellationToken) =>
        DeploymentScope.BeginAsync(_dataSource.Value, cancellationToken);

    /// <summary>
    /// The <c>gk_admin</c> data source, for a Tenant scope on the path Tenant only (Story 1.28):
    /// <c>TenantScope.BeginAsync(services.Source, AdminRequestChecks.PathTenant(context), …)</c>.
    /// The one exception is <see cref="CrossTenantRejection"/>, which writes a refusal to the
    /// refused Tenant's own Log (Story 7.4).
    /// </summary>
    public NpgsqlDataSource Source => _dataSource.Value;

    /// <summary>Whether there is a bootstrap to claim: a token issued and bootstrap not complete.</summary>
    public async Task<bool> IsBootstrapOpenAsync(CancellationToken cancellationToken) =>
        !_bootstrapComplete && await ReadBootstrapAsync(cancellationToken) == BootstrapOpenness.Open;

    /// <summary>Whether bootstrap is complete, so there is an Admin who could sign in (Story 1.23).</summary>
    public async Task<bool> IsBootstrapCompleteAsync(CancellationToken cancellationToken) =>
        _bootstrapComplete || await ReadBootstrapAsync(cancellationToken) == BootstrapOpenness.Complete;

    private async Task<BootstrapOpenness> ReadBootstrapAsync(CancellationToken cancellationToken)
    {
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

        return state;
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
    public static IEnumerable<string> RefusedSettings(IConfiguration configuration)
    {
        var refused = new List<string>();
        if (!TryLockTimeout(configuration, out _))
        {
            refused.Add(LockTimeoutSetting);
        }

        if (!TryHttpsPort(configuration, out _))
        {
            refused.Add(TenantHttpsPortSetting);
        }

        var zone = configuration[TenantZoneSetting];
        if (!TenantAddressing.IsValidZone(zone)
            || (OriginHost(configuration) is { } admin && TenantAddressing.ZoneCovers(zone!, admin)))
        {
            // Malformed, or the Admin hostname is the zone or under it (AD-6).
            refused.Add(TenantZoneSetting);
        }

        return refused;
    }

    private static bool TryAddressing(IConfiguration configuration, out TenantAddressing addressing)
    {
        addressing = null!;
        var zone = configuration[TenantZoneSetting];
        if (!TenantAddressing.IsValidZone(zone) || !TryHttpsPort(configuration, out var port))
        {
            return false;
        }

        addressing = new TenantAddressing(zone!, port);
        return true;
    }

    private static bool TryHttpsPort(IConfiguration configuration, out int port)
    {
        port = TenantAddressing.DefaultHttpsPort;
        var text = configuration[TenantHttpsPortSetting];
        if (text is null)
        {
            return true;
        }

        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
    }

    /// <summary>The Admin origin's host, when it parses: the shared startup check refuses it otherwise.</summary>
    private static string? OriginHost(IConfiguration configuration) =>
        Uri.TryCreate(configuration[HostSettingNames.PublicOrigin]?.Trim(), UriKind.Absolute, out var origin) ? origin.IdnHost : null;

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
