using System.Collections.Concurrent;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;
using OpenIddict.Server;

namespace Gatekeep.Tests.Isolation.Protocol;

/// <summary>
/// Host.Hosted's public pipeline as <c>Program.cs</c> builds it (Tenant resolution, then the
/// Protocol module, then routing and the fixed 404), on a TestServer, with the real Protocol
/// registration over a migrated database as <c>gk_hosted</c> and the real OpenBao through the
/// <c>host-hosted</c> login, wrapped so a test can count or fail custody calls. Logs are captured
/// so a test can check that no key material or ciphertext reaches them.
/// </summary>
internal sealed class ProtocolHost : IAsyncDisposable
{
    private readonly WebApplication _app;

    private ProtocolHost(WebApplication app, ControlledCustody custody, CapturingLoggerProvider logs)
    {
        _app = app;
        Custody = custody;
        Logs = logs;
        Http = app.GetTestClient();
    }

    public HttpClient Http { get; }

    public ControlledCustody Custody { get; }

    public CapturingLoggerProvider Logs { get; }

    public IServiceProvider Services => _app.Services;

    /// <summary>The options OpenIddict built at startup: the ones no Tenant request may use.</summary>
    public OpenIddictServerOptions GlobalOptions =>
        _app.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

    public ITenantServerOptions TenantOptions => _app.Services.GetRequiredService<ITenantServerOptions>();

    public static async Task<ProtocolHost> StartAsync(
        string hostedConnection,
        OpenBaoFixture bao,
        TimeProvider? time = null)
    {
        var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Hosted));
        var logs = new CapturingLoggerProvider();

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Trace);
        builder.Logging.AddProvider(logs);

        if (time is not null)
        {
            builder.Services.AddSingleton(time);
        }

        builder.Services.AddSingleton<IKeyCustody>(custody);
        builder.Services.AddGatekeepProtocol(_ => hostedConnection);

        var app = builder.Build();
        app.UseTenantResolution(() => hostedConnection);
        app.UseGatekeepProtocol();
        app.UseRouting();
        app.MapFallback(TenancyContract.NotFoundAsync);

        await app.StartAsync(TestContext.Current.CancellationToken);
        return new ProtocolHost(app, custody, logs);
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await _app.StopAsync(CancellationToken.None);
        await _app.DisposeAsync();
        Custody.Dispose();
    }
}

/// <summary>A database with Tenants on their own hosts, and their keys provisioned the way Host.Worker does.</summary>
internal sealed class ProtocolDatabase(PostgresFixture postgres, string name)
{
    public string Name { get; } = name;

    public string Hosted => postgres.RoleConnection(TableRegistry.Hosted, Name);

    public string Superuser => postgres.SuperuserConnection(Name);

    public static async Task<ProtocolDatabase> CreateAsync(PostgresFixture postgres) =>
        new(postgres, await postgres.NewMigratedDatabaseAsync());

    /// <summary>An active Tenant on <paramref name="host"/>, with its stored issuer <c>https://{host}/</c> unless one is given.</summary>
    public async Task<ResolvedTenant> AddTenantAsync(string host, string? issuer = null)
    {
        var id = Guid.CreateVersion7();
        await TestTenants.InsertAsync(Superuser, id, host);
        if (issuer is not null)
        {
            await PostgresFixture.ExecuteAsync(
                Superuser,
                $"SET session_replication_role = replica; UPDATE tenant SET issuer = '{issuer}' WHERE id = '{id}'; SET session_replication_role = DEFAULT");
        }

        return new ResolvedTenant(id, issuer ?? $"https://{host}/", host, issuer ?? $"https://{host}/");
    }

    /// <summary>Runs the one Keys provisioning path as <c>gk_worker</c>, with the Worker's custody login.</summary>
    public async Task<bool> ProvisionAsync(OpenBaoFixture bao, Guid tenantId, IKeyCustody? custody = null)
    {
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, Name));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, TestContext.Current.CancellationToken);

        var created = await KeysContract.EnsureTenantKeysAsync(
            scope.CreateCommandContext(), custody ?? worker, AuditContract.CreateAppender(), tenantId, TestContext.Current.CancellationToken);
        await scope.CommitAsync(TestContext.Current.CancellationToken);
        return created;
    }

    /// <summary>
    /// Runs one Tenant's rotation as <c>gk_worker</c>, as the daily job does for each Tenant, with the
    /// production destroy job type and enqueuer, and commits it when anything changed.
    /// </summary>
    public async Task<bool> RotateAsync(OpenBaoFixture bao, Guid tenantId, IKeyCustody? custody = null)
    {
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, Name));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, TestContext.Current.CancellationToken);

        var changed = await KeysContract.RotateTenantKeysAsync(
            scope.CreateCommandContext(),
            custody ?? worker,
            AuditContract.CreateAppender(),
            Gatekeep.Modules.Operations.Contracts.OperationsContract.CreateEnqueuer(
                Gatekeep.Modules.Operations.Contracts.OperationsContract.ProductionRegistry, custody: null),
            Gatekeep.Modules.Operations.Contracts.OperationsContract.DestroySigningKey,
            tenantId,
            TestContext.Current.CancellationToken);
        if (changed)
        {
            await scope.CommitAsync(TestContext.Current.CancellationToken);
        }

        return changed;
    }

    public string Role(string role) => postgres.RoleConnection(role, Name);

    /// <summary>A production job runner over this database, with short retry timings.</summary>
    public Gatekeep.Modules.Operations.Contracts.IJobRunner Runner(IKeyCustody? custody, ILogger? logger = null) =>
        Gatekeep.Modules.Operations.Contracts.OperationsContract.CreateRunner(
            Gatekeep.Modules.Operations.Contracts.OperationsContract.ProductionRegistry,
            new Gatekeep.Modules.Operations.Contracts.JobDatabases(
                Role(TableRegistry.Dispatch), Role(TableRegistry.Worker), Role(TableRegistry.Sealer), Role(TableRegistry.Retention)),
            Gatekeep.Tests.Isolation.Jobs.JobDatabase.FastOptions,
            custody,
            logger);

    /// <summary>
    /// Runs <paramref name="sql"/> as the superuser with triggers off, so a test can age a row by
    /// moving its times back instead of waiting.
    /// </summary>
    public Task BackdateAsync(string sql) =>
        PostgresFixture.ExecuteAsync(Superuser, $"SET session_replication_role = replica; {sql}; SET session_replication_role = DEFAULT");

    public Task<T> ScalarAsync<T>(string sql) => PostgresFixture.ScalarAsync<T>(Superuser, sql);

    public Task ExecuteAsync(string sql) => PostgresFixture.ExecuteAsync(Superuser, sql);

    /// <summary>The Tenant's <c>signing_key</c> rows as <c>{transit_name}.v{version}</c>, the <c>kid</c> each would carry.</summary>
    public async Task<IReadOnlyList<string>> KeyIdsAsync(Guid tenantId, string purpose)
    {
        await using var connection = new NpgsqlConnection(Superuser);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = new NpgsqlCommand(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{tenantId}' AND purpose = '{purpose}' ORDER BY transit_name COLLATE \"C\"",
            connection);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);

        var ids = new List<string>();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            ids.Add(reader.GetString(0));
        }

        return ids;
    }
}

/// <summary>
/// A real custody login, wrapped: it counts each operation, and can fail or hang the operations a
/// test names, as an unreachable or stalled OpenBao would. Failures name no value.
/// </summary>
internal sealed class ControlledCustody(OpenBaoKeyCustody inner) : IKeyCustody, IDisposable
{
    private readonly ConcurrentDictionary<KeyOperation, int> _calls = new();
    private readonly ConcurrentQueue<string> _deleted = new();

    /// <summary>Operations that throw <see cref="KeyCustodyFailure.Unavailable"/> while listed.</summary>
    public HashSet<KeyOperation> Failing { get; } = [];

    /// <summary>Operations that wait until cancelled while listed.</summary>
    public HashSet<KeyOperation> Hanging { get; } = [];

    /// <summary>Called before each create, with the name: a test may throw from it to stop partway.</summary>
    public Action<KeyName>? BeforeCreate { get; set; }

    /// <summary>Awaited before each create, with the name: a test may hold a create there.</summary>
    public Func<KeyName, Task>? BeforeCreateAsync { get; set; }

    public int Calls(KeyOperation operation) => _calls.GetValueOrDefault(operation);

    public int TotalCalls => _calls.Values.Sum();

    public async Task<IReadOnlyList<KeyPublicVersion>> CreateKeyAsync(KeyName key, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Create, cancellationToken);
        BeforeCreate?.Invoke(key);
        if (BeforeCreateAsync is { } gate)
        {
            await gate(key);
        }

        return await inner.CreateKeyAsync(key, cancellationToken);
    }

    public async Task<KeySignature> SignAsync(KeyName key, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Sign, cancellationToken);
        return await inner.SignAsync(key, data, cancellationToken);
    }

    public async Task<bool> VerifyAsync(KeyName key, ReadOnlyMemory<byte> data, KeySignature signature, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Verify, cancellationToken);
        return await inner.VerifyAsync(key, data, signature, cancellationToken);
    }

    public async Task<KeyCiphertext> EncryptAsync(KeyName key, Guid? tenantId, Secret<byte[]> plaintext, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Encrypt, cancellationToken);
        return await inner.EncryptAsync(key, tenantId, plaintext, cancellationToken);
    }

    public async Task<Secret<byte[]>> DecryptAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Decrypt, cancellationToken);
        return await inner.DecryptAsync(key, tenantId, ciphertext, cancellationToken);
    }

    public async Task<KeyHmac> HmacAsync(KeyName key, Secret<byte[]> input, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Hmac, cancellationToken);
        return await inner.HmacAsync(key, input, cancellationToken);
    }

    public async Task<KeyCiphertext> CreateWrappedDataKeyAsync(KeyName key, Guid tenantId, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.WrapDataKey, cancellationToken);
        return await inner.CreateWrappedDataKeyAsync(key, tenantId, cancellationToken);
    }

    public async Task RotateAsync(KeyName key, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Rotate, cancellationToken);
        await inner.RotateAsync(key, cancellationToken);
    }

    public async Task<KeyCiphertext> RewrapAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Rewrap, cancellationToken);
        return await inner.RewrapAsync(key, tenantId, ciphertext, cancellationToken);
    }

    public async Task DeleteAsync(KeyName key, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.Delete, cancellationToken);
        await inner.DeleteAsync(key, cancellationToken);
        _deleted.Enqueue(key.Value);
    }

    public async Task<IReadOnlyList<KeyPublicVersion>> GetPublicKeysAsync(KeyName key, CancellationToken cancellationToken)
    {
        await EnterAsync(key, KeyOperation.ReadPublicKey, cancellationToken);
        return await inner.GetPublicKeysAsync(key, cancellationToken);
    }

    /// <summary>
    /// The real list, with each key in <see cref="Backdated"/> reported that much older: Transit's
    /// creation time can't be moved, and a test never waits a day.
    /// </summary>
    public async Task<IReadOnlyList<ListedKey>> ListRowKeysAsync(CancellationToken cancellationToken)
    {
        _calls.AddOrUpdate(KeyOperation.List, 1, (_, n) => n + 1);
        if (Failing.Contains(KeyOperation.List))
        {
            throw new KeyCustodyException("transit/keys", KeyOperation.List, KeyCustodyFailure.Unavailable);
        }

        var listed = await inner.ListRowKeysAsync(cancellationToken);
        return [.. listed.Select(k => Backdated.TryGetValue(k.Key.Value, out var by) ? k with { CreatedAt = k.CreatedAt - by } : k)];
    }

    /// <summary>Keys <see cref="ListRowKeysAsync"/> reports as older than they are, by name.</summary>
    public ConcurrentDictionary<string, TimeSpan> Backdated { get; } = new();

    /// <summary>Key names on which every operation throws <see cref="KeyCustodyFailure.Unavailable"/>.</summary>
    public ConcurrentDictionary<string, bool> FailingKeys { get; } = new();

    /// <summary>Operations that throw the given failure while listed, before reaching custody.</summary>
    public ConcurrentDictionary<KeyOperation, KeyCustodyFailure> FailingWith { get; } = new();

    /// <summary>Every key this wrapper deleted, in order.</summary>
    public IReadOnlyList<string> Deleted => [.. _deleted];

    public void Dispose() => inner.Dispose();

    private async Task EnterAsync(KeyName key, KeyOperation operation, CancellationToken cancellationToken)
    {
        _calls.AddOrUpdate(operation, 1, (_, n) => n + 1);

        if (FailingWith.TryGetValue(operation, out var failure))
        {
            throw new KeyCustodyException(key.Value, operation, failure);
        }

        if (Failing.Contains(operation) || FailingKeys.ContainsKey(key.Value))
        {
            throw new KeyCustodyException(key.Value, operation, KeyCustodyFailure.Unavailable);
        }

        if (Hanging.Contains(operation))
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }
}

/// <summary>A clock a test moves by hand, timers included, so no test waits on the wall clock.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly Lock _lock = new();
    private readonly List<ManualTimer> _timers = [];
    private long _ticks = TimeSpan.FromDays(1).Ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => Interlocked.Read(ref _ticks);

    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(GetTimestamp());

    /// <summary>Moves the clock on, then fires every one-shot timer now due, on this thread.</summary>
    public void Advance(TimeSpan by)
    {
        var now = Interlocked.Add(ref _ticks, by.Ticks);
        List<ManualTimer> due;
        lock (_lock)
        {
            due = [.. _timers.Where(t => t.DueAt <= now)];
            _timers.RemoveAll(due.Contains);
        }

        foreach (var timer in due)
        {
            timer.Fire();
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state, GetTimestamp() + dueTime.Ticks);
        if (dueTime <= TimeSpan.Zero)
        {
            timer.Fire();
        }
        else
        {
            lock (_lock)
            {
                _timers.Add(timer);
            }
        }

        return timer;
    }

    private void Remove(ManualTimer timer)
    {
        lock (_lock)
        {
            _timers.Remove(timer);
        }
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state, long dueAt) : ITimer
    {
        public long DueAt { get; } = dueAt;

        public void Fire() => callback(state);

        public bool Change(TimeSpan dueTime, TimeSpan period) => throw new NotSupportedException();

        public void Dispose() => owner.Remove(this);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>Every formatted log line and exception, from every category.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _lines = new();

    public IReadOnlyList<string> Lines => [.. _lines];

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            owner._lines.Enqueue($"{category}: {formatter(state, exception)} {exception}");
    }
}
