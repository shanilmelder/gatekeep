using System.Text;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Operations.Contracts;
using Microsoft.Extensions.Logging;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Jobs;

/// <summary>
/// One migrated database with Tenants A and B, whose guard is rendered from the test's own
/// registry as <c>gk_migrator</c>, as the production guard is rendered into the migration.
/// </summary>
internal sealed class JobDatabase
{
    public static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000000a");
    public static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000000b");

    /// <summary>Short timings, so retries can be watched. Backoff is checked from <c>run_after</c>.</summary>
    public static readonly JobRunnerOptions FastOptions = new()
    {
        Lease = TimeSpan.FromSeconds(30),
        BaseBackoff = TimeSpan.FromMilliseconds(400),
        MaxBackoff = TimeSpan.FromSeconds(30),
        NeverDeadMaxBackoff = TimeSpan.FromMilliseconds(800),
        PollInterval = TimeSpan.FromSeconds(1),
    };

    private readonly PostgresFixture _postgres;

    private JobDatabase(PostgresFixture postgres, string name)
    {
        _postgres = postgres;
        Name = name;
    }

    public string Name { get; }

    public static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    /// <param name="registry">Rendered into the database. Null keeps the migration's production guard.</param>
    public static async Task<JobDatabase> CreateAsync(PostgresFixture postgres, JobRegistry? registry)
    {
        var database = new JobDatabase(postgres, await postgres.NewMigratedDatabaseAsync());

        await database.SuperuserAsync(TestTenants.InsertSql(TenantA, TenantB));

        if (registry is not null)
        {
            await PostgresFixture.ExecuteAsync(
                postgres.RoleConnection(TableRegistry.Migrator, database.Name),
                OperationsContract.RenderGuard(registry));
        }

        return database;
    }

    public JobDatabases Databases => new(
        Connection(TableRegistry.Dispatch),
        Connection(TableRegistry.Worker),
        Connection(TableRegistry.Sealer),
        Connection(TableRegistry.Retention));

    public string Connection(string role) => _postgres.RoleConnection(role, Name);

    public NpgsqlDataSource Source(string role) => NpgsqlDataSource.Create(Connection(role));

    public IJobRunner Runner(
        JobRegistry registry,
        IKeyCustody? custody = null,
        ILogger? logger = null,
        JobRunnerOptions? options = null,
        OperationRegistry? operations = null) =>
        OperationsContract.CreateRunner(registry, Databases, options ?? FastOptions, custody, logger, operations);

    public Task SuperuserAsync(string sql) => PostgresFixture.ExecuteAsync(_postgres.SuperuserConnection(Name), sql);

    public Task<T> ScalarAsync<T>(string sql) => PostgresFixture.ScalarAsync<T>(_postgres.SuperuserConnection(Name), sql);

    /// <summary>Runs <paramref name="work"/> in a Tenant scope (or the Deployment's, for null) as <paramref name="role"/>, then ends it.</summary>
    public async Task<T> InScopeAsync<T>(string role, Guid? tenantId, Func<CommandContext, Task<T>> work)
    {
        await using var source = Source(role);
        await using CommandScope scope = tenantId is { } id
            ? await TenantScope.BeginAsync(source, id, Cancellation)
            : await DeploymentScope.BeginAsync(source, Cancellation);

        var result = await work(scope.CreateCommandContext());
        await scope.CommitAsync(Cancellation);
        return result;
    }

    public Task InScopeAsync(string role, Guid? tenantId, string sql) =>
        InScopeAsync(role, tenantId, async context =>
        {
            await using var command = context.CreateCommand();
            command.CommandText = sql;
            return await command.ExecuteNonQueryAsync(Cancellation);
        });

    /// <summary>The job row as JSON, read by the superuser.</summary>
    public Task<string> JobRowAsync(Guid id) => ScalarAsync<string>($"SELECT to_jsonb(j)::text FROM job j WHERE id = '{id}'");

    public Task<string> StatusAsync(Guid id) => ScalarAsync<string>($"SELECT status FROM job WHERE id = '{id}'");

    public Task<int> AttemptsAsync(Guid id) => ScalarAsync<int>($"SELECT attempts FROM job WHERE id = '{id}'");

    /// <summary>Seconds from now until the job is due, read straight after a retry.</summary>
    public Task<double> SecondsUntilDueAsync(Guid id) =>
        ScalarAsync<double>($"SELECT extract(epoch FROM run_after - clock_timestamp())::float8 FROM job WHERE id = '{id}'");

    /// <summary>Makes a retried job due now, so a test needn't wait out its backoff.</summary>
    public Task MakeDueAsync(Guid id) => SuperuserAsync($"UPDATE job SET run_after = now() WHERE id = '{id}'");
}

/// <summary>A stand-in for OpenBao Transit. It isn't encryption: it proves only who decrypts, how often, and for whom.</summary>
internal sealed class FakeKeyCustody : IKeyCustody
{
    private const string Prefix = "vault:v1:";

    public int Encrypts { get; private set; }

    /// <summary>Characters added to each ciphertext, to make one longer than the schema allows.</summary>
    public int Padding { get; init; }

    public int Decrypts { get; private set; }

    public List<string> KeysUsed { get; } = [];

    public Task<KeyCiphertext> EncryptAsync(KeyName key, Guid? tenantId, Secret<byte[]> plaintext, CancellationToken cancellationToken)
    {
        Encrypts++;
        KeysUsed.Add(key.Value);
        var bound = plaintext.Use(bytes => Convert.ToBase64String([.. Encoding.UTF8.GetBytes($"{tenantId}|"), .. bytes]));
        return Task.FromResult(new KeyCiphertext(Prefix + bound + new string('A', Padding)));
    }

    public Task<Secret<byte[]>> DecryptAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken)
    {
        Decrypts++;
        KeysUsed.Add(key.Value);
        var bytes = Convert.FromBase64String(ciphertext.Value[Prefix.Length..]);
        var binding = Encoding.UTF8.GetBytes($"{tenantId}|");

        if (!bytes.AsSpan().StartsWith(binding))
        {
            throw new KeyCustodyException(key.Value, KeyOperation.Decrypt, KeyCustodyFailure.Rejected);
        }

        return Task.FromResult(new Secret<byte[]>(bytes[binding.Length..]));
    }

    public Task<IReadOnlyList<KeyPublicVersion>> CreateKeyAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeySignature> SignAsync(KeyName key, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<bool> VerifyAsync(KeyName key, ReadOnlyMemory<byte> data, KeySignature signature, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<KeyHmac> HmacAsync(KeyName key, Secret<byte[]> input, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> CreateWrappedDataKeyAsync(KeyName key, Guid tenantId, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task RotateAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<KeyCiphertext> RewrapAsync(KeyName key, Guid? tenantId, KeyCiphertext ciphertext, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task DeleteAsync(KeyName key, CancellationToken cancellationToken) => throw new NotSupportedException();

    public Task<IReadOnlyList<KeyPublicVersion>> GetPublicKeysAsync(KeyName key, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<ListedKey>> ListRowKeysAsync(CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}

/// <summary>Records every formatted line and every exception the runner hands its logger.</summary>
internal sealed class RecordingLogger : ILogger
{
    private readonly Lock _lock = new();

    public List<string> Lines { get; } = [];

    public List<Exception> Exceptions { get; } = [];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (_lock)
        {
            Lines.Add(formatter(state, exception));
            if (exception is not null)
            {
                Exceptions.Add(exception);
            }
        }
    }
}
