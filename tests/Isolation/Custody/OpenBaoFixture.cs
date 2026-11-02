using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Volumes;
using Gatekeep.Adapters.OpenBao;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation.Custody;

[CollectionDefinition(Name)]
public sealed class OpenBaoCollection : ICollectionFixture<OpenBaoFixture>
{
    public const string Name = "OpenBao";
}

/// <summary>
/// One OpenBao 2.7.2 container running the <c>deploy/openbao</c> config, Master Key script
/// and setup script, as root, the way the host will. Only a test listener is added, because
/// a Windows host can't reach the container's unix socket. Postgres tests don't wait on it.
/// </summary>
public class OpenBaoFixture : IAsyncLifetime
{
    public const string Image = "openbao/openbao:2.7.2";
    public const string Socket = "unix:///run/openbao/openbao.sock";
    public const string KeyDirectory = "/srv/gatekeep/keys";
    public const string KeyFile = KeyDirectory + "/master-key";
    public const string EscrowFile = "/root/openbao-init.json";
    public const string AppRoleDirectory = "/etc/gatekeep/openbao";
    public const string AuditLog = "/var/log/openbao/audit.log";

    public const string Hosted = "host-hosted";
    public const string Admin = "host-admin";
    public const string Worker = "host-worker";
    public const string Cli = "cli";

    public static readonly IReadOnlyList<string> Roles = [Hosted, Admin, Worker, Cli];

    private const int TestPort = 8210;

    private readonly string _credentials = Path.Combine(Path.GetTempPath(), "gatekeep-approle-" + Guid.NewGuid().ToString("N"));

    private IContainer? _container;

    public IContainer Container => _container ?? throw new InvalidOperationException("Not started.");

    public Uri Address { get; private set; } = null!;

    public ExecResult Setup { get; private set; }

    /// <summary>A Tenant whose keys exist after start, with one Signing and one Management key.</summary>
    public Guid TenantA { get; } = Guid.CreateVersion7();

    public Guid TenantB { get; } = Guid.CreateVersion7();

    public KeyName SigningA { get; private set; } = null!;

    public KeyName ManagementA { get; private set; } = null!;

    protected virtual string TokenTtl => "15m";

    protected virtual string TokenMaxTtl => "1h";

    public async ValueTask InitializeAsync()
    {
        _container = Build(generateKey: true)
            .WithPortBinding(TestPort, assignRandomHostPort: true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilMessageIsLogged("OpenBao server started"))
            .Build();
        await _container.StartAsync();

        Address = new UriBuilder(Uri.UriSchemeHttp, _container.Hostname, _container.GetMappedPublicPort(TestPort)).Uri;

        Setup = await ExecAsync(
            "env",
            $"GATEKEEP_TOKEN_TTL={TokenTtl}",
            $"GATEKEEP_TOKEN_MAX_TTL={TokenMaxTtl}",
            "sh",
            "/opt/gatekeep/openbao/setup.sh");
        if (Setup.ExitCode != 0)
        {
            throw new InvalidOperationException($"setup.sh failed: {Setup.Stderr}");
        }

        Directory.CreateDirectory(_credentials);
        foreach (var role in Roles)
        {
            Directory.CreateDirectory(Path.Combine(_credentials, role));
            foreach (var file in new[] { "role-id", "secret-id" })
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(_credentials, role, file),
                    await _container.ReadFileAsync($"{AppRoleDirectory}/{role}/{file}"));
            }
        }

        await SeedKeysAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }

        if (Directory.Exists(_credentials))
        {
            Directory.Delete(_credentials, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    public OpenBaoOptions Options(string role) => new()
    {
        Address = Address,
        RoleIdFile = Path.Combine(_credentials, role, "role-id"),
        SecretIdFile = Path.Combine(_credentials, role, "secret-id"),
    };

    /// <summary>The adapter as <paramref name="role"/> would use it, optionally with a wrapped handler or clock.</summary>
    public OpenBaoKeyCustody Custody(
        string role,
        TimeProvider? time = null,
        Func<HttpMessageHandler, HttpMessageHandler>? wrap = null)
    {
        var options = Options(role);
        HttpMessageHandler handler = OpenBaoKeyCustody.CreateHandler(options);
        return new OpenBaoKeyCustody(wrap is null ? handler : wrap(handler), options, time ?? TimeProvider.System);
    }

    /// <summary>A raw token for <paramref name="role"/>, for requests the adapter never makes.</summary>
    public async Task<string> LoginAsync(string role)
    {
        using var http = new HttpClient { BaseAddress = Address };
        using var response = await http.PostAsJsonAsync("v1/auth/approle/login", new
        {
            role_id = await File.ReadAllTextAsync(Path.Combine(_credentials, role, "role-id")),
            secret_id = await File.ReadAllTextAsync(Path.Combine(_credentials, role, "secret-id")),
        });
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("auth").GetProperty("client_token").GetString()!;
    }

    public async Task<string> ReadTextAsync(string path) =>
        Encoding.UTF8.GetString(await Container.ReadFileAsync(path));

    public Task<ExecResult> ExecAsync(params string[] command) => Container.ExecAsync(command);

    /// <summary>Docker can't copy a file out of a tmpfs, so the key file is read through exec.</summary>
    public async Task<byte[]> ReadKeyFileAsync()
    {
        var read = await ExecAsync("base64", "-w", "0", KeyFile);
        return read.ExitCode == 0
            ? Convert.FromBase64String(read.Stdout.Trim())
            : throw new InvalidOperationException("Couldn't read the key file.");
    }

    /// <summary>
    /// The container as root, with the deploy files where the host keeps them. Line endings
    /// are normalized because a Windows checkout may hold CRLF, which sh can't run. The key
    /// directory is a mount, as the key volume is: a tmpfs, or <paramref name="keyVolume"/>
    /// when the key must survive a restart.
    /// </summary>
    public static ContainerBuilder Build(bool generateKey, IVolume? keyVolume = null)
    {
        var root = RepositoryRoot();
        var deploy = Path.Combine(root, "deploy", "openbao");
        var custody = Path.Combine(root, "tests", "Isolation", "Custody");

        var builder = new ContainerBuilder(Image);
        builder = keyVolume is null
            ? builder.WithTmpfsMount(KeyDirectory)
            : builder.WithVolumeMount(keyVolume, KeyDirectory);

        builder = builder
            .WithCreateParameterModifier(parameters => parameters.User = "root")
            .WithEntrypoint("sh")
            .WithCommand("/opt/gatekeep/test/start-openbao.sh")
            .WithEnvironment("GATEKEEP_TEST_GENERATE_KEY", generateKey ? "1" : "0")
            .WithResourceMapping(Lf(Path.Combine(deploy, "openbao.hcl")), "/etc/openbao/openbao.hcl")
            .WithResourceMapping(Lf(Path.Combine(custody, "test-listener.hcl")), "/etc/openbao/test-listener.hcl")
            .WithResourceMapping(Lf(Path.Combine(custody, "start-openbao.sh")), "/opt/gatekeep/test/start-openbao.sh")
            .WithResourceMapping(Lf(Path.Combine(deploy, "setup.sh")), "/opt/gatekeep/openbao/setup.sh")
            .WithResourceMapping(Lf(Path.Combine(deploy, "generate-master-key.sh")), "/opt/gatekeep/openbao/generate-master-key.sh");

        foreach (var policy in Directory.EnumerateFiles(Path.Combine(deploy, "policies"), "*.hcl"))
        {
            builder = builder.WithResourceMapping(Lf(policy), $"/opt/gatekeep/openbao/policies/{Path.GetFileName(policy)}");
        }

        return builder;
    }

    public static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Gatekeep.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("No Gatekeep.slnx above the test output.");
    }

    private static byte[] Lf(string path) =>
        Encoding.UTF8.GetBytes(File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal));

    /// <summary>Tenant keys made as <c>Host.Worker</c> would at Tenant creation.</summary>
    private async Task SeedKeysAsync()
    {
        using var worker = Custody(Worker);
        var cancellation = CancellationToken.None;

        SigningA = KeyName.Signing(TenantA, Guid.CreateVersion7());
        ManagementA = KeyName.Management(TenantA, Guid.CreateVersion7());
        await worker.CreateKeyAsync(SigningA, cancellation);
        await worker.CreateKeyAsync(ManagementA, cancellation);

        foreach (var keyClass in Enum.GetValues<TenantKeyClass>())
        {
            await worker.CreateKeyAsync(KeyName.ForTenant(keyClass, TenantA), cancellation);
        }

        await worker.CreateKeyAsync(KeyName.ForTenant(TenantKeyClass.Social, TenantB), cancellation);
    }
}

/// <summary>The same setup with three-second tokens, so a token can expire between calls.</summary>
public sealed class ShortTokenOpenBaoFixture : OpenBaoFixture
{
    protected override string TokenTtl => "3s";

    protected override string TokenMaxTtl => "3s";
}
