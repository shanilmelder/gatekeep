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
    public const string KeyDirectory = "/secrets";
    public const string KeyFile = KeyDirectory + "/master-key";
    public const string KeyIdFile = KeyDirectory + "/master-key-id";
    public const string PreviousDirectory = KeyDirectory + "/previous";
    public const string RenderedConfig = "/tmp/openbao.hcl";
    public const string RotationModeFlag = "/opt/gatekeep/test/rotation-mode";
    public const string EscrowFile = KeyDirectory + "/openbao-init.json";
    public const string AppRoleDirectory = KeyDirectory + "/approle";
    public const string MasterKeySecret = "/run/secrets/master_key";
    public const string AuditLog = "/var/log/openbao/audit.log";

    public const string Hosted = "host-hosted";
    public const string Admin = "host-admin";
    public const string Worker = "host-worker";
    public const string Cli = "cli";

    public static readonly IReadOnlyList<string> Roles = [Hosted, Admin, Worker, Cli];

    private const int TestPort = 8210;

    private readonly string _credentials = Path.Combine(Path.GetTempPath(), "gatekeep-approle-" + Guid.NewGuid().ToString("N"));

    private IContainer? _container;

    private IVolume? _keyVolume;

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

    /// <summary>The setup script as the container runs it. A variant may leave steps out.</summary>
    protected virtual string SetupScript(string script) => script;

    /// <summary>
    /// The key directory as a volume, not a tmpfs, so the Master Key survives <see cref="RestartAsync"/>
    /// as the bind-mounted secrets directory would.
    /// </summary>
    protected virtual bool KeysSurviveRestart => false;

    public async ValueTask InitializeAsync()
    {
        if (KeysSurviveRestart)
        {
            _keyVolume = new VolumeBuilder().WithName("gatekeep-keys-" + Guid.NewGuid().ToString("N")).Build();
            await _keyVolume.CreateAsync();
        }

        _container = Build(generateKey: true, _keyVolume, SetupScript)
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
                    await ReadBytesAsync(_container, $"{AppRoleDirectory}/{role}/{file}"));
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

        if (_keyVolume is not null)
        {
            await _keyVolume.DisposeAsync();
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

    /// <summary>
    /// The adapter as <paramref name="role"/> would use it, following <see cref="Address"/> across
    /// <see cref="RestartAsync"/>, which can move the mapped port. Its token is the one it logged in
    /// for first, as a running host's would be.
    /// </summary>
    public OpenBaoKeyCustody FollowingCustody(string role) => Custody(role, wrap: inner => new FollowAddress(this, inner));

    /// <summary>
    /// Stops and starts OpenBao, as Compose recreating the service would, in rotation mode or not
    /// (the stand-in start script mounts <see cref="PreviousDirectory"/> only in rotation mode).
    /// It doesn't wait for an unseal, which may rightly never come.
    /// </summary>
    public async Task RestartAsync(bool rotationMode)
    {
        var flag = await ExecAsync(rotationMode ? ["touch", RotationModeFlag] : ["rm", "-f", RotationModeFlag]);
        if (flag.ExitCode != 0)
        {
            throw new InvalidOperationException("Couldn't set the rotation mode flag.");
        }

        await Container.StopAsync();
        await Container.StartAsync();
        Address = new UriBuilder(Uri.UriSchemeHttp, Container.Hostname, Container.GetMappedPublicPort(TestPort)).Uri;
    }

    /// <summary>The <c>bao status</c> JSON over the socket, or null while it doesn't answer.</summary>
    public async Task<JsonElement?> StatusAsync()
    {
        var status = await ExecAsync("bao", "status", "-format=json", $"-address={Socket}");
        if (status.Stdout.Trim().Length == 0)
        {
            return null;
        }

        using var json = JsonDocument.Parse(status.Stdout);
        return json.RootElement.Clone();
    }

    /// <summary>True once OpenBao reports unsealed within <paramref name="deadline"/>.</summary>
    public async Task<bool> UnsealsWithinAsync(TimeSpan deadline)
    {
        var until = DateTime.UtcNow + deadline;
        while (DateTime.UtcNow < until)
        {
            if (await StatusAsync() is { } status && !status.GetProperty("sealed").GetBoolean())
            {
                return true;
            }

            await Task.Delay(500);
        }

        return false;
    }

    public async Task<string> ReadTextAsync(string path) =>
        Encoding.UTF8.GetString(await ReadBytesAsync(Container, path));

    public Task<ExecResult> ExecAsync(params string[] command) => Container.ExecAsync(command);

    public Task<byte[]> ReadKeyFileAsync() => ReadBytesAsync(Container, KeyFile);

    /// <summary>
    /// Docker can't copy a file out of a tmpfs, and the secrets directory is one, so files
    /// are read through exec.
    /// </summary>
    public static async Task<byte[]> ReadBytesAsync(IContainer container, string path)
    {
        var read = await container.ExecAsync(["base64", "-w", "0", path]);
        return read.ExitCode == 0
            ? Convert.FromBase64String(read.Stdout.Trim())
            : throw new InvalidOperationException($"Couldn't read {path}.");
    }

    /// <summary>
    /// The container as root, with the deploy files where the OpenBao image keeps them. Line endings
    /// are normalized because a Windows checkout may hold CRLF, which sh can't run. The key
    /// directory is a mount, as the bind-mounted secrets directory is: a tmpfs, or <paramref name="keyVolume"/>
    /// when the key must survive a restart.
    /// </summary>
    public static ContainerBuilder Build(bool generateKey, IVolume? keyVolume = null, Func<string, string>? setup = null)
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
            .WithResourceMapping(Lf(Path.Combine(deploy, "setup.sh"), setup), "/opt/gatekeep/openbao/setup.sh");

        foreach (var script in new[] { "start-openbao.sh", "generate-master-key.sh", "rotate-master-key.sh", "rotate-root-key.sh" })
        {
            builder = builder.WithResourceMapping(Lf(Path.Combine(deploy, script)), $"/opt/gatekeep/openbao/{script}");
        }

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

    private static byte[] Lf(string path, Func<string, string>? transform = null) =>
        Encoding.UTF8.GetBytes((transform ?? (s => s))(File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal)));

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

/// <summary>
/// Setup without its four Deployment key lines, so <c>gatekeep init</c> is the one that makes
/// them (Story 1.19). Fails at start if the lines it removes are no longer there.
/// </summary>
public sealed class NoDeploymentKeysOpenBaoFixture : OpenBaoFixture
{
    protected override string SetupScript(string script)
    {
        var lines = script.Split('\n');
        var kept = lines.Where(l => !l.StartsWith("bao write transit/keys/dep-", StringComparison.Ordinal)).ToArray();
        if (lines.Length - kept.Length != 4)
        {
            throw new InvalidOperationException("setup.sh no longer creates the four Deployment keys on four lines.");
        }

        return string.Join('\n', kept);
    }
}

/// <summary>
/// Story 12.7: the same setup with its key directory on a volume, so a Master Key rotation can
/// restart OpenBao and keep master/ as the secrets directory would.
/// </summary>
public sealed class RotationOpenBaoFixture : OpenBaoFixture
{
    protected override bool KeysSurviveRestart => true;
}

/// <summary>Sends each request to the fixture's current address, which a restart can change.</summary>
internal sealed class FollowAddress(OpenBaoFixture bao, HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is { } uri)
        {
            request.RequestUri = new UriBuilder(uri) { Host = bao.Address.Host, Port = bao.Address.Port }.Uri;
        }

        return base.SendAsync(request, cancellationToken);
    }
}
