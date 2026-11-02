using System.Net;
using System.Net.Sockets;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Secrets;
using Xunit;

namespace Gatekeep.Tests.Isolation.Hosting;

/// <summary>
/// Story 1.10: each real host refuses a missing or default setting naming only the setting,
/// reads passwords from Compose-style secret files, needs key custody, and answers
/// <c>/healthz</c> on its private port only, with 503 naming the failed check.
/// </summary>
public sealed class HostStartupTests(PostgresFixture postgres) : IDisposable
{
    private const string Canary = "canary-startup-value-5f3a";
    private const string HealthEndpoint = "/healthz";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static readonly string[] CustodySettings = ["Custody:SocketPath", "Custody:RoleIdFile", "Custody:SecretIdFile"];

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-host-").FullName;
    private readonly List<FakeOpenBaoSocket> _sockets = [];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string> Hosts => ["Hosted", "Admin", "Worker"];

    [Theory]
    [MemberData(nameof(Hosts))]
    public async Task Host_with_no_settings_refuses_naming_each_missing_setting(string host)
    {
        using var process = HostProcess.Start(host, $"--Gatekeep:HealthPort={HostProcess.FreePort()}");
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains($"Host.{host} refuses to start", output);
        foreach (var (name, _) in Databases(host))
        {
            Assert.Contains($"ConnectionStrings:{name}", output);
        }

        // Custody isn't optional: every host uses it (AD-10).
        foreach (var setting in CustodySettings)
        {
            Assert.Contains(setting, output);
        }
    }

    [Theory]
    [MemberData(nameof(Hosts))]
    public async Task Host_without_custody_settings_refuses_naming_them(string host)
    {
        var database = await postgres.NewMigratedDatabaseAsync();

        using var process = HostProcess.Start(
            host,
            Connections(Databases(host), database).Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        foreach (var setting in CustodySettings)
        {
            Assert.Contains(setting, output);
        }

        Assert.DoesNotContain("ConnectionStrings:", output);
    }

    [Theory]
    [InlineData("Hosted", "changeme")]
    [InlineData("Admin", "CHANGEME")]
    [InlineData("Worker", "isolation-test-only")]
    [InlineData("Hosted", "gatekeep")]
    [InlineData("Admin", "short-but-new-1")]
    public async Task Host_with_a_default_or_short_password_refuses_naming_only_the_setting(string host, string password)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var databases = Databases(host);
        var (first, _) = databases[0];

        // Every other setting is valid, so the refusal names exactly one.
        var arguments = Connections(databases, database)
            .Concat(Custody())
            .Append($"--Database:{first}:Password={password}")
            .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}");

        using var process = HostProcess.Start(host, arguments);
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains($"Host.{host} refuses to start", output);
        Assert.Contains($"Database:{first}:Password", output);
        if (password.Length >= 10)
        {
            // Short words such as "gatekeep" also appear in category names.
            Assert.DoesNotContain(password, output, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain(PostgresFixture.Password, output);
        Assert.DoesNotContain("ConnectionStrings:", output);
        Assert.DoesNotContain("Custody:", output);
    }

    [Fact]
    public async Task Default_password_in_the_connection_string_refuses_without_echoing_it()
    {
        using var process = HostProcess.Start(
            "Hosted",
            Custody()
                .Append($"--ConnectionStrings:Hosted=Host=localhost;Username=gk_hosted;Password=postgres;Application Name={Canary}")
                .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("ConnectionStrings:Hosted", output);
        Assert.DoesNotContain(Canary, output);
        Assert.DoesNotContain("Password=", output);
    }

    [Fact]
    public async Task Missing_password_file_refuses_naming_the_password_setting()
    {
        using var process = HostProcess.Start(
            "Admin",
            Custody()
                .Append("--ConnectionStrings:Admin=Host=localhost;Username=gk_admin")
                .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("Database:Admin:Password", output);
        Assert.DoesNotContain("ConnectionStrings:Admin", output);
    }

    [Fact]
    public async Task Partial_custody_settings_refuse_naming_the_missing_ones()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var roleId = SecretFile("role-id", Guid.NewGuid().ToString());

        using var process = HostProcess.Start(
            "Admin",
            Connections(Databases("Admin"), database)
                .Append($"--Custody:RoleIdFile={roleId}")
                .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("Custody:SocketPath", output);
        Assert.Contains("Custody:SecretIdFile", output);
        Assert.DoesNotContain("Custody:RoleIdFile", output);
    }

    [Fact]
    public async Task Custody_secret_file_holding_a_default_refuses()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var socket = Socket();

        using var process = HostProcess.Start(
            "Worker",
            Connections(Databases("Worker"), database)
                .Append($"--Custody:SocketPath={socket.Path}")
                .Append($"--Custody:RoleIdFile={SecretFile("role-id", Guid.NewGuid().ToString())}")
                .Append($"--Custody:SecretIdFile={SecretFile("secret-id", "changeme\n")}")
                .Append($"--Gatekeep:HealthPort={HostProcess.FreePort()}"));
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("Custody:SecretIdFile", output);
        Assert.DoesNotContain("Custody:RoleIdFile", output);
    }

    [Theory]
    [MemberData(nameof(Hosts))]
    public async Task Host_reads_passwords_from_secret_files_and_reports_healthy(string host)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var secrets = Directory.CreateDirectory(Path.Combine(_directory, "secrets-" + host)).FullName;
        var arguments = Custody().ToList();
        foreach (var (name, role) in Databases(host))
        {
            // The connection string carries no password: Compose mounts it as a file.
            var connection = postgres.RoleConnection(role, database).Replace($"Password={PostgresFixture.Password};", string.Empty);
            Assert.DoesNotContain(PostgresFixture.Password, connection);
            arguments.Add($"--ConnectionStrings:{name}={connection}");
            await File.WriteAllTextAsync(Path.Combine(secrets, $"Database__{name}__Password"), PostgresFixture.Password + "\n", Cancellation);
        }

        // A file the host must not read as a setting.
        await File.WriteAllTextAsync(Path.Combine(secrets, "ConnectionStrings__Hosted"), "Host=nowhere", Cancellation);

        var health = HostProcess.FreePort();
        arguments.Add($"--Gatekeep:SecretsDirectory={secrets}");
        arguments.Add($"--Gatekeep:HealthPort={health}");
        if (host != "Worker")
        {
            arguments.Add($"--Gatekeep:PublicPort={HostProcess.FreePort()}");
        }

        using var process = HostProcess.Start(host, arguments);
        var (status, body) = await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("healthy", body);
        Assert.DoesNotContain(PostgresFixture.Password, process.Output);
    }

    [Theory]
    [MemberData(nameof(Hosts))]
    public async Task Unreachable_database_answers_503_naming_database(string host)
    {
        var health = HostProcess.FreePort();
        var closed = HostProcess.FreePort();
        var arguments = Databases(host)
            .Select(d => $"--ConnectionStrings:{d.Name}=Host=127.0.0.1;Port={closed};Database=gatekeep;Username={d.Role};Password={Canary}")
            .Concat(Custody())
            .Append($"--Gatekeep:HealthPort={health}")
            .Append($"--Gatekeep:PublicPort={HostProcess.FreePort()}");

        using var process = HostProcess.Start(host, arguments);
        var (status, body) = await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, status);
        Assert.Equal("unhealthy: database", body);
        Assert.DoesNotContain(Canary, process.Output);
    }

    [Fact]
    public async Task Custody_up_then_gone_answers_200_then_503_naming_custody()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var socket = Socket();
        var health = HostProcess.FreePort();

        using var process = HostProcess.Start(
            "Hosted",
            Connections(Databases("Hosted"), database)
                .Concat(Custody(socket))
                .Append($"--Gatekeep:HealthPort={health}")
                .Append($"--Gatekeep:PublicPort={HostProcess.FreePort()}"));

        var up = await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation);
        Assert.Equal((HttpStatusCode.OK, "healthy"), up);

        socket.Dispose();

        var gone = await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation);
        Assert.Equal((HttpStatusCode.ServiceUnavailable, "unhealthy: custody"), gone);
    }

    [Theory]
    [InlineData(503)]
    [InlineData(501)]
    [InlineData(429)]
    public async Task Sealed_uninitialized_or_standby_OpenBao_answers_503_naming_custody(int openBaoStatus)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var socket = Socket(openBaoStatus);
        var health = HostProcess.FreePort();

        using var process = HostProcess.Start(
            "Admin",
            Connections(Databases("Admin"), database)
                .Concat(Custody(socket))
                .Append($"--Gatekeep:HealthPort={health}")
                .Append($"--Gatekeep:PublicPort={HostProcess.FreePort()}"));

        var answer = await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation);
        Assert.Equal((HttpStatusCode.ServiceUnavailable, "unhealthy: custody"), answer);

        // Once OpenBao is active the same host is healthy, so the status decided it.
        socket.Status = 200;
        Assert.Equal((HttpStatusCode.OK, "healthy"), await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation));
    }

    [Fact]
    public async Task Health_is_served_only_on_the_health_port()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var health = HostProcess.FreePort();
        var publicPort = HostProcess.FreePort();

        using var process = HostProcess.Start(
            "Hosted",
            Connections(Databases("Hosted"), database)
                .Concat(Custody())
                .Append($"--Gatekeep:HealthPort={health}")
                .Append($"--Gatekeep:PublicPort={publicPort}"));

        Assert.Equal(HttpStatusCode.OK, (await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation)).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await process.GetAsync(publicPort, HealthEndpoint, Timeout, Cancellation)).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await process.GetAsync(health, "/", Timeout, Cancellation)).Status);
    }

    [Fact]
    public async Task Worker_listens_on_no_port_but_health_even_when_given_a_public_port()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var health = HostProcess.FreePort();
        var publicPort = HostProcess.FreePort();

        using var process = HostProcess.Start(
            "Worker",
            Connections(Databases("Worker"), database)
                .Concat(Custody())
                .Append($"--Gatekeep:HealthPort={health}")
                .Append($"--Gatekeep:PublicPort={publicPort}"));

        // Health answering means Kestrel has bound every endpoint it will.
        Assert.Equal(HttpStatusCode.OK, (await process.GetAsync(health, HealthEndpoint, Timeout, Cancellation)).Status);

        using var client = new TcpClient();
        var refused = await Assert.ThrowsAsync<SocketException>(
            async () => await client.ConnectAsync(IPAddress.Loopback, publicPort, Cancellation));
        Assert.Equal(SocketError.ConnectionRefused, refused.SocketErrorCode);
    }

    [Fact]
    public async Task Health_port_equal_to_the_public_port_refuses()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var port = HostProcess.FreePort();

        using var process = HostProcess.Start(
            "Admin",
            Connections(Databases("Admin"), database)
                .Concat(Custody())
                .Append($"--Gatekeep:HealthPort={port}")
                .Append($"--Gatekeep:PublicPort={port}"));
        var output = await process.WaitForExitAsync(Timeout, Cancellation);

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("Gatekeep:HealthPort", output);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("  ", true)]
    [InlineData("ChangeMe", true)]
    [InlineData(" postgres ", true)]
    [InlineData("isolation-test-only", true)]
    [InlineData("fifteen-chars-x", true)]
    [InlineData("sixteen-chars-xy", false)]
    public void Password_check_uses_the_one_defaults_list(string? password, bool unsafePassword)
    {
        Assert.Equal(unsafePassword, SecretDefaults.IsUnsafePassword(password));
    }

    public void Dispose()
    {
        foreach (var socket in _sockets)
        {
            socket.Dispose();
        }

        Directory.Delete(_directory, recursive: true);
    }

    private static IReadOnlyList<(string Name, string Role)> Databases(string host) => host switch
    {
        "Hosted" => [("Hosted", TableRegistry.Hosted)],
        "Admin" => [("Admin", TableRegistry.Admin)],
        "Worker" =>
        [
            ("Dispatch", TableRegistry.Dispatch),
            ("Worker", TableRegistry.Worker),
            ("Sealer", TableRegistry.Sealer),
            ("Retention", TableRegistry.Retention),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(host)),
    };

    private IEnumerable<string> Connections(IReadOnlyList<(string Name, string Role)> databases, string database) =>
        databases.Select(d => $"--ConnectionStrings:{d.Name}={postgres.RoleConnection(d.Role, database)}");

    /// <summary>Custody settings for an OpenBao stand-in that answers 200, or for <paramref name="socket"/>.</summary>
    private IEnumerable<string> Custody(FakeOpenBaoSocket? socket = null) =>
    [
        $"--Custody:SocketPath={(socket ?? Socket()).Path}",
        $"--Custody:RoleIdFile={SecretFile("role-id", Guid.NewGuid().ToString())}",
        $"--Custody:SecretIdFile={SecretFile("secret-id", Guid.NewGuid().ToString())}",
    ];

    private FakeOpenBaoSocket Socket(int status = 200)
    {
        var socket = new FakeOpenBaoSocket(status);
        _sockets.Add(socket);
        return socket;
    }

    private string SecretFile(string name, string contents)
    {
        var path = Path.Combine(_directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, contents);
        return path;
    }
}
