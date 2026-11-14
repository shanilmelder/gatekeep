using System.Net;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Tests.Isolation.Hosting;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.21 (FR-2): while bootstrap is incomplete no Tenant can exist, so the real
/// <c>Host.Hosted</c> answers every request, for any host and path, with its one fixed 404.
/// </summary>
public sealed class TenantHostBeforeBootstrapTests(PostgresFixture postgres) : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private readonly string _directory = Directory.CreateTempSubdirectory("gatekeep-tenant-host-").FullName;

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Every_host_and_path_gets_the_same_fixed_404_before_bootstrap(bool tokenIssued)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        if (tokenIssued)
        {
            // Issued and unclaimed: bootstrap is still incomplete.
            await IssueTokenAsync(database);
        }

        Assert.Equal(tokenIssued ? 1L : 0L, await PostgresFixture.ScalarAsync<long>(postgres.SuperuserConnection(database), "SELECT count(*) FROM bootstrap_state WHERE completed_at IS NULL"));

        using var socket = new FakeOpenBaoSocket();
        var (health, port) = HostProcess.FreePorts();
        using var process = HostProcess.Start(
            "Hosted",
            $"--ConnectionStrings:Hosted={postgres.RoleConnection(TableRegistry.Hosted, database)}",
            $"--Custody:SocketPath={socket.Path}",
            $"--Custody:RoleIdFile={SecretFile("role-id")}",
            $"--Custody:SecretIdFile={SecretFile("secret-id")}",
            $"--Gatekeep:HealthPort={health}",
            $"--Gatekeep:PublicPort={port}");
        Assert.Equal(HttpStatusCode.OK, (await process.GetAsync(health, "/healthz", Timeout, Cancellation)).Status);

        using var http = new HttpClient(new SocketsHttpHandler { UseCookies = false, AllowAutoRedirect = false, UseProxy = false });
        var snapshots = new List<string>();
        foreach (var (hostName, method, path) in new[]
        {
            ("acme.gatekeep.test", HttpMethod.Get, "/"),
            ("acme.gatekeep.test", HttpMethod.Get, "/.well-known/openid-configuration"),
            ("other.gatekeep.test", HttpMethod.Post, "/connect/token"),
            ("x.y.example", HttpMethod.Get, "/bootstrap"),
            ("admin.gatekeep.test", HttpMethod.Post, "/api/v1/deployment/bootstrap"),
            ("127.0.0.1", HttpMethod.Get, "/random/path?with=query"),
        })
        {
            using var request = new HttpRequestMessage(method, new Uri($"http://127.0.0.1:{port}{path}"));
            request.Headers.Host = hostName;
            if (method == HttpMethod.Post)
            {
                request.Content = new StringContent("{}");
            }

            using var response = await http.SendAsync(request, Cancellation);
            await response.Content.LoadIntoBufferAsync(Cancellation);
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            snapshots.Add(await AdminHost.SnapshotAsync(response));
        }

        Assert.Single(snapshots.Distinct());
        Assert.EndsWith("\n", snapshots[0]);
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    /// <summary>Issues a bootstrap token as <c>gatekeep init</c> does, as <c>gk_cli</c>.</summary>
    private async Task IssueTokenAsync(string database)
    {
        var token = Gatekeep.Modules.Admins.Contracts.BootstrapToken.Generate();
        await using var source = Npgsql.NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Cli, database));
        await using var scope = await Gatekeep.Kernel.Persistence.DeploymentScope.BeginAsync(source, Cancellation);
        Assert.NotNull(await Gatekeep.Modules.Admins.Contracts.AdminsContract
            .CreateBootstrapIssuer(Gatekeep.Modules.Audit.Contracts.AuditContract.CreateAppender())
            .IssueAsync(scope.CreateCommandContext(), new Gatekeep.Kernel.Secrets.Secret<byte[]>(token), Cancellation));
        await scope.CommitAsync(Cancellation);
    }

    private string SecretFile(string name)
    {
        var path = Path.Combine(_directory, $"{name}-{Guid.NewGuid():N}");
        File.WriteAllText(path, Guid.NewGuid().ToString());
        return path;
    }
}
