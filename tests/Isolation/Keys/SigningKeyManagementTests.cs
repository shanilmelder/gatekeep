using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 9.1 (FR-37, AD-5, AD-33): <see cref="ISigningKeyManagement"/> as gk_admin, against the real
/// PostgreSQL and OpenBao through the real <c>host-admin</c> policy. The JWKS sample is the very key
/// set the Tenant's JWKS on Host.Hosted serves, member for member; the capability is decided again
/// from the grant; and nothing is written.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SigningKeyManagementTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string HostA = "acme.signing-keys.test";

    private static readonly string[] PublicMembers = ["alg", "e", "kid", "kty", "n", "use"];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_sample_is_exactly_what_Host_Hosted_serves_for_the_Tenant()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));

        // A previous key too, as a rotation leaves one: Transit first, then its row.
        var id = Guid.CreateVersion7();
        var previous = KeyName.Signing(a.TenantId, id);
        using (var worker = bao.Custody(OpenBaoFixture.Worker))
        {
            await worker.CreateKeyAsync(previous, Cancellation);
        }

        await database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, rotated_at, promoted_at) VALUES ('{id}', '{a.TenantId}', 'signing', 'previous', '{previous.Value}', 1, now(), now(), now())");

        using var admin = bao.Custody(OpenBaoFixture.Admin);
        var sample = await JwksAsync(database, a.TenantId, admin, Reader(a.TenantId));
        Assert.Equal(SigningKeyReadStatus.Read, sample.Status);
        Assert.Equal($"{a.Issuer}.well-known/jwks", sample.JwksUri);

        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://{HostA}{ProtocolContract.JsonWebKeySetPath}"));
        using var response = await host.Http.SendAsync(request, Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var served = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        var hosted = served.RootElement.GetProperty("keys").EnumerateArray().ToList();

        // The URI is the one the Tenant's own discovery names, not just a literal that matches it today.
        using var discoveryRequest = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://{HostA}{ProtocolContract.ConfigurationPath}"));
        using var discoveryResponse = await host.Http.SendAsync(discoveryRequest, Cancellation);
        Assert.Equal(HttpStatusCode.OK, discoveryResponse.StatusCode);
        using var discovery = JsonDocument.Parse(await discoveryResponse.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(discovery.RootElement.GetProperty("jwks_uri").GetString(), sample.JwksUri);

        // Host.Hosted's own members for an RSA key, and nothing else (Design Notes: the sample follows Hosted).
        Assert.All(hosted, k => Assert.Equal(PublicMembers, k.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal)));

        // Current, then next, then previous: the order both read the rows in.
        Assert.Equal(3, sample.Keys.Count);
        Assert.Equal(hosted.Select(Members), sample.Keys.Select(Members));
        Assert.Equal($"{previous.Value}.v1", sample.Keys[2].Kid);
        Assert.All(sample.Keys, k => Assert.StartsWith($"sig-{a.TenantId:D}-", k.Kid, StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_list_and_the_sample_need_tenant_configuration_read_in_the_path_Tenant()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.forbidden.signing-keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.forbidden.signing-keys.test")).TenantId;
        await SigningKeySeeds.FreshAsync(database.Superuser, a);
        using var admin = bao.Custody(OpenBaoFixture.Admin);

        // No role in A, a role in B only, and a Deployment Owner with none: refused alike, from the grant given.
        var refused = new (AdminPrincipal Principal, TenantRoleGrant? Grant)[]
        {
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), null),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(b, TenantRole.Owner)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true), null),
        };

        foreach (var (principal, grant) in refused)
        {
            Assert.Equal(SigningKeyReadStatus.Forbidden, (await ListAsync(database, a, principal, grant)).Status);
            var jwks = await JwksAsync(database, a, admin, (principal, grant));
            Assert.Equal(SigningKeyReadStatus.Forbidden, jwks.Status);
            Assert.Null(jwks.JwksUri);
            Assert.Empty(jwks.Keys);
        }

        foreach (var role in Enum.GetValues<TenantRole>())
        {
            var principal = new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false);
            var listed = await ListAsync(database, a, principal, new TenantRoleGrant(a, role));
            Assert.Equal(SigningKeyReadStatus.Read, listed.Status);
            Assert.Equal(2, listed.Keys.Count);
        }

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event"));
    }

    [Fact]
    public async Task A_custody_failure_or_a_missing_version_makes_the_whole_sample_unavailable_but_not_the_list()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync("down.signing-keys.test");
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));

        // No custody at all, custody refusing, and a row naming a version custody hasn't got.
        Assert.Equal(SigningKeyReadStatus.Unavailable, (await JwksAsync(database, a.TenantId, null, Reader(a.TenantId))).Status);

        using (var failing = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin)))
        {
            failing.Failing.Add(KeyOperation.ReadPublicKey);
            var down = await JwksAsync(database, a.TenantId, failing, Reader(a.TenantId));
            Assert.Equal(SigningKeyReadStatus.Unavailable, down.Status);
            Assert.Empty(down.Keys);
        }

        var (principal, grant) = Reader(a.TenantId);
        Assert.Equal(SigningKeyReadStatus.Read, (await ListAsync(database, a.TenantId, principal, grant)).Status);

        await database.ExecuteAsync(
            $"SET session_replication_role = replica; UPDATE signing_key SET transit_version = 2 WHERE tenant_id = '{a.TenantId}' AND purpose = 'signing' AND state = 'next'; SET session_replication_role = DEFAULT");
        using var admin = bao.Custody(OpenBaoFixture.Admin);
        Assert.Equal(SigningKeyReadStatus.Unavailable, (await JwksAsync(database, a.TenantId, admin, Reader(a.TenantId))).Status);
    }

    [Fact]
    public async Task Reads_need_the_path_Tenants_own_scope()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.scope.signing-keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.scope.signing-keys.test")).TenantId;
        var (principal, grant) = Reader(b);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
        var keys = ManagementContract.CreateSigningKeys(AuditContract.CreateAppender());

        await Assert.ThrowsAsync<InvalidOperationException>(() => keys.ListAsync(scope.CreateCommandContext(), principal, grant, b, Cancellation));
        await Assert.ThrowsAsync<InvalidOperationException>(() => keys.GetJwksAsync(scope.CreateCommandContext(), null, principal, grant, b, Cancellation));
    }

    private static (AdminPrincipal Principal, TenantRoleGrant? Grant) Reader(Guid tenant) =>
        (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(tenant, TenantRole.Viewer));

    private static string Members(JsonElement key) =>
        string.Join("|", PublicMembers.Select(m => key.GetProperty(m).GetString()));

    private static string Members(SigningKeyJwk key) =>
        string.Join("|", key.Alg, key.E, key.Kid, key.Kty, key.N, key.Use);

    private async Task<SigningKeyListRead> ListAsync(ProtocolDatabase database, Guid tenant, AdminPrincipal principal, TenantRoleGrant? grant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var read = await ManagementContract.CreateSigningKeys(AuditContract.CreateAppender())
            .ListAsync(scope.CreateCommandContext(), principal, grant, tenant, Cancellation);
        await scope.CommitAsync(Cancellation);
        return read;
    }

    private async Task<SigningKeyJwksRead> JwksAsync(
        ProtocolDatabase database,
        Guid tenant,
        IKeyCustody? custody,
        (AdminPrincipal Principal, TenantRoleGrant? Grant) caller)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var read = await ManagementContract.CreateSigningKeys(AuditContract.CreateAppender())
            .GetJwksAsync(scope.CreateCommandContext(), custody, caller.Principal, caller.Grant, tenant, Cancellation);
        await scope.CommitAsync(Cancellation);
        return read;
    }
}
