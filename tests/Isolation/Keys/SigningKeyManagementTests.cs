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

    /// <summary>
    /// Story 9.2 (AD-5): the rotation decides <c>tenant.signing_keys.rotate</c> again from the grant it is given.
    /// Only the path Tenant's Owner rotates; a Viewer, an Editor, another Tenant's Owner and a Deployment
    /// Owner with no role are refused before custody is called, and nothing is written.
    /// </summary>
    [Fact]
    public async Task The_rotation_needs_tenant_signing_keys_rotate_in_the_path_Tenant()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.rotate.signing-keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.rotate.signing-keys.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, a));
        await database.BackdateAsync(
            $"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE tenant_id = '{a}' AND purpose = 'signing' AND state = 'next'");
        var before = await database.ScalarAsync<string>($"SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM signing_key s WHERE tenant_id = '{a}'");

        var refused = new (AdminPrincipal Principal, TenantRoleGrant? Grant)[]
        {
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(a, TenantRole.Viewer)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(a, TenantRole.Editor)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(b, TenantRole.Owner)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true), null),
        };

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        foreach (var (principal, grant) in refused)
        {
            var result = await RotateAsync(database, a, custody, principal, grant);
            Assert.Equal(SigningKeyRotateStatus.Forbidden, result.Status);
            Assert.Null(result.RetryAfter);
        }

        Assert.Equal(0, custody.TotalCalls);
        Assert.Equal(before, await database.ScalarAsync<string>($"SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM signing_key s WHERE tenant_id = '{a}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code LIKE 'keys.signing_key.%'"));

        // The Owner without custody is Unavailable; with it, the rotation is the Owner's, as Actor.
        var owner = new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false);
        Assert.Equal(SigningKeyRotateStatus.Unavailable, (await RotateAsync(database, a, null, owner, new TenantRoleGrant(a, TenantRole.Owner))).Status);
        Assert.Equal(SigningKeyRotateStatus.Rotated, (await RotateAsync(database, a, custody, owner, new TenantRoleGrant(a, TenantRole.Owner))).Status);
        Assert.Equal(3L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND actor_kind = 'admin' AND actor_id = '{owner.AdminId}'"));

        // The next key, now brand new, is not ready; once aged, a failing custody is Unavailable too.
        Assert.Equal(SigningKeyRotateStatus.NotReady, (await RotateAsync(database, a, custody, owner, new TenantRoleGrant(a, TenantRole.Owner))).Status);
        await database.BackdateAsync(
            $"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE tenant_id = '{a}' AND purpose = 'signing' AND state = 'next'");
        custody.Failing.Add(KeyOperation.Create);
        Assert.Equal(SigningKeyRotateStatus.Unavailable, (await RotateAsync(database, a, custody, owner, new TenantRoleGrant(a, TenantRole.Owner))).Status);
    }

    /// <summary>
    /// Story 9.3 (AD-5): the revocation decides <c>tenant.signing_keys.revoke</c> again from the grant it is given.
    /// Only the path Tenant's Owner revokes; a Viewer, an Editor, another Tenant's Owner and a Deployment Owner
    /// with no role are refused before custody is called, and nothing is written.
    /// </summary>
    [Fact]
    public async Task The_revocation_needs_tenant_signing_keys_revoke_in_the_path_Tenant()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.revoke.signing-keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.revoke.signing-keys.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, a));
        var keyId = await CurrentKeyIdAsync(database, a);
        var before = await database.ScalarAsync<string>($"SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM signing_key s WHERE tenant_id = '{a}'");

        var refused = new (AdminPrincipal Principal, TenantRoleGrant? Grant)[]
        {
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(a, TenantRole.Viewer)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(a, TenantRole.Editor)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false), new TenantRoleGrant(b, TenantRole.Owner)),
            (new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: true), null),
        };

        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Admin));
        foreach (var (principal, grant) in refused)
        {
            Assert.Equal(SigningKeyRevokeStatus.Forbidden, (await RevokeAsync(database, a, custody, principal, grant, keyId, revokeAccess: true)).Status);
        }

        Assert.Equal(0, custody.TotalCalls);
        Assert.Equal(before, await database.ScalarAsync<string>($"SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM signing_key s WHERE tenant_id = '{a}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code LIKE 'keys.signing_key.%' OR type_code = 'sessions.access.revoked'"));

        // The Owner: no custody is Unavailable, a key ID naming no published key NotFound, a failing custody Unavailable.
        var owner = new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false);
        var ownerGrant = new TenantRoleGrant(a, TenantRole.Owner);
        Assert.Equal(SigningKeyRevokeStatus.Unavailable, (await RevokeAsync(database, a, null, owner, ownerGrant, keyId, revokeAccess: false)).Status);
        Assert.Equal(SigningKeyRevokeStatus.NotFound, (await RevokeAsync(database, a, custody, owner, ownerGrant, "sig-unknown.v1", revokeAccess: true)).Status);
        custody.Failing.Add(KeyOperation.Create);
        Assert.Equal(SigningKeyRevokeStatus.Unavailable, (await RevokeAsync(database, a, custody, owner, ownerGrant, keyId, revokeAccess: true)).Status);
        Assert.Equal(before, await database.ScalarAsync<string>($"SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM signing_key s WHERE tenant_id = '{a}'"));
        custody.Failing.Clear();

        // Without revokeAccess, no Session is touched and no revocation event written.
        Assert.Equal(SigningKeyRevokeStatus.Revoked, (await RevokeAsync(database, a, custody, owner, ownerGrant, keyId, revokeAccess: false)).Status);
        Assert.Equal(2L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND actor_kind = 'admin' AND actor_id = '{owner.AdminId}' AND type_code IN ('keys.signing_key.revoked', 'keys.signing_key.created')"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code = 'sessions.access.revoked'"));
    }

    /// <summary>
    /// Story 9.3 (AD-13): with <c>revokeAccess</c>, the revocation also ends every Session and revokes every Token
    /// Family and token of the path Tenant, through <c>RevokeAccessAsync</c>, with one <c>sessions.access.revoked</c>
    /// in the same transaction. Another Tenant's are untouched.
    /// </summary>
    [Fact]
    public async Task Revoking_with_revokeAccess_revokes_the_Tenants_Sessions_and_tokens_by_the_one_path()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.access.signing-keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.access.signing-keys.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, a));
        await SeedAccessAsync(database, a);
        await SeedAccessAsync(database, b);
        var bBefore = await AccessAsync(database, b);

        var owner = new AdminPrincipal(Guid.CreateVersion7(), DeploymentOwner: false);
        using var custody = bao.Custody(OpenBaoFixture.Admin);
        var result = await RevokeAsync(database, a, custody, owner, new TenantRoleGrant(a, TenantRole.Owner), await CurrentKeyIdAsync(database, a), revokeAccess: true);

        Assert.Equal(SigningKeyRevokeStatus.Revoked, result.Status);
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{a}' AND (ended_at IS NULL OR end_reason <> 'admin_revoke')"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{a}' AND status <> 'revoked'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{a}' AND status <> 'revoked'"));
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = 'sessions.access.revoked' AND actor_kind = 'admin' AND actor_id = '{owner.AdminId}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a}' AND type_code = 'keys.signing_key.revoked'"));

        Assert.Equal(bBefore, await AccessAsync(database, b));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{b}' AND type_code = 'sessions.access.revoked'"));
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

    /// <summary>The rotation as Host.Admin calls it, committed only when it rotated.</summary>
    private async Task<SigningKeyRotateResult> RotateAsync(
        ProtocolDatabase database,
        Guid tenant,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var result = await ManagementContract.CreateSigningKeys(AuditContract.CreateAppender())
            .RotateAsync(scope.CreateCommandContext(), custody, principal, grant, tenant, Cancellation);
        if (result.Status == SigningKeyRotateStatus.Rotated)
        {
            await scope.CommitAsync(Cancellation);
        }

        return result;
    }

    /// <summary>The revocation as Host.Admin calls it, committed only when it revoked.</summary>
    private async Task<SigningKeyRevokeResult> RevokeAsync(
        ProtocolDatabase database,
        Guid tenant,
        IKeyCustody? custody,
        AdminPrincipal principal,
        TenantRoleGrant? grant,
        string keyId,
        bool revokeAccess)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var result = await ManagementContract.CreateSigningKeys(AuditContract.CreateAppender())
            .RevokeAsync(scope.CreateCommandContext(), custody, principal, grant, tenant, keyId, revokeAccess, Cancellation);
        if (result.Status == SigningKeyRevokeStatus.Revoked)
        {
            await scope.CommitAsync(Cancellation);
        }

        return result;
    }

    private static Task<string> CurrentKeyIdAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'current'");

    /// <summary>Two live Sessions of one User, each with a Token Family and a refresh token, as the superuser.</summary>
    private static async Task SeedAccessAsync(ProtocolDatabase database, Guid tenant)
    {
        var user = await database.AddUserAsync(tenant);
        var (application, _) = await database.CreateApplicationAsync(tenant, "web");
        for (var i = 0; i < 2; i++)
        {
            var session = Guid.CreateVersion7();
            var family = Guid.CreateVersion7();
            await database.ExecuteAsync(
                $"""
                INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
                VALUES ('{tenant}', '{session}', '{user}', sha256('{session}'::bytea), ARRAY['pwd'], now(), now() + interval '1 day', now() + interval '2 days', now());
                INSERT INTO "authorization" (tenant_id, id, application_id, user_session_id, subject, status, type, concurrency_token)
                VALUES ('{tenant}', '{family}', '{application}', '{session}', '{user}', 'valid', 'ad-hoc', gen_random_uuid());
                INSERT INTO token (tenant_id, id, application_id, authorization_id, subject, type, status, reference_id, concurrency_token)
                VALUES ('{tenant}', gen_random_uuid(), '{application}', '{family}', '{user}', 'refresh_token', 'valid',
                        encode(sha256('{family}'::bytea), 'base64'), gen_random_uuid());
                """);
        }
    }

    /// <summary>Every column of the Tenant's Sessions, Token Families and tokens, so any change shows.</summary>
    private static Task<string> AccessAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"""
            SELECT coalesce((SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM user_session s WHERE tenant_id = '{tenant}'), '')
                || '|' || coalesce((SELECT string_agg(to_jsonb(f)::text, ',' ORDER BY id) FROM "authorization" f WHERE tenant_id = '{tenant}'), '')
                || '|' || coalesce((SELECT string_agg(to_jsonb(t)::text, ',' ORDER BY id) FROM token t WHERE tenant_id = '{tenant}'), '')
            """);

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
