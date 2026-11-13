using System.Net;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 9.3 (FR-38, AD-5, AD-11, AD-13, AD-20) on the real Host.Admin and PostgreSQL, with the OpenBao
/// stand-in creating any replacement key: <c>POST /api/v1/tenants/{tenantId}/signing-keys/{keyId}/revoke</c>.
/// Only the path Tenant's Owner revokes, after a fresh assertion bound to the key; the key leaves the JWKS
/// and its destruction is queued; a revoked current or next is replaced; a key ID naming no published key of
/// the Tenant is one 404; custody down is 503; and nothing else, and no other Tenant, changes. One test or more
/// per API row of the story's matrix; the JWKS row runs Host.Hosted on the real OpenBao. No assertion prints a
/// key name or version.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class SigningKeyRevokeApiTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string Action = "tenant.signing_keys.revoke";

    private const string Revoked = "keys.signing_key.revoked";
    private const string Promoted = "keys.signing_key.promoted";
    private const string PromotedUnaged = "keys.signing_key.promoted_unaged";
    private const string Created = "keys.signing_key.created";
    private const string AccessRevoked = "sessions.access.revoked";

    private const string Destroy = "keys.signing_key.destroy";

    private const string Denied = "type_code = 'admin.access.denied'";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_Owner_revokes_a_previous_key_alone_and_gets_the_keys_as_the_revocation_leaves_them()
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var (signing, _) = await SigningKeySeeds.EveryStateAsync(setup.Host.Superuser, setup.Tenant);
        var previous = signing[2];

        await using var listener = await ListenAsync(setup.Host);
        await setup.ConfirmAsync(previous.KeyId);
        using var response = await RevokeAsync(setup, previous.KeyId);

        var keys = await KeysAsync(response);
        Assert.Equal(
            [(signing[0].KeyId, "next"), (signing[1].KeyId, "current")],
            keys.Take(2).Select(k => (k.GetProperty("keyId").GetString()!, k.GetProperty("state").GetString()!)));
        Assert.Equal("revoked", keys.Single(k => k.GetProperty("keyId").GetString() == previous.KeyId).GetProperty("state").GetString());
        Assert.Empty(custody.Created);

        Assert.Equal(1L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code = '{Revoked}' AND actor_kind = 'admin' AND actor_id = '{setup.Owner}'"));
        Assert.Equal("1/0/0/0", await EventsAsync(setup.Host, setup.Tenant));
        Assert.Equal(1L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM job j JOIN job_payload p ON p.job_id = j.id WHERE j.type = '{Destroy}' AND j.status = 'pending' AND p.ids ->> 'signing_key_id' = '{IdOf(previous)}'"));
        Assert.Equal(setup.Tenant.ToString(), await listener.NextAsync());

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        Assert.DoesNotContain("mgmt-", body, StringComparison.Ordinal);
        Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(20, Promoted)]
    [InlineData(2, PromotedUnaged)]
    public async Task The_Owner_revokes_the_current_key_and_next_is_promoted_aged_or_not(int nextPublishedMinutesAgo, string promotion)
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var fresh = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, setup.Tenant);
        await PublishedAsync(setup.Host, setup.Tenant, nextPublishedMinutesAgo);
        var management = await SnapshotAsync(setup.Host, setup.Tenant, "management");

        await setup.ConfirmAsync(fresh[1].KeyId);
        using var response = await RevokeAsync(setup, fresh[1].KeyId);

        // The new next, then the old next as current, then the old current, revoked.
        var keys = await KeysAsync(response);
        var created = Assert.Single(custody.Created);
        Assert.StartsWith($"sig-{setup.Tenant:D}-", created, StringComparison.Ordinal);
        Assert.Equal(
            [($"{created}.v1", "next"), (fresh[0].KeyId, "current"), (fresh[1].KeyId, "revoked")],
            keys.Select(k => (k.GetProperty("keyId").GetString()!, k.GetProperty("state").GetString()!)));

        Assert.Equal(promotion == Promoted ? "1/1/0/1" : "1/0/1/1", await EventsAsync(setup.Host, setup.Tenant));
        Assert.Equal(3L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code LIKE 'keys.%' AND actor_kind = 'admin' AND actor_id = '{setup.Owner}'"));
        Assert.Equal(management, await SnapshotAsync(setup.Host, setup.Tenant, "management"));
        Assert.Equal(1L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{Destroy}'"));
    }

    [Fact]
    public async Task The_Owner_revokes_the_next_key_and_it_is_replaced_with_current_unchanged()
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var fresh = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, setup.Tenant);
        var current = await RowAsync(setup.Host, fresh[1]);

        await setup.ConfirmAsync(fresh[0].KeyId);
        using var response = await RevokeAsync(setup, fresh[0].KeyId);

        var keys = await KeysAsync(response);
        var created = Assert.Single(custody.Created);
        Assert.Equal(
            [($"{created}.v1", "next"), (fresh[1].KeyId, "current"), (fresh[0].KeyId, "revoked")],
            keys.Select(k => (k.GetProperty("keyId").GetString()!, k.GetProperty("state").GetString()!)));
        Assert.Equal(current, await RowAsync(setup.Host, fresh[1]));
        Assert.Equal("1/0/0/1", await EventsAsync(setup.Host, setup.Tenant));
    }

    [Fact]
    public async Task With_revokeAccess_every_Session_and_token_of_the_Tenant_is_revoked_in_the_same_transaction_and_another_Tenants_are_untouched()
    {
        await using var setup = await SetupAsync();
        _ = new PublicHalves(setup.Host);
        var other = await InsertAsync(setup.Host);
        var (signing, _) = await SigningKeySeeds.EveryStateAsync(setup.Host.Superuser, setup.Tenant);
        await SeedAccessAsync(setup.Host, setup.Tenant);
        await SeedAccessAsync(setup.Host, other);
        var otherBefore = await AccessAsync(setup.Host, other);

        await setup.ConfirmAsync(signing[2].KeyId);
        using var response = await RevokeAsync(setup, signing[2].KeyId, """{"revokeAccess":true}""");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM user_session WHERE tenant_id = '{setup.Tenant}' AND (ended_at IS NULL OR end_reason <> 'admin_revoke')"));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM \"authorization\" WHERE tenant_id = '{setup.Tenant}' AND status <> 'revoked'"));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM token WHERE tenant_id = '{setup.Tenant}' AND status <> 'revoked'"));

        // One revocation event, the Owner's, beside the key's own.
        Assert.Equal(1L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code = '{AccessRevoked}' AND actor_kind = 'admin' AND actor_id = '{setup.Owner}'"));
        Assert.Equal(1L, await TenantEventsAsync(setup.Host, setup.Tenant, Revoked));

        Assert.Equal(otherBefore, await AccessAsync(setup.Host, other));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{other}' AND type_code = '{AccessRevoked}'"));
    }

    [Fact]
    public async Task Without_revokeAccess_no_Session_or_token_changes()
    {
        await using var setup = await SetupAsync();
        _ = new PublicHalves(setup.Host);
        var (signing, _) = await SigningKeySeeds.EveryStateAsync(setup.Host.Superuser, setup.Tenant);
        await SeedAccessAsync(setup.Host, setup.Tenant);
        var before = await AccessAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync(signing[2].KeyId);
        using var response = await RevokeAsync(setup, signing[2].KeyId);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before, await AccessAsync(setup.Host, setup.Tenant));
        Assert.Equal(0L, await TenantEventsAsync(setup.Host, setup.Tenant, AccessRevoked));
    }

    public static TheoryData<string> Unknown => new()
    {
        "retired",
        "revoked",
        "management",
        "other",
        "absent",
        "version",
        "malformed",
    };

    [Theory]
    [MemberData(nameof(Unknown))]
    public async Task A_key_ID_naming_no_published_signing_key_of_the_Tenant_is_the_same_404_and_nothing_is_written(string kind)
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var other = await InsertAsync(setup.Host);
        var (signing, management) = await SigningKeySeeds.EveryStateAsync(setup.Host.Superuser, setup.Tenant);
        var otherKeys = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, other);
        var keyId = kind switch
        {
            "retired" => signing[3].KeyId,
            "revoked" => signing[4].KeyId,
            "management" => management[0].KeyId,
            "other" => otherKeys[1].KeyId,
            "absent" => $"sig-{setup.Tenant:D}-{Guid.CreateVersion7():D}.v1",
            "version" => signing[1].KeyId[..^1] + "2",
            _ => "not-a-kid",
        };
        var (before, otherBefore) = (await SnapshotAsync(setup.Host, setup.Tenant), await SnapshotAsync(setup.Host, other));

        await setup.ConfirmAsync(keyId);
        using var response = await RevokeAsync(setup, keyId, """{"revokeAccess":true}""");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("not_found", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(setup.Host, setup.Tenant));
        Assert.Equal(otherBefore, await SnapshotAsync(setup.Host, other));
        Assert.Equal("0/0/0/0", await EventsAsync(setup.Host, setup.Tenant));
        Assert.Equal(0L, await TenantEventsAsync(setup.Host, setup.Tenant, AccessRevoked));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{Destroy}'"));
    }

    [Fact]
    public async Task With_no_fresh_assertion_a_stale_one_or_one_for_another_key_it_is_403_and_nothing_is_written()
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var fresh = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, setup.Tenant);
        var before = await SnapshotAsync(setup.Host, setup.Tenant);

        using (var none = await RevokeAsync(setup, fresh[1].KeyId))
        {
            await FreshAssertionTests.AssertProblemAsync(none, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        // A grant bound to the next key never serves the current one.
        await setup.ConfirmAsync(fresh[0].KeyId);
        using (var wrongTarget = await RevokeAsync(setup, fresh[1].KeyId))
        {
            await FreshAssertionTests.AssertProblemAsync(wrongTarget, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        // The last assertion more than 5 minutes old.
        await setup.ConfirmAsync(fresh[1].KeyId);
        await PostgresFixture.ExecuteAsync(
            setup.Host.Superuser,
            "UPDATE admin_fresh_assertion SET created_at = created_at - interval '6 minutes', expires_at = expires_at - interval '6 minutes'");
        using (var stale = await RevokeAsync(setup, fresh[1].KeyId))
        {
            await FreshAssertionTests.AssertProblemAsync(stale, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(setup.Host, setup.Tenant));
        Assert.Equal("0/0/0/0", await EventsAsync(setup.Host, setup.Tenant));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{Destroy}'"));
    }

    [Theory]
    [InlineData("editor")]
    [InlineData("viewer")]
    public async Task An_Editor_or_a_Viewer_is_403_audited_and_nothing_changes(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var tenant = await InsertAsync(host);
        var fresh = await SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        var before = await SnapshotAsync(host, tenant);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, role);

        using var response = await RevokeAsync(host, cookie, csrf, tenant, fresh[1].KeyId);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(host, tenant));
        Assert.Equal("0/0/0/0", await EventsAsync(host, tenant));
        Assert.Equal(1L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{tenant}'"));
    }

    [Fact]
    public async Task Another_Tenants_Owner_is_403_and_neither_Tenant_changes()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var custody = new PublicHalves(host);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        var aKeys = await SigningKeySeeds.FreshAsync(host.Superuser, a);
        await SigningKeySeeds.FreshAsync(host.Superuser, b);
        var (aBefore, bBefore) = (await SnapshotAsync(host, a), await SnapshotAsync(host, b));
        var (cookie, csrf, _) = await RoleSessionAsync(host, b, "owner");

        using var response = await RevokeAsync(host, cookie, csrf, a, aKeys[1].KeyId);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("access_denied", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(aBefore, await SnapshotAsync(host, a));
        Assert.Equal(bBefore, await SnapshotAsync(host, b));
    }

    [Fact]
    public async Task Custody_refusing_the_create_is_503_the_key_stays_current_and_nothing_is_written()
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host) { RefuseCreate = true };
        var other = await InsertAsync(setup.Host);
        var fresh = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, setup.Tenant);
        await SigningKeySeeds.FreshAsync(setup.Host.Superuser, other);
        var (before, otherBefore) = (await SnapshotAsync(setup.Host, setup.Tenant), await SnapshotAsync(setup.Host, other));

        await setup.ConfirmAsync(fresh[1].KeyId);
        using var response = await RevokeAsync(setup, fresh[1].KeyId, """{"revokeAccess":true}""");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty(custody.Created);
        Assert.Equal("current", await setup.Host.ScalarAsync<string>(
            $"SELECT state FROM signing_key WHERE tenant_id = '{setup.Tenant}' AND transit_name = '{fresh[1].Key.Value}'"));
        Assert.Equal(before, await SnapshotAsync(setup.Host, setup.Tenant));
        Assert.Equal(otherBefore, await SnapshotAsync(setup.Host, other));
        Assert.Equal("0/0/0/0", await EventsAsync(setup.Host, setup.Tenant));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM job WHERE type = '{Destroy}'"));
        // The console logger writes from its own queue, so the line can land just after the answer.
        const string Logged = "Key custody couldn't create a Signing Key for a revocation";
        for (var waited = 0; waited < 50 && !setup.Host.Output.Contains(Logged, StringComparison.Ordinal); waited++)
        {
            await Task.Delay(100, Cancellation);
        }

        Assert.Contains(Logged, setup.Host.Output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"revokeAccess":"yes"}""")]
    [InlineData("""{"revokeAccess":null}""")]
    [InlineData("null")]
    [InlineData("not json")]
    public async Task A_malformed_body_is_400_invalid_request_and_nothing_is_written(string body)
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var fresh = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, setup.Tenant);
        var before = await SnapshotAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync(fresh[1].KeyId);
        using var response = await RevokeAsync(setup, fresh[1].KeyId, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(setup.Host, setup.Tenant));
        Assert.Equal("0/0/0/0", await EventsAsync(setup.Host, setup.Tenant));
    }

    [Fact]
    public async Task A_different_page_Tenant_is_409_tenant_mismatch_and_nothing_runs()
    {
        await using var setup = await SetupAsync();
        var custody = new PublicHalves(setup.Host);
        var b = await InsertAsync(setup.Host);
        var fresh = await SigningKeySeeds.FreshAsync(setup.Host.Superuser, setup.Tenant);
        var before = await SnapshotAsync(setup.Host, setup.Tenant);

        using var response = await setup.Host.SendAsync(
            HttpMethod.Post, RevokePath(setup.Tenant, fresh[1].KeyId), setup.Cookie, setup.Csrf, AdminHost.Origin, """{"revokeAccess":false}""", [(Header, Id(b))]);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_mismatch", await CodeAsync(response));
        Assert.Empty(custody.Created);
        Assert.Equal(before, await SnapshotAsync(setup.Host, setup.Tenant));
    }

    [Fact]
    public async Task No_Session_is_401()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);

        using var response = await host.SendAsync(
            HttpMethod.Post, RevokePath(tenant, "sig-x.v1"), origin: AdminHost.Origin, body: """{"revokeAccess":false}""", headers: [(Header, Id(tenant))]);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// The key leaves the Tenant's JWKS on Host.Hosted at once: the revocation's NOTIFY drops the kept runtime, so
    /// the next request serves the set without it. Real OpenBao, so Host.Hosted can read the public halves.
    /// </summary>
    [Fact]
    public async Task A_revoked_key_leaves_the_JWKS_Host_Hosted_serves_at_once()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = await database.AddTenantAsync($"t{Guid.NewGuid():N}.revoke-api.test");
        Assert.True(await database.ProvisionAsync(bao, tenant.TenantId));
        await RotateOnDemandAsync(database, tenant.TenantId);
        var previous = await database.ScalarAsync<string>(
            $"SELECT transit_name || '.v' || transit_version FROM signing_key WHERE tenant_id = '{tenant.TenantId}' AND purpose = 'signing' AND state = 'previous'");

        await using var hosted = await ProtocolHost.StartAsync(database.Hosted, bao, new ManualTimeProvider());
        Assert.Contains(previous, await KidsAsync(hosted, tenant.RpId));

        await using var setup = await SetupAsync(database, tenant.TenantId);
        await setup.ConfirmAsync(previous);
        using (var response = await RevokeAsync(setup, previous))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        // The clock never moves: only the revocation's notification can make Host.Hosted drop its copy.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(15);
        List<string> kids;
        while ((kids = await KidsAsync(hosted, tenant.RpId)).Contains(previous) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), Cancellation);
        }

        Assert.DoesNotContain(previous, kids);
        Assert.Equal(2, kids.Count);
    }

    private static string RevokePath(Guid tenant, string keyId) =>
        $"/api/v1/tenants/{Id(tenant)}/signing-keys/{Uri.EscapeDataString(keyId)}/revoke";

    private static Task<HttpResponseMessage> RevokeAsync(Setup setup, string keyId, string body = """{"revokeAccess":false}""") =>
        RevokeAsync(setup.Host, setup.Cookie, setup.Csrf, setup.Tenant, keyId, body);

    private static Task<HttpResponseMessage> RevokeAsync(
        AdminHost host, string cookie, string csrf, Guid tenant, string keyId, string body = """{"revokeAccess":false}""") =>
        host.SendAsync(HttpMethod.Post, RevokePath(tenant, keyId), cookie, csrf, AdminHost.Origin, body, [(Header, Id(tenant))]);

    private async Task<Setup> SetupAsync()
    {
        var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant);
        return new Setup(host, tenant, cookie, csrf, owner, authenticators);
    }

    private async Task<Setup> SetupAsync(ProtocolDatabase database, Guid tenant)
    {
        var host = await AdminHost.StartAsync(postgres, database.Name);
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant);
        return new Setup(host, tenant, cookie, csrf, owner, authenticators);
    }

    /// <summary>A rotation on demand as Host.Admin runs it, with the real custody, so the Tenant has a previous key.</summary>
    private async Task RotateOnDemandAsync(ProtocolDatabase database, Guid tenant)
    {
        await database.BackdateAsync(
            $"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'");
        using var custody = bao.Custody(OpenBaoFixture.Admin);
        await using var source = NpgsqlDataSource.Create(database.Role(TableRegistry.Admin));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        var rotation = await KeysContract.RotateSigningKeyNowAsync(
            scope.CreateCommandContext(), custody, AuditContract.CreateAppender(), Actor.Admin(Guid.CreateVersion7()), tenant, Cancellation);
        Assert.Equal(SigningKeyRotationStatus.Rotated, rotation.Status);
        await scope.CommitAsync(Cancellation);
    }

    private static async Task<List<string>> KidsAsync(ProtocolHost host, string tenantHost)
    {
        using var response = await host.Http.GetAsync(new Uri($"http://{tenantHost}{ProtocolContract.JsonWebKeySetPath}"), Cancellation);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        return [.. document.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()!)];
    }

    /// <summary>The row ID a seeded key's name carries: <c>sig-{tenant}-{row}</c>.</summary>
    private static Guid IdOf(SigningKeySeeds.Seeded key) => Guid.Parse(key.Key.Value[^36..]);

    /// <summary>Backdates the Tenant's signing next's publication, as the superuser with the triggers off.</summary>
    private static Task PublishedAsync(AdminHost host, Guid tenant, int minutesAgo) =>
        PostgresFixture.ExecuteAsync(
            host.Superuser,
            "SET session_replication_role = replica; "
            + $"UPDATE signing_key SET published_at = now() - make_interval(mins => {minutesAgo}) WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'; "
            + "SET session_replication_role = DEFAULT");

    /// <summary>Two live Sessions of one User, each with a Token Family and a refresh token, as the superuser.</summary>
    private static async Task SeedAccessAsync(AdminHost host, Guid tenant)
    {
        var user = Guid.CreateVersion7();
        var application = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"INSERT INTO \"user\" (tenant_id, id) VALUES ('{tenant}', '{user}'); {TestTenants.ApplicationSql(tenant, application)}");
        for (var i = 0; i < 2; i++)
        {
            var session = Guid.CreateVersion7();
            var family = Guid.CreateVersion7();
            await PostgresFixture.ExecuteAsync(
                host.Superuser,
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
    private static Task<string> AccessAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<string>(
            $"""
            SELECT coalesce((SELECT string_agg(to_jsonb(s)::text, ',' ORDER BY id) FROM user_session s WHERE tenant_id = '{tenant}'), '')
                || '|' || coalesce((SELECT string_agg(to_jsonb(f)::text, ',' ORDER BY id) FROM "authorization" f WHERE tenant_id = '{tenant}'), '')
                || '|' || coalesce((SELECT string_agg(to_jsonb(t)::text, ',' ORDER BY id) FROM token t WHERE tenant_id = '{tenant}'), '')
            """);

    private static Task<string> RowAsync(AdminHost host, SigningKeySeeds.Seeded key) =>
        host.ScalarAsync<string>($"SELECT to_jsonb(s)::text FROM signing_key s WHERE transit_name = '{key.Key.Value}'");

    /// <summary>Every column of the Tenant's rows (of one purpose, if given), so any change shows.</summary>
    private static Task<string> SnapshotAsync(AdminHost host, Guid tenant, string? purpose = null) =>
        host.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(to_jsonb(s)::text, ',' ORDER BY id), '') FROM signing_key s WHERE tenant_id = '{tenant}'"
            + (purpose is null ? string.Empty : $" AND purpose = '{purpose}'"));

    /// <summary>The Tenant's revoked, promoted, promoted_unaged and created events, as counts.</summary>
    private static Task<string> EventsAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<string>(
            "SELECT " + string.Join(
                " || '/' || ",
                new[] { Revoked, Promoted, PromotedUnaged, Created }.Select(c => $"(SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{c}')")));

    private static async Task<List<JsonElement>> KeysAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(["keys"], json.RootElement.EnumerateObject().Select(p => p.Name));
        return [.. json.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.Clone())];
    }

    private static async Task<Listener> ListenAsync(AdminHost host)
    {
        var connection = new NpgsqlConnection(host.Superuser);
        await connection.OpenAsync(Cancellation);
        await using (var command = new NpgsqlCommand("LISTEN gatekeep_signing_keys", connection))
        {
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        return new Listener(connection);
    }

    /// <summary>One test's Admin host, Tenant and its Owner, whose revocations confirm against <see cref="Authenticators"/>.</summary>
    private sealed class Setup(AdminHost host, Guid tenant, string cookie, string csrf, Guid owner, SoftwareAuthenticator[] authenticators) : IAsyncDisposable
    {
        private int _calls;

        public AdminHost Host => host;

        public Guid Tenant => tenant;

        public string Cookie { get; private set; } = cookie;

        public string Csrf { get; private set; } = csrf;

        public Guid Owner => owner;

        public SoftwareAuthenticator[] Authenticators => authenticators;

        /// <summary>Confirms tenant.signing_keys.revoke in the Tenant, bound to <paramref name="keyId"/>: the Tenant begin, the sheet and the complete.</summary>
        public async Task ConfirmAsync(string keyId)
        {
            // A Session may make only so many fresh-assertion calls (a begin and a complete each).
            if (_calls + 2 > Gatekeep.Kernel.Limits.SecurityLimits.FreshAssertionAttempts)
            {
                (Cookie, Csrf) = await Host.SignInAsync(Authenticators[0]);
                _calls = 0;
            }

            _calls += 2;
            var (begin, options) = await BeginAsync(Host, Cookie, Csrf, Tenant, JsonSerializer.Serialize(new { action = Action, target = keyId }));
            using (begin)
            {
                Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            }

            using var complete = await Host.CompleteAssertionAsync(Cookie, Csrf, Authenticators[0].Assert(options, AdminHost.Origin));
            Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var authenticator in Authenticators)
            {
                authenticator.Dispose();
            }

            await Host.DisposeAsync();
        }
    }

    /// <summary>A superuser connection listening on the Signing Keys channel, as Host.Hosted's listener does.</summary>
    private sealed class Listener : IAsyncDisposable
    {
        private readonly NpgsqlConnection _connection;
        private string? _payload;

        public Listener(NpgsqlConnection connection)
        {
            _connection = connection;
            _connection.Notification += (_, e) => _payload = e.Payload;
        }

        /// <summary>The payload of the notification already sent, or of the next within 10 seconds.</summary>
        public async Task<string?> NextAsync()
        {
            if (_payload is null)
            {
                await _connection.WaitAsync(TimeSpan.FromSeconds(10), Cancellation);
            }

            return _payload;
        }

        public ValueTask DisposeAsync() => _connection.DisposeAsync();
    }
}
