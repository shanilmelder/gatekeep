using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Keys.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Jobs;
using Gatekeep.Tests.Isolation.Protocol;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Keys;

/// <summary>
/// Story 2.3 (AD-10, AD-11, AD-27): <c>signing_key</c> and <c>protection_key_wrap</c>, provisioned by
/// the one Keys path, <see cref="KeysContract.EnsureTenantKeysAsync"/>, from the Tenant creation stage
/// and the hourly backfill, against the real PostgreSQL and OpenBao through the <c>host-worker</c>
/// login. No assertion prints a key or a ciphertext.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class TenantKeysTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string Provisioned = "keys.tenant_keys.provisioned";

    private const string NewTenantRows = "management/current,management/next,signing/current,signing/next";

    [Fact]
    public async Task New_Tenant_gets_four_distinct_rsa_3072_Transit_keys_and_one_wrap_then_activates()
    {
        var database = await CreateAsync(postgres, registry: null);
        var admin = Guid.CreateVersion7();
        await database.SuperuserAsync($"INSERT INTO admin (id, deployment_owner) VALUES ('{admin}', true)");
        var created = await database.InScopeAsync(TableRegistry.Admin, null, context =>
            ManagementContract.CreateTenants(AuditContract.CreateAppender(), new TenantAddressing("gatekeep.test"))
                .CreateAsync(context, new AdminPrincipal(admin, true), new CreateTenantInput("Acme Dev", "acme-keys", "dev"), Cancellation));
        var tenant = created.Tenant!.Id;

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await using (var runner = database.Runner(OperationsContract.ProductionRegistry, worker))
        {
            while (await runner.RunOnceAsync(Cancellation))
            {
            }
        }

        Assert.Equal("active", await database.ScalarAsync<string>($"SELECT status FROM tenant WHERE id = '{tenant}'"));
        Assert.Equal(NewTenantRows, await RowsAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Provisioned}' AND actor_kind = 'system'"));

        // Signing rows are published at insert; Management rows never.
        Assert.Equal(0L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND ((purpose = 'signing') <> (published_at IS NOT NULL) OR published_at <> created_at)"));

        // A new Tenant's current keys are promoted at once (Story 2.4); nothing has rotated yet.
        Assert.Equal(0L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}' AND ((state = 'current') <> (promoted_at IS NOT NULL) OR promoted_at <> created_at OR rotated_at IS NOT NULL OR retired_at IS NOT NULL OR destroyed_at IS NOT NULL)"));

        var names = await NamesAsync(database, tenant);
        Assert.Equal(4, names.Distinct().Count());
        using var http = new HttpClient { BaseAddress = bao.Address };
        http.DefaultRequestHeaders.Add("X-Vault-Token", await bao.LoginAsync(OpenBaoFixture.Worker));
        foreach (var name in names)
        {
            using var body = JsonDocument.Parse(await http.GetStringAsync($"v1/transit/keys/{name}", Cancellation));
            var data = body.RootElement.GetProperty("data");
            Assert.Equal("rsa-3072", data.GetProperty("type").GetString());
            Assert.False(data.GetProperty("exportable").GetBoolean());
            Assert.Equal(1, data.GetProperty("latest_version").GetInt32());
        }

        // The wrap is Transit's ciphertext, and the Hosted login can unwrap it to 256 bits.
        var wrap = new KeyCiphertext(await database.ScalarAsync<string>($"SELECT ciphertext FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        using var hosted = bao.Custody(OpenBaoFixture.Hosted);
        var unwrapped = await hosted.DecryptAsync(KeysContract.TokenProtectionKey(tenant), tenant, wrap, Cancellation);
        Assert.Equal(32, unwrapped.Use(b => b.Length));
    }

    [Fact]
    public async Task A_second_run_creates_nothing_and_writes_no_event()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync("rerun.keys.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, tenant));
        var before = await NamesAsync(database, tenant);

        using var counting = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));
        Assert.False(await database.ProvisionAsync(bao, tenant, counting));

        Assert.Equal(0, counting.TotalCalls);
        Assert.Equal(before, await NamesAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Provisioned}'"));
    }

    [Fact]
    public async Task A_failure_after_two_Transit_keys_takes_back_every_row_and_a_rerun_converges()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync("crash.keys.test")).TenantId;

        var made = new List<string>();
        using var failing = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker))
        {
            BeforeCreate = key =>
            {
                if (made.Count == 2)
                {
                    throw new KeyCustodyException(key.Value, KeyOperation.Create, KeyCustodyFailure.Unavailable);
                }

                made.Add(key.Value);
            },
        };

        // The step's own transaction commits what it wrote before the failure: the savepoint takes it back.
        await using (var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, database.Name)))
        await using (var scope = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            await Assert.ThrowsAsync<KeyCustodyException>(() => KeysContract.EnsureTenantKeysAsync(
                scope.CreateCommandContext(), failing, AuditContract.CreateAppender(), tenant, Cancellation));
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(2, made.Count);
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{tenant}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Provisioned}'"));

        Assert.True(await database.ProvisionAsync(bao, tenant));
        Assert.Equal(NewTenantRows, await RowsAsync(database, tenant));

        // The two keys made before the failure are orphans: they exist, and no row names them.
        var names = await NamesAsync(database, tenant);
        using var worker = bao.Custody(OpenBaoFixture.Worker);
        foreach (var orphan in made)
        {
            Assert.DoesNotContain(orphan, names);
            Assert.NotEmpty(await worker.GetPublicKeysAsync(Parse(orphan), Cancellation));
        }
    }

    [Fact]
    public async Task Provisioning_needs_the_Tenants_own_scope()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.scope.keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.scope.keys.test")).TenantId;

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Worker, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);

        await Assert.ThrowsAsync<InvalidOperationException>(() => KeysContract.EnsureTenantKeysAsync(
            scope.CreateCommandContext(), worker, AuditContract.CreateAppender(), b, Cancellation));
    }

    [Fact]
    public async Task Backfill_gives_active_Tenants_their_keys_and_leaves_complete_ones_untouched()
    {
        var database = await CreateAsync(postgres, registry: null);

        // TenantB already has its keys; TenantA is from before Story 2.3 and has none.
        var b = new ProtocolDatabase(postgres, database.Name);
        Assert.True(await b.ProvisionAsync(bao, TenantB));
        var bNames = await NamesAsync(database, TenantB);
        var bWrap = await database.ScalarAsync<string>($"SELECT ciphertext FROM protection_key_wrap WHERE tenant_id = '{TenantB}'");

        // A Tenant still being created is its creation Operation's, not the backfill's.
        var creating = Guid.CreateVersion7();
        await TestTenants.InsertAsync(b.Superuser, creating, status: "creating");

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await RunBackfillAsync(database, worker, logger: null);

        Assert.Equal(NewTenantRows, await RowsAsync(database, TenantA));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND type_code = '{Provisioned}'"));

        Assert.Equal(bNames, await NamesAsync(database, TenantB));
        Assert.Equal(bWrap, await database.ScalarAsync<string>($"SELECT ciphertext FROM protection_key_wrap WHERE tenant_id = '{TenantB}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantB}' AND type_code = '{Provisioned}'"));

        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{creating}'"));
        Assert.Equal("done", await database.ScalarAsync<string>("SELECT status FROM job WHERE type = 'keys.tenant_keys.backfill'"));
    }

    /// <summary>Story 2.8: an active Tenant with its keys but no system Application gets exactly one, and a rerun keeps it.</summary>
    [Fact]
    public async Task Backfill_gives_an_active_Tenant_with_keys_its_one_system_Application()
    {
        var database = await CreateAsync(postgres, registry: null);
        var protocol = new ProtocolDatabase(postgres, database.Name);
        Assert.True(await protocol.ProvisionAsync(bao, TenantA));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await RunBackfillAsync(database, worker, logger: null);

        var system = await database.ScalarAsync<Guid>($"SELECT id FROM application WHERE tenant_id = '{TenantA}' AND kind = 'system'");
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));

        await RunBackfillAsync(database, worker, logger: null);

        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM application WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(system, await database.ScalarAsync<Guid>($"SELECT id FROM application WHERE tenant_id = '{TenantA}' AND kind = 'system'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.tenant_keys.backfill' AND status <> 'done'"));
    }

    /// <summary>
    /// Story 3.6: an active Tenant with no built-in Management API gets exactly one with its 17 Permissions, and no event;
    /// a rerun adds nothing, and one after a Permission went missing puts back only that one.
    /// </summary>
    [Fact]
    public async Task Backfill_gives_an_active_Tenant_its_one_built_in_Management_API_and_a_rerun_adds_nothing()
    {
        var database = await CreateAsync(postgres, registry: null);
        var protocol = new ProtocolDatabase(postgres, database.Name);
        Assert.True(await protocol.ProvisionAsync(bao, TenantA));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{TenantA}'"));

        using var worker = bao.Custody(OpenBaoFixture.Worker);
        await RunBackfillAsync(database, worker, logger: null);

        var api = await database.ScalarAsync<Guid>($"SELECT id FROM api WHERE tenant_id = '{TenantA}' AND built_in AND identifier = 'urn:gatekeep:management'");
        Assert.Equal(17L, await database.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE tenant_id = '{TenantA}' AND api_id = '{api}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}' AND target_kind = 'api'"));

        await RunBackfillAsync(database, worker, logger: null);

        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM api WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(api, await database.ScalarAsync<Guid>($"SELECT id FROM api WHERE tenant_id = '{TenantA}' AND built_in"));
        Assert.Equal(17L, await database.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE tenant_id = '{TenantA}'"));

        await database.SuperuserAsync($"DELETE FROM permission WHERE tenant_id = '{TenantA}' AND value = 'users:read'");
        await RunBackfillAsync(database, worker, logger: null);

        Assert.Equal(17L, await database.ScalarAsync<long>($"SELECT count(*) FROM permission WHERE tenant_id = '{TenantA}' AND api_id = '{api}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM job WHERE type = 'keys.tenant_keys.backfill' AND status <> 'done'"));
    }

    [Fact]
    public async Task Backfill_logs_one_Tenants_failure_and_still_provisions_the_others()
    {
        var database = await CreateAsync(postgres, registry: null);
        using var custody = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker))
        {
            BeforeCreate = key =>
            {
                if (key.TenantId == TenantA)
                {
                    throw new KeyCustodyException(key.Value, KeyOperation.Create, KeyCustodyFailure.Unavailable);
                }
            },
        };

        var logger = new RecordingLogger();
        await RunBackfillAsync(database, custody, logger);

        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM signing_key WHERE tenant_id = '{TenantA}'"));
        Assert.Equal(NewTenantRows, await RowsAsync(database, TenantB));
        Assert.Contains(logger.Lines, l => l == $"Key backfill for Tenant {TenantA} failed on KeyCustodyException.");
        Assert.DoesNotContain(logger.Lines, l => l.Contains("vault:", StringComparison.Ordinal) || l.Contains("sig-", StringComparison.Ordinal));

        // B was still provisioned and committed; the job records the failure and retries.
        Assert.Equal("pending/handler_failed", await database.ScalarAsync<string>(
            "SELECT status || '/' || failure_code FROM job WHERE type = 'keys.tenant_keys.backfill'"));
    }

    [Fact]
    public async Task Backfill_without_custody_fails_with_a_fixed_code_and_writes_nothing()
    {
        var database = await CreateAsync(postgres, registry: null);

        await RunBackfillAsync(database, custody: null, logger: null);

        Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM signing_key"));
        Assert.Equal("pending/handler_failed", await database.ScalarAsync<string>(
            "SELECT status || '/' || failure_code FROM job WHERE type = 'keys.tenant_keys.backfill'"));
    }

    [Fact]
    public void Backfill_is_a_Deployment_wide_type()
    {
        Assert.Equal("keys.tenant_keys.backfill", OperationsContract.BackfillTenantKeys.Value);
        Assert.Equal(JobScope.DeploymentWide, OperationsContract.ProductionRegistry.Find(OperationsContract.BackfillTenantKeys)!.Scope);
    }

    [Fact]
    public async Task Concurrent_provisioning_of_one_Tenant_creates_one_set()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync("concurrent.keys.test")).TenantId;

        // The first provisioner holds its first create until the second is waiting on the lock.
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var first = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker))
        {
            BeforeCreateAsync = async _ =>
            {
                entered.TrySetResult();
                await release.Task;
            },
        };
        using var second = new ControlledCustody(bao.Custody(OpenBaoFixture.Worker));

        var one = database.ProvisionAsync(bao, tenant, first);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(30), Cancellation);
        var two = database.ProvisionAsync(bao, tenant, second);

        // Deterministic: the second is blocked on the Tenant's advisory lock before the first goes on.
        for (var i = 0; i < 300 && await database.ScalarAsync<long>("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted") == 0; i++)
        {
            await Task.Delay(50, Cancellation);
        }

        Assert.Equal(1L, await database.ScalarAsync<long>("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted"));
        release.SetResult();

        Assert.True(await one);
        Assert.False(await two);
        Assert.Equal(0, second.Calls(KeyOperation.Create));
        Assert.Equal(NewTenantRows, await RowsAsync(database, tenant));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM protection_key_wrap WHERE tenant_id = '{tenant}'"));
        Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenant}' AND type_code = '{Provisioned}'"));
    }

    [Theory]
    [InlineData("signing_key", "INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version) SELECT id, tenant_id, purpose, 'previous', transit_name, transit_version FROM signing_key LIMIT 1")]
    [InlineData("signing_key", "UPDATE signing_key SET state = 'revoked'")]
    [InlineData("signing_key", "DELETE FROM signing_key")]
    [InlineData("protection_key_wrap", "UPDATE protection_key_wrap SET ciphertext = ciphertext")]
    [InlineData("protection_key_wrap", "DELETE FROM protection_key_wrap")]
    [InlineData("protection_key_wrap", "INSERT INTO protection_key_wrap (tenant_id, ciphertext) VALUES (current_setting('gatekeep.tenant_id')::uuid, 'vault:v1:AAAA')")]
    public async Task Hosted_can_only_read_the_key_tables(string table, string sql)
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database, TableRegistry.Hosted, tenant, sql));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, refused.SqlState);
        Assert.Contains(table, refused.MessageText, StringComparison.Ordinal);
    }

    // Story 2.4 lets the Worker move a row's state and lifecycle times, and nothing else.
    [Theory]
    [InlineData("UPDATE signing_key SET transit_name = transit_name")]
    [InlineData("UPDATE signing_key SET transit_version = transit_version")]
    [InlineData("UPDATE signing_key SET published_at = now()")]
    [InlineData("UPDATE signing_key SET created_at = now()")]
    [InlineData("UPDATE signing_key SET purpose = purpose")]
    [InlineData("UPDATE protection_key_wrap SET ciphertext = ciphertext")]
    public async Task Worker_never_changes_a_key_rows_identity_or_a_wrap(string sql)
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database, TableRegistry.Worker, tenant, sql));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, refused.SqlState);
    }

    // Story 9.2 lets Host.Admin rotate on demand: insert a next row and move state, promoted_at and
    // rotated_at. Never a retirement, a destruction, a deletion or a key row's identity.
    [Theory]
    [InlineData("DELETE FROM signing_key")]
    [InlineData("UPDATE signing_key SET retired_at = now()")]
    [InlineData("UPDATE signing_key SET destroyed_at = now()")]
    [InlineData("UPDATE signing_key SET transit_name = transit_name")]
    [InlineData("UPDATE signing_key SET published_at = now()")]
    [InlineData("UPDATE protection_key_wrap SET ciphertext = ciphertext")]
    public async Task Admin_never_retires_destroys_or_deletes_a_key_row(string sql)
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database, TableRegistry.Admin, tenant, sql));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, refused.SqlState);
    }

    // Story 1.29: the Worker deletes key rows only in a Tenant's deletion; for a live Tenant the trigger refuses (GK008).
    [Theory]
    [InlineData("DELETE FROM signing_key")]
    [InlineData("DELETE FROM protection_key_wrap")]
    public async Task Worker_never_deletes_a_live_Tenants_key_rows(string sql)
    {
        var (database, tenant) = await ProvisionedAsync();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => RunAsync(database, TableRegistry.Worker, tenant, sql));
        Assert.Equal("GK008", refused.SqlState);
    }

    [Fact]
    public async Task One_Tenants_scope_sees_none_of_anothers_key_rows()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = (await database.AddTenantAsync("a.rls.keys.test")).TenantId;
        var b = (await database.AddTenantAsync("b.rls.keys.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, a));
        Assert.True(await database.ProvisionAsync(bao, b));

        foreach (var role in new[] { TableRegistry.Hosted, TableRegistry.Worker })
        {
            Assert.Equal(
                $"4/1/0",
                await ScalarInScopeAsync(database, role, a, $"SELECT (SELECT count(*) FROM signing_key) || '/' || (SELECT count(*) FROM protection_key_wrap) || '/' || (SELECT count(*) FROM signing_key WHERE tenant_id = '{b}')"));
        }

        // The Hosted read API, in A's scope, returns A's signing keys only.
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, a, Cancellation);
        var published = await KeysContract.ReadPublishedSigningKeysAsync(scope.CreateCommandContext(), Cancellation);
        Assert.Equal(2, published.Count);
        Assert.All(published, k => Assert.StartsWith($"sig-{a:D}-", k.Key.Value, StringComparison.Ordinal));
        Assert.Equal([PublishedKeyState.Current, PublishedKeyState.Next], published.Select(k => k.State));
        Assert.NotNull(await KeysContract.ReadProtectionKeyWrapAsync(scope.CreateCommandContext(), Cancellation));
    }

    [Theory]
    [InlineData("current")]
    [InlineData("next")]
    public async Task A_second_current_or_next_per_purpose_is_refused(string state)
    {
        var (database, tenant) = await ProvisionedAsync();
        var id = Guid.CreateVersion7();

        var refused = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at, promoted_at) VALUES ('{id}', '{tenant}', 'signing', '{state}', 'sig-{tenant:D}-{id:D}', 1, now(), now())"));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, refused.SqlState);
    }

    [Theory]
    [InlineData("'management', 'next', 'mgmt-{0}-{1}', 1, now()", "signing_key_management_unpublished")]
    [InlineData("'signing', 'next', 'mgmt-{0}-{1}', 1, now()", "signing_key_transit_name")]
    [InlineData("'signing', 'next', 'sig-{0}-{2}', 1, now()", "signing_key_transit_name")]
    [InlineData("'signing', 'active', 'sig-{0}-{1}', 1, now()", "signing_key_state")]
    [InlineData("'encryption', 'next', 'sig-{0}-{1}', 1, now()", "signing_key_purpose")]
    [InlineData("'signing', 'next', 'sig-{0}-{1}', 1, NULL", "signing_key_signing_published")]
    [InlineData("'signing', 'next', 'sig-{0}-{1}', 0, now()", "signing_key_transit_version")]
    public async Task Constraints_refuse_a_malformed_key_row(string values, string constraint)
    {
        var (database, tenant) = await ProvisionedAsync();
        var id = Guid.CreateVersion7();
        var sql = string.Format(System.Globalization.CultureInfo.InvariantCulture, values, tenant, id, Guid.CreateVersion7());

        var refused = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at) VALUES ('{id}', '{tenant}', {sql})"));
        Assert.Equal(constraint, refused.ConstraintName);
    }

    [Fact]
    public async Task A_non_v7_id_and_a_plaintext_wrap_are_refused()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync("checks.keys.test")).TenantId;
        var v4 = Guid.NewGuid();

        var id = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync(
            $"INSERT INTO signing_key (id, tenant_id, purpose, state, transit_name, transit_version, published_at) VALUES ('{v4}', '{tenant}', 'signing', 'current', 'sig-{tenant:D}-{v4:D}', 1, now())"));
        Assert.Equal("signing_key_id_v7", id.ConstraintName);

        var wrap = await Assert.ThrowsAsync<PostgresException>(() => database.ExecuteAsync(
            $"INSERT INTO protection_key_wrap (tenant_id, ciphertext) VALUES ('{tenant}', '{Convert.ToBase64String(new byte[32])}')"));
        Assert.Equal("protection_key_wrap_ciphertext", wrap.ConstraintName);
    }

    [Fact]
    public void Public_half_decodes_from_SubjectPublicKeyInfo_and_PKCS1_without_the_PEM_import_APIs()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(3072);
        var expected = rsa.ExportParameters(includePrivateParameters: false);

        foreach (var pem in new[] { rsa.ExportSubjectPublicKeyInfoPem(), rsa.ExportRSAPublicKeyPem() })
        {
            var parsed = KeysContract.RsaPublicParameters(pem);
            Assert.True(expected.Modulus.AsSpan().SequenceEqual(parsed.Modulus), "The modulus differs.");
            Assert.True(expected.Exponent.AsSpan().SequenceEqual(parsed.Exponent), "The exponent differs.");
            Assert.Null(parsed.D);
        }

        Assert.Throws<FormatException>(() => KeysContract.RsaPublicParameters("not a key"));
        using var ec = System.Security.Cryptography.ECDsa.Create();
        Assert.Throws<FormatException>(() => KeysContract.RsaPublicParameters(ec.ExportSubjectPublicKeyInfoPem()));
        Assert.Throws<FormatException>(() => KeysContract.RsaPublicParameters(rsa.ExportRSAPrivateKeyPem()));
    }

    [Fact]
    public async Task Public_half_from_Transit_decodes_to_a_3072_bit_key()
    {
        var (database, tenant) = await ProvisionedAsync();
        using var hosted = bao.Custody(OpenBaoFixture.Hosted);

        foreach (var name in (await NamesAsync(database, tenant)).Where(n => n.StartsWith("sig-", StringComparison.Ordinal)))
        {
            var version = Assert.Single(await hosted.GetPublicKeysAsync(Parse(name), Cancellation));
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportFromPem(version.PublicKeyPem);

            var parsed = KeysContract.RsaPublicParameters(version.PublicKeyPem);
            Assert.Equal(384, parsed.Modulus!.Length);
            Assert.True(rsa.ExportParameters(false).Modulus.AsSpan().SequenceEqual(parsed.Modulus), "The modulus differs.");
        }
    }

    private async Task<(ProtocolDatabase Database, Guid Tenant)> ProvisionedAsync()
    {
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var tenant = (await database.AddTenantAsync($"t{Guid.NewGuid():N}.keys.test")).TenantId;
        Assert.True(await database.ProvisionAsync(bao, tenant));
        return (database, tenant);
    }

    private async Task RunAsync(ProtocolDatabase database, string role, Guid tenant, string sql)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(Cancellation);
    }

    private async Task<string> ScalarInScopeAsync(ProtocolDatabase database, string role, Guid tenant, string sql)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(role, database.Name));
        await using var scope = await TenantScope.BeginAsync(source, tenant, Cancellation);
        await using var command = scope.CreateCommandContext().CreateCommand();
        command.CommandText = sql;
        return (string)(await command.ExecuteScalarAsync(Cancellation))!;
    }

    private static async Task RunBackfillAsync(JobDatabase database, IKeyCustody? custody, Microsoft.Extensions.Logging.ILogger? logger)
    {
        await database.InScopeAsync(
            TableRegistry.Worker, null, "INSERT INTO job (id, type, deployment_wide) VALUES (gen_random_uuid(), 'keys.tenant_keys.backfill', true)");

        await using var runner = database.Runner(OperationsContract.ProductionRegistry, custody, logger);
        Assert.True(await runner.RunOnceAsync(Cancellation));
    }

    private static Task<string> RowsAsync(JobDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}'");

    private static Task<string> RowsAsync(ProtocolDatabase database, Guid tenant) =>
        database.ScalarAsync<string>(
            $"SELECT string_agg(purpose || '/' || state, ',' ORDER BY purpose, state) FROM signing_key WHERE tenant_id = '{tenant}'");

    private static async Task<List<string>> NamesAsync(JobDatabase database, Guid tenant)
    {
        var names = await database.ScalarAsync<string>(
            $"SELECT coalesce(string_agg(transit_name, ',' ORDER BY transit_name COLLATE \"C\"), '') FROM signing_key WHERE tenant_id = '{tenant}'");
        return [.. names.Split(',', StringSplitOptions.RemoveEmptyEntries)];
    }

    private static async Task<List<string>> NamesAsync(ProtocolDatabase database, Guid tenant) =>
        [.. (await database.KeyIdsAsync(tenant, "signing")).Concat(await database.KeyIdsAsync(tenant, "management")).Select(StripVersion)];

    private static string StripVersion(string kid) => kid[..kid.LastIndexOf(".v", StringComparison.Ordinal)];

    /// <summary>A Transit name back to its <see cref="KeyName"/>: <c>sig-</c> or <c>mgmt-</c>, then two UUIDs.</summary>
    private static KeyName Parse(string name)
    {
        var management = name.StartsWith("mgmt-", StringComparison.Ordinal);
        var rest = name[(management ? 5 : 4)..];
        var tenant = Guid.Parse(rest[..36]);
        var row = Guid.Parse(rest[37..]);
        return management ? KeyName.Management(tenant, row) : KeyName.Signing(tenant, row);
    }
}
