using System.Text.RegularExpressions;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Sessions.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Gatekeep.Tests.Architecture;
using Gatekeep.Tests.Isolation.Admins;
using Xunit;

namespace Gatekeep.Tests.Isolation.Audit;

/// <summary>
/// Story 7.8 and FR-40: each of the 11 Tenant Log classes is proved by a catalogued code, whose
/// flow a test runs and whose code it finds in the Tenant's Log, or is pending on a story that
/// exists in <c>sprint-status.yaml</c> and isn't done. A pending class whose story is done fails.
/// </summary>
public sealed class EventClassTests(PostgresFixture postgres)
{
    private const string Project = "tests/Isolation";
    private const string SprintStatus = "_bmad-output/implementation-artifacts/sprint-status.yaml";

    private static readonly Regex StatusLine = new(@"^  (?<key>[0-9][\w-]*):\s*(?<status>[\w-]+)\s*$", RegexOptions.Multiline | RegexOptions.Compiled);

    /// <summary>
    /// The flow that proves each mapped class: it runs the flow in a fresh database and returns the
    /// database and the Tenant whose Log must hold the class's code. A story that maps a class to a
    /// code adds its proof here, and removes the class's pending story in <see cref="AuditCatalogue"/>.
    /// </summary>
    private static readonly Dictionary<TenantLogClass, Func<PostgresFixture, Task<(string Database, Guid TenantId)>>> Proofs = new()
    {
        [TenantLogClass.SessionRevocation] = ProveSessionRevocationAsync,
        [TenantLogClass.TokenFamilyRevocation] = ProveTokenFamilyRevocationAsync,
        [TenantLogClass.CrossTenantRejection] = ProveClientCrossTenantRejectionAsync,
        [TenantLogClass.KeyOperation] = ProveKeyOperationAsync,
    };

    [Fact]
    public void Every_class_is_proved_by_a_catalogued_code_or_pending_on_a_story()
    {
        Assert.Empty(ClassProblems(AuditCatalogue.TenantLogClasses, Catalogue(), Proofs.Keys.Select(k => k.ToString())));
    }

    [Fact]
    public void Every_pending_story_exists_and_isnt_done()
    {
        Assert.Empty(PendingProblems(AuditCatalogue.TenantLogClasses, Statuses(File.ReadAllText(Path.Combine(BuildOutput.RepositoryRoot(), SprintStatus)))));
    }

    [Fact]
    public void The_two_classes_the_story_names_are_pending_on_16_8_and_17_2()
    {
        Assert.Equal("16.8", AuditCatalogue.TenantLogClasses.Single(c => c.Name == nameof(TenantLogClass.EmailChange)).PendingStory);
        Assert.Equal("17.2", AuditCatalogue.TenantLogClasses.Single(c => c.Name == nameof(TenantLogClass.ManagementApiGrant)).PendingStory);
    }

    [Fact]
    public async Task Each_proved_class_has_its_code_in_the_Tenants_Log()
    {
        var catalogue = Catalogue();

        foreach (var (logClass, prove) in Proofs)
        {
            var codes = AuditCatalogue.TenantLogClasses.Single(c => c.Name == logClass.ToString()).Codes(catalogue).ToList();
            Assert.NotEmpty(codes);

            var (database, tenantId) = await prove(postgres);
            var written = await PostgresFixture.ScalarAsync<long>(
                postgres.SuperuserConnection(database),
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenantId}' AND type_code IN ({string.Join(", ", codes.Select(c => $"'{c}'"))})");

            Assert.True(written > 0, $"{logClass}'s flow wrote none of {string.Join(", ", codes)} to the Tenant's Log.");
        }
    }

    /// <summary>
    /// Story 7.4's writer of the same class, beside Story 2.5's token-endpoint proof above: a refused
    /// Admin with no role in the path Tenant puts <c>admin.cross_tenant.rejected</c> on that Tenant's Log.
    /// </summary>
    [Fact]
    public async Task A_refused_role_less_Admin_writes_the_cross_Tenant_class_to_the_Tenants_Log()
    {
        var (database, tenantId) = await ProveAdminCrossTenantRejectionAsync(postgres);
        var written = await PostgresFixture.ScalarAsync<long>(
            postgres.SuperuserConnection(database),
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{tenantId}' AND type_code = '{Gatekeep.Modules.Admins.Contracts.AdminsEvents.CrossTenantRejected.Code.Value}'");
        Assert.Equal(1L, written);
    }

    [Fact]
    public void Pending_class_whose_story_is_done_is_reported()
    {
        LogClass[] classes = [new("EmailChange", "Email changes", "16.8")];

        var problem = Assert.Single(PendingProblems(classes, new Dictionary<string, string> { ["16-8-change-an-email-address-safely"] = "done" }));

        Assert.Equal("Email changes is pending on Story 16.8, which is done: map the class to its code or name the story that will.", problem);
    }

    [Fact]
    public void Pending_class_whose_story_is_missing_is_reported()
    {
        LogClass[] classes = [new("EmailChange", "Email changes", "16.99")];

        var problem = Assert.Single(PendingProblems(classes, new Dictionary<string, string> { ["16-8-change-an-email-address-safely"] = "backlog" }));

        Assert.Equal("Email changes is pending on Story 16.99, which isn't in sprint-status.yaml.", problem);
    }

    [Fact]
    public void Class_with_no_code_and_no_story_is_reported()
    {
        LogClass[] classes = [new("SignIn", "Sign-ins and failures", null)];

        var problem = Assert.Single(ClassProblems(classes, [], []));

        Assert.Equal("Sign-ins and failures has no catalogued code and no pending story.", problem);
    }

    [Fact]
    public void Class_both_mapped_and_pending_or_mapped_with_no_proof_is_reported()
    {
        LogClass[] classes = [new("SignIn", "Sign-ins and failures", "4.9")];
        CatalogueEvent[] events = [new("auth.signin.succeeded", "Authentication", "A User signed in.", "SignIn", "Success")];

        var problems = ClassProblems(classes, events, []);

        Assert.Equal(
            new[]
            {
                "Sign-ins and failures is mapped to auth.signin.succeeded and still pending on Story 4.9: remove the pending story.",
                "Sign-ins and failures is mapped to auth.signin.succeeded but no test proves it: add its flow to EventClassTests.Proofs.",
            },
            problems);
    }

    [Fact]
    public void Sprint_status_lines_are_read()
    {
        var statuses = Statuses(
            """
            development_status:
              epic-16: backlog
              16-8-change-an-email-address-safely: backlog
              7-3-verify-chains-and-apply-retention: done
              epic-7-retrospective: optional
            """);

        Assert.Equal("backlog", statuses["16-8-change-an-email-address-safely"]);
        Assert.Equal("done", statuses["7-3-verify-chains-and-apply-retention"]);
        Assert.DoesNotContain("epic-16", statuses.Keys);
    }

    private static IReadOnlyList<CatalogueEvent> Catalogue() => AuditCatalogue.Load(BuildOutput.RepositoryRoot(), Project);

    private static List<string> ClassProblems(
        IEnumerable<LogClass> classes,
        IReadOnlyList<CatalogueEvent> events,
        IEnumerable<string> proved)
    {
        var proofs = proved.ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();

        foreach (var logClass in classes)
        {
            var codes = logClass.Codes(events).ToList();
            var mapped = string.Join(", ", codes);

            if (codes.Count == 0 && logClass.PendingStory is null)
            {
                problems.Add($"{logClass.Title} has no catalogued code and no pending story.");
            }

            if (codes.Count > 0 && logClass.PendingStory is { } story)
            {
                problems.Add($"{logClass.Title} is mapped to {mapped} and still pending on Story {story}: remove the pending story.");
            }

            if (codes.Count > 0 && !proofs.Contains(logClass.Name))
            {
                problems.Add($"{logClass.Title} is mapped to {mapped} but no test proves it: add its flow to EventClassTests.Proofs.");
            }
        }

        return problems;
    }

    /// <summary>Each pending story must be a story key in the sprint status, and not <c>done</c>.</summary>
    private static List<string> PendingProblems(IEnumerable<LogClass> classes, IReadOnlyDictionary<string, string> statuses)
    {
        var problems = new List<string>();

        foreach (var logClass in classes)
        {
            if (logClass.PendingStory is not { } story)
            {
                continue;
            }

            var prefix = story.Replace('.', '-') + "-";
            var matches = statuses.Where(s => s.Key.StartsWith(prefix, StringComparison.Ordinal)).ToList();

            if (matches.Count != 1)
            {
                problems.Add($"{logClass.Title} is pending on Story {story}, which isn't in sprint-status.yaml.");
            }
            else if (matches[0].Value == "done")
            {
                problems.Add($"{logClass.Title} is pending on Story {story}, which is done: map the class to its code or name the story that will.");
            }
        }

        return problems;
    }

    /// <summary>Story keys, such as <c>16-8-change-an-email-address-safely</c>, and their status. Epics and retrospectives aren't stories.</summary>
    private static Dictionary<string, string> Statuses(string yaml) =>
        StatusLine.Matches(yaml.ReplaceLineEndings("\n"))
            .Where(m => Regex.IsMatch(m.Groups["key"].Value, @"\A\d+-\d+-"))
            .ToDictionary(m => m.Groups["key"].Value, m => m.Groups["status"].Value, StringComparer.Ordinal);

    /// <summary>
    /// Story 7.4, over HTTP on the real Host.Admin: an Admin holding a role only in Tenant A calls a
    /// Tenant B route, is refused, and B's own Log holds <c>admin.cross_tenant.rejected</c>.
    /// </summary>
    private static async Task<(string Database, Guid TenantId)> ProveAdminCrossTenantRejectionAsync(PostgresFixture postgres)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, session) = await host.InsertFullSessionAsync();
        var admin = await host.AdminOfSessionAsync(session);
        var a = await host.InsertTenantAsync();
        var b = await host.InsertTenantAsync();
        await host.GrantTenantRoleAsync(a, admin, "owner");

        using var refused = await host.SendAsync(
            HttpMethod.Get, $"/api/v1/tenants/{PublicId.Format(PublicIdType.Tenant, b)}/capabilities", cookie);
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, refused.StatusCode);

        return (host.Database, b);
    }

    /// <summary>
    /// Story 9.2, over HTTP on the real Host.Admin: the Tenant Owner rotates the Signing Key on demand, which
    /// writes <c>keys.signing_key.rotated</c>, <c>promoted</c> and <c>created</c> on the Tenant's own Log.
    /// <c>SigningKeyRotateNowTests</c> and <c>SigningKeyRotateApiTests</c> cover the rotation itself.
    /// </summary>
    private static async Task<(string Database, Guid TenantId)> ProveKeyOperationAsync(PostgresFixture postgres)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        _ = new Gatekeep.Tests.Isolation.Keys.PublicHalves(host);
        var (cookie, csrf, session) = await host.InsertFullSessionAsync();
        var admin = await host.AdminOfSessionAsync(session);
        var tenant = Guid.CreateVersion7();
        await TestTenants.InsertAsync(host.Superuser, tenant, TestTenants.Host(tenant));
        await Gatekeep.Tests.Isolation.Keys.SigningKeySeeds.FreshAsync(host.Superuser, tenant);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "SET session_replication_role = replica; "
            + $"UPDATE signing_key SET published_at = now() - interval '20 minutes' WHERE tenant_id = '{tenant}' AND purpose = 'signing' AND state = 'next'; "
            + "SET session_replication_role = DEFAULT");
        await host.GrantTenantRoleAsync(tenant, admin, "owner");

        var id = PublicId.Format(PublicIdType.Tenant, tenant);
        using var rotated = await host.SendAsync(
            HttpMethod.Post, $"/api/v1/tenants/{id}/signing-keys/rotate", cookie, csrf, AdminHost.Origin, headers: [("X-Gatekeep-Tenant", id)]);
        Assert.Equal(System.Net.HttpStatusCode.OK, rotated.StatusCode);

        return (host.Database, tenant);
    }

    /// <summary>Story 2.7: a Tenant-scope <c>RevokeAccessAsync</c> as <c>gk_hosted</c> writes <c>sessions.access.revoked</c>.</summary>
    private static async Task<(string Database, Guid TenantId)> ProveSessionRevocationAsync(PostgresFixture postgres)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenantId = Guid.CreateVersion7();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(tenantId));

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, CancellationToken.None);
        var sessions = SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System);

        await sessions.RevokeAccessAsync(
            scope.CreateCommandContext(),
            new RevocationScope.Tenant(),
            exceptSessionId: null,
            RevocationReason.AdminRevoke,
            Actor.System,
            CancellationToken.None);
        await scope.CommitAsync(CancellationToken.None);

        return (database, tenantId);
    }

    /// <summary>
    /// Story 2.10: a rotated refresh token presented again. OpenIddict finds it redeemed and asks the token
    /// store, as <c>gk_hosted</c>, to revoke its family. The store revokes it through the one revocation
    /// path, which writes <c>sessions.access.revoked</c>. <c>RefreshTokenTests</c> drives the same path
    /// end to end through the token endpoint.
    /// </summary>
    private static async Task<(string Database, Guid TenantId)> ProveTokenFamilyRevocationAsync(PostgresFixture postgres)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenantId = Guid.CreateVersion7();
        var user = Guid.CreateVersion7();
        var session = Guid.CreateVersion7();
        var family = Guid.CreateVersion7();
        var referenceId = new string('A', 43) + "=";
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(tenantId));
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            $"""
            INSERT INTO "user" (tenant_id, id) VALUES ('{tenantId}', '{user}');
            INSERT INTO user_session (tenant_id, id, user_id, id_hash, amr, auth_time, idle_expires_at, absolute_expires_at, created_at)
            VALUES ('{tenantId}', '{session}', '{user}', decode(repeat('01', 32), 'hex'), ARRAY['test'], now(), now() + interval '1 day', now() + interval '2 days', now());
            INSERT INTO "authorization" (tenant_id, id, user_session_id, status, type, creation_date, concurrency_token)
            VALUES ('{tenantId}', '{family}', '{session}', 'valid', 'ad-hoc', now(), gen_random_uuid());
            INSERT INTO token (tenant_id, id, authorization_id, type, status, reference_id, redemption_date, concurrency_token)
            VALUES ('{tenantId}', gen_random_uuid(), '{family}', 'urn:ietf:params:oauth:token-type:refresh_token', 'redeemed', '{referenceId}', now(), gen_random_uuid());
            """);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Hosted, database));
        await using var scope = await TenantScope.BeginAsync(source, tenantId, CancellationToken.None);
        var context = scope.CreateCommandContext();
        var store = SessionsContract.CreateTokenStore(
            new StoreRequest(() => context, _ => { }, () => { }),
            SessionsContract.CreateSessions(AuditContract.CreateAppender(), TimeProvider.System));

        Assert.NotNull(await store.FindByReferenceIdAsync(referenceId, CancellationToken.None));
        Assert.Equal(1L, await store.RevokeByAuthorizationIdAsync(family.ToString(), CancellationToken.None));
        await scope.CommitAsync(CancellationToken.None);

        return (database, tenantId);
    }

    /// <summary>
    /// Story 2.5: Tenant A's valid client credential, presented at Tenant B's token endpoint through the
    /// real Protocol pipeline, writes <c>protocol.client.cross_tenant_rejected</c> to B's Log. Neither
    /// Tenant has keys: the attempt is refused before anything would sign.
    /// </summary>
    private static async Task<(string Database, Guid TenantId)> ProveClientCrossTenantRejectionAsync(PostgresFixture postgres)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), a, "a.proof.test");
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), b, "b.proof.test");

        string clientId;
        string secret;
        await using (var admin = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database)))
        await using (var scope = await TenantScope.BeginAsync(admin, a, CancellationToken.None))
        {
            var created = await Gatekeep.Modules.Directory.Contracts.DirectoryContract.CreateDirectory(AuditContract.CreateAppender(), TimeProvider.System)
                .CreateMachineClientAsync(scope.CreateCommandContext(), "Proof client", CancellationToken.None);
            await scope.CommitAsync(CancellationToken.None);
            clientId = created.ClientId;
            secret = created.Secret.Use(static s => s);
        }

        var hosted = postgres.RoleConnection(TableRegistry.Hosted, database);
        var builder = Microsoft.AspNetCore.Builder.WebApplication.CreateSlimBuilder();
        Microsoft.AspNetCore.TestHost.WebHostBuilderExtensions.UseTestServer(builder.WebHost);
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(AuditContract.CreateAppender());
        builder.Services.AddSingleton<Gatekeep.Modules.Protocol.Contracts.IAuthorizationSignIn, Gatekeep.Modules.Protocol.Contracts.UnavailableSignIn>();
        Gatekeep.Modules.Protocol.Contracts.ProtocolContract.AddGatekeepProtocol(builder.Services, _ => hosted, Gatekeep.Adapters.Hosting.SecurityHeaders.Apply);

        await using var app = builder.Build();
        Gatekeep.Modules.Tenancy.Contracts.TenancyContract.UseTenantResolution(app, () => hosted);
        Gatekeep.Modules.Protocol.Contracts.ProtocolContract.UseGatekeepProtocol(app);
        await app.StartAsync(CancellationToken.None);

        using var http = Microsoft.AspNetCore.TestHost.HostBuilderTestServerExtensions.GetTestClient(app);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
        });
        using var response = await http.PostAsync(new Uri("http://b.proof.test" + Gatekeep.Modules.Protocol.Contracts.ProtocolContract.TokenPath), content);
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
        await app.StopAsync(CancellationToken.None);

        return (database, b);
    }
}
