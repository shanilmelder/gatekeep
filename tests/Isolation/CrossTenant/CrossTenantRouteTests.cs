using System.Net;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Gatekeep.Modules.Protocol.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Protocol;
using Gatekeep.Tests.Isolation.Tenancy;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gatekeep.Tests.Isolation.CrossTenant;

/// <summary>
/// One real Host.Admin on its own migrated database, with two active Tenants, A and B, shared by
/// every Admin case of <see cref="CrossTenantRouteTests"/>. Each case makes its own Admin, so the
/// per-Admin denial audit cap (Story 1.24) never counts one case against another.
/// </summary>
public sealed class CrossTenantAdmin(PostgresFixture postgres) : IAsyncLifetime
{
    private AdminHost? _host;

    internal AdminHost Host => _host ?? throw new InvalidOperationException("The Admin host isn't started.");

    public Guid TenantA { get; private set; }

    public Guid TenantB { get; private set; }

    public async ValueTask InitializeAsync()
    {
        _host = await AdminHost.StartAsync(postgres);
        TenantA = await TenantRequests.InsertAsync(_host, name: "Tenant A");
        TenantB = await TenantRequests.InsertAsync(_host, name: "Tenant B");
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }
    }
}

/// <summary>
/// Story 1.31 (FR-8, AD-4, AD-9, AD-19, AD-25, SM-2): the cross-Tenant case of every
/// <see cref="RouteRegistry"/> entry, driven from the registry, so a new entry runs its case with no
/// new test code. An Admin route naming Tenant B, called by an Admin who holds Owner in Tenant A
/// only and isn't the Deployment Owner, is refused with 403 <c>access_denied</c> and writes exactly
/// one <c>admin.access.denied</c> and nothing else, and B is unchanged. A <see cref="CaseKind.TargetTenant"/>
/// route is refused by Deployment Owner gating, so the same Admin gets the identical refusal for its
/// own Tenant A: those cases prove the Owner gate, and their event names no target Tenant (AD-19:
/// only <c>{tenantId}</c> names a path Tenant; the Tenant's own Log is Story 7.4). A Hosted route
/// asked on B's host answers with B's issuer and keys only, and the token endpoint refuses.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class CrossTenantRouteTests(PostgresFixture postgres, OpenBaoFixture bao, CrossTenantAdmin admin)
    : IClassFixture<CrossTenantAdmin>
{
    private const string HostA = "acme.cross-tenant.test";
    private const string HostB = "beta.cross-tenant.test";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    public static TheoryData<string, string> AdminCases() => Cases(RouteRegistry.Admin, CaseKind.TenantPath, CaseKind.TargetTenant);

    public static TheoryData<string, string> HostedCases() => Cases(RouteRegistry.Hosted, CaseKind.HostResolved);

    [Fact]
    public void The_registry_has_Admin_and_Hosted_cases_to_run()
    {
        // The theories below run these; an empty set would pass them vacuously.
        Assert.NotEmpty(AdminCases());
        Assert.NotEmpty(HostedCases());
    }

    [Theory]
    [MemberData(nameof(AdminCases))]
    public async Task Admin_route_naming_Tenant_B_is_refused_and_audited_for_an_Owner_of_Tenant_A_only(string method, string pattern)
    {
        var entry = RouteRegistry.Admin.Single(e => e.Method == method && e.Pattern == pattern);
        var host = admin.Host;
        var (cookie, csrf, adminId) = await TenantRequests.RoleSessionAsync(host, admin.TenantA, "owner");
        Assert.False(await host.ScalarAsync<bool>($"SELECT deployment_owner FROM admin WHERE id = '{adminId}'"));
        var tenantB = PublicId.Format(PublicIdType.Tenant, admin.TenantB);
        var before = await StateOfBAsync(adminId);

        var path = PathFor(entry, tenantB);
        var stateChanging = method is not ("GET" or "HEAD");
        using var response = await host.SendAsync(
            new HttpMethod(method),
            path,
            cookie,
            stateChanging ? csrf : null,
            stateChanging ? AdminHost.Origin : null,
            entry.Body,
            headers: [(TenantRequests.Header, tenantB)]);

        Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{entry} at Tenant B answered {(int)response.StatusCode}.");
        Assert.Equal("access_denied", await TenantRequests.CodeAsync(response));

        // Exactly one event from this Admin: the refusal, on the Deployment chain.
        Assert.Equal(
            "1 admin.access.denied",
            await host.ScalarAsync<string>(
                $"SELECT count(*) || ' ' || coalesce(min(type_code), '') FROM deployment_audit_event WHERE actor_id = '{adminId}'"));
        var target = await host.ScalarAsync<string>(
            $"SELECT coalesce(target_kind || ' ' || target_id, 'none') FROM deployment_audit_event WHERE actor_id = '{adminId}'");
        Assert.Equal(
            entry.Kind == CaseKind.TenantPath
                ? $"tenant {admin.TenantB}"

                // A Deployment route's Tenant is never a path Tenant (AD-19), so its refusal targets none.
                : "none",
            target);

        // A Tenant-path refusal also goes on Tenant B's own Log, once, with this Admin as Actor (Story
        // 7.4, AD-9); a Deployment route has no path Tenant, so B's Log holds none from it.
        Assert.Equal(
            entry.Kind == CaseKind.TenantPath ? 1L : 0L,
            await host.ScalarAsync<long>(
                $"SELECT count(*) FROM audit_event WHERE tenant_id = '{admin.TenantB}' AND type_code = 'admin.cross_tenant.rejected' AND actor_id = '{adminId}'"));

        // Nothing else reached Tenant B or its Log.
        Assert.Equal(before, await StateOfBAsync(adminId));

        if (entry.Kind == CaseKind.TargetTenant)
        {
            // Deployment Owner gating refuses it, whatever the target: the same refusal for the
            // Admin's own Tenant A, so these cases prove the Owner gate, not a Tenant check.
            var tenantA = PublicId.Format(PublicIdType.Tenant, admin.TenantA);
            using var own = await host.SendAsync(
                new HttpMethod(method),
                PathFor(entry, tenantA),
                cookie,
                stateChanging ? csrf : null,
                stateChanging ? AdminHost.Origin : null,
                entry.Body,
                headers: [(TenantRequests.Header, tenantA)]);
            Assert.True(own.StatusCode == HttpStatusCode.Forbidden, $"{entry} at Tenant A answered {(int)own.StatusCode}.");
            Assert.Equal("access_denied", await TenantRequests.CodeAsync(own));
            Assert.Equal(
                2L,
                await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE actor_id = '{adminId}' AND type_code = 'admin.access.denied' AND target_id IS NULL"));
        }
    }

    [Theory]
    [MemberData(nameof(HostedCases))]
    public async Task Hosted_route_on_Tenant_B_s_host_carries_only_Tenant_B(string method, string pattern)
    {
        var entry = RouteRegistry.Hosted.Single(e => e.Method == method && e.Pattern == pattern);
        var database = await ProtocolDatabase.CreateAsync(postgres);
        var a = await database.AddTenantAsync(HostA);
        var b = await database.AddTenantAsync(HostB);
        Assert.True(await database.ProvisionAsync(bao, a.TenantId));
        Assert.True(await database.ProvisionAsync(bao, b.TenantId));
        // The test-only credential step authenticates only an identifier of its own form (Story 4.2), so it changes
        // nothing for a case that names none.
        await using var host = await ProtocolHost.StartAsync(database.Hosted, bao);

        switch (entry.Pattern)
        {
            case ProtocolContract.ConfigurationPath:
            {
                using var response = await host.Http.GetAsync(new Uri($"http://{HostB}{entry.Pattern}"), Cancellation);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                using var document = JsonDocument.Parse(body);
                Assert.Equal(b.Issuer, document.RootElement.GetProperty("issuer").GetString());
                Assert.Equal($"{b.Issuer}.well-known/jwks", document.RootElement.GetProperty("jwks_uri").GetString());
                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                break;
            }

            case ProtocolContract.JsonWebKeySetPath:
            {
                using var response = await host.Http.GetAsync(new Uri($"http://{HostB}{entry.Pattern}"), Cancellation);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                using var document = JsonDocument.Parse(body);
                var kids = document.RootElement.GetProperty("keys").EnumerateArray().Select(k => k.GetProperty("kid").GetString()!).Order(StringComparer.Ordinal).ToList();
                Assert.Equal(await database.KeyIdsAsync(b.TenantId, "signing"), kids);
                Assert.Empty(kids.Intersect(await database.KeyIdsAsync(a.TenantId, "signing")));
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                break;
            }

            case ProtocolContract.TokenPath:
            {
                // Tenant A's real machine client, presented at B's host by Basic and by post: refused
                // with invalid_client, nothing issued, and the rejection logged in B's Log only, naming
                // nothing of A (Story 2.5).
                var client = await database.CreateClientAsync(a.TenantId);
                var eventsA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'");
                foreach (var how in new[] { "basic", "post" })
                {
                    using var refused = await ClientCredentialsTests.TokenAsync(host, HostB, client.ClientId, client.Secret, how);
                    Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
                    Assert.Equal("invalid_client", refused.Error);
                }

                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
                Assert.Equal(2L, await database.ScalarAsync<long>(
                    $"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}' AND type_code = 'protocol.client.cross_tenant_rejected' AND actor_kind = 'anonymous' AND target_id IS NULL"));
                Assert.Equal(eventsA, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'"));
                break;
            }

            case ProtocolContract.AuthorizePath:
            {
                // Tenant A's real web client, at B's host (Story 2.9): B doesn't know it, so the request gets
                // Generic error (Story 4.1), never a redirect to A's client or to Login, and naming nothing of A. Nothing begins.
                var client = await database.CreateWebClientAsync(a.TenantId, [CodeFlowSetup.Callback]);
                var user = await database.AddUserAsync(a.TenantId);
                using var response = await CodeFlow.AuthorizeAsync(host, HostB, client.ClientId, CodeFlowSetup.Callback, Pkce.New(), user, state: "cross-tenant");
                await StepPage.AssertGenericErrorAsync(response, ProtocolDatabase.TestTenantName);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(client.ClientId, body, StringComparison.Ordinal);
                Assert.DoesNotContain("cross-tenant", body, StringComparison.Ordinal);
                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM signin_transaction"));
                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM token"));
                break;
            }

            case ProtocolContract.UserinfoPath:
            {
                // Tenant A's real access token, from A's code flow, as a bearer at B's userinfo (Story 2.11): B's keys
                // don't verify it, so it is invalid_token and answers nothing of A's User.
                var flow = await CodeFlowWithin(database, a, b);
                var tokens = await UserinfoAndRevocationTests.TokensAsync(host, flow, HostA, "openid");
                using var response = await UserinfoAndRevocationTests.UserinfoAsync(host, HostB, tokens.Access);
                Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
                Assert.Contains("error=\"invalid_token\"", response.WwwAuthenticate, StringComparison.Ordinal);
                Assert.DoesNotContain(PublicId.Format(PublicIdType.User, flow.UserA), response.Body, StringComparison.Ordinal);
                break;
            }

            case ProtocolContract.RevocationPath:
            {
                // Tenant A's real refresh token, revoked at B by B's own client (Story 2.11): refused before any lookup,
                // answered 200 as RFC 7009 asks, logged once in B's Log, and A's token still refreshes at A.
                var flow = await CodeFlowWithin(database, a, b);
                var clientB = await database.CreateWebClientAsync(b.TenantId, [CodeFlowSetup.Callback]);
                var tokens = await UserinfoAndRevocationTests.TokensAsync(host, flow, HostA, "openid offline_access");
                using (var response = await UserinfoAndRevocationTests.RevokeAsync(host, HostB, clientB.ClientId, clientB.Secret, tokens.Refresh))
                {
                    Assert.Equal(HttpStatusCode.OK, response.Status);
                }

                Assert.Equal(1L, await database.ScalarAsync<long>(
                    $"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}' AND type_code = 'protocol.client.cross_tenant_rejected' AND actor_kind = 'anonymous' AND target_id IS NULL"));
                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code = 'sessions.access.revoked'"));
                using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, tokens.Refresh);
                Assert.Equal(HttpStatusCode.OK, refreshed.Status);
                break;
            }

            case ProtocolContract.LoginPath:
            case ProtocolContract.LoginIdentifierPath:
            case ProtocolContract.LoginExtendPath:
            case ProtocolContract.SignupOpenPath:
            case ProtocolContract.SignupBackPath:
            case ProtocolContract.SignupPath:
            case ProtocolContract.VerificationResendPath:
            case ProtocolContract.VerificationContinuePath:
            case ProtocolContract.PasswordPath:
            case ProtocolContract.PasswordBackPath:
            case ProtocolContract.ResetOpenPath:
            case ProtocolContract.ResetPath:
            case ProtocolContract.ResetBackPath:
            {
                // Tenant A's real sign-in transaction cookie, presented at B's host (Story 4.2): B's lookup, under B's
                // row-level security, finds nothing, so it is refused as invalid_transaction, the refusal logged in B's
                // Log only, and A's transaction is untouched. The CSRF token is the cookie's own, so only the lookup refuses.
                var client = await database.CreateWebClientAsync(a.TenantId, [CodeFlowSetup.Callback]);
                var atA = new HostedBrowser(host, HostA);
                using (var begun = await atA.GetAsync(CodeFlow.AuthorizeUrl(client.ClientId, CodeFlowSetup.Callback, Pkce.New())))
                {
                    Assert.True(HostedBrowser.IsLoginRedirect(begun), "A's request didn't go to Login.");
                }

                var atB = new HostedBrowser(host, HostB);
                atB.Cookies[ProtocolContract.TransactionCookie] = atA.Cookies[ProtocolContract.TransactionCookie];
                var csrf = (await atA.LoginStepAsync()).Csrf;
                var before = await database.ScalarAsync<string>("SELECT tenant_id || '/' || expires_at::text || '/' || step_version FROM signin_transaction");
                var eventsA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'");

                using var response = entry.Pattern == ProtocolContract.LoginPath
                    ? await atB.GetAsync(ProtocolContract.LoginPath)
                    : await atB.PostAsync(entry.Pattern, new { stepVersion = 1, email = "someone@example.com", password = "Correct-Horse-7battery" }, csrf);
                string body;
                if (entry.Pattern == ProtocolContract.LoginPath)
                {
                    await StepPage.AssertGenericErrorAsync(response, ProtocolDatabase.TestTenantName, "invalid_transaction");
                    body = await response.Content.ReadAsStringAsync(Cancellation);
                }
                else
                {
                    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                    body = await response.Content.ReadAsStringAsync(Cancellation);
                    using var step = JsonDocument.Parse(body);
                    Assert.Equal("invalid_transaction", step.RootElement.GetProperty("data").GetProperty("code").GetString());
                }

                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(before, await database.ScalarAsync<string>("SELECT tenant_id || '/' || expires_at::text || '/' || step_version FROM signin_transaction"));
                Assert.Equal(1L, await database.ScalarAsync<long>(
                    $"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}' AND type_code = 'authentication.signin_transaction.refused'"));
                Assert.Equal(eventsA, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'"));
                Assert.All(atB.SetCookies, c => Assert.DoesNotContain("Domain", c, StringComparison.OrdinalIgnoreCase));
                break;
            }

            case ProtocolContract.VerifyEmailPath:
            case ProtocolContract.VerificationNewLinkPath:
            {
                // Tenant A's real verification link, from a sign-up at A (Story 4.7), at B's host: refused by its prefix
                // before any lookup, as Link expired, or for "Send a new link" the neutral answer with nothing sent. Neither
                // Tenant changes, B logs nothing of A, and the link still verifies at A.
                await database.ExecuteAsync(
                    $"INSERT INTO connection (tenant_id, id, kind) VALUES ('{a.TenantId}', gen_random_uuid(), 'database'), ('{b.TenantId}', gen_random_uuid(), 'database')");
                await ProtocolDatabase.ProvisionSecretClassesAsync(bao, a.TenantId);
                var client = await database.CreateWebClientAsync(a.TenantId, [CodeFlowSetup.Callback]);
                var atA = new HostedBrowser(host, HostA);
                using (var begun = await atA.GetAsync(CodeFlow.AuthorizeUrl(client.ClientId, CodeFlowSetup.Callback, Pkce.New())))
                {
                    Assert.True(HostedBrowser.IsLoginRedirect(begun), "A's request didn't go to Login.");
                }

                var login = await atA.LoginStepAsync();
                using (var opened = await atA.PostAsync(ProtocolContract.SignupOpenPath, new { stepVersion = login.StepVersion, email = "a.user@example.com" }, login.Csrf))
                using (var created = await atA.PostAsync(
                    ProtocolContract.SignupPath,
                    new { stepVersion = login.StepVersion + 1, email = "a.user@example.com", password = "Correct-Horse-7battery" },
                    login.Csrf))
                {
                    using var step = await HostedBrowser.StepAsync(created);
                    Assert.Equal(StepNames.VerifyEmail, step.RootElement.GetProperty("step").GetString());
                }

                var link = host.Jobs.LastLink();
                var rowsA = await database.ScalarAsync<string>(
                    $"SELECT string_agg(to_jsonb(t)::text, ';') FROM one_time_token t WHERE tenant_id = '{a.TenantId}'");
                var eventsA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'");
                var eventsB = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}'");
                var jobs = host.Jobs.Jobs.Count;

                var atB = new HostedBrowser(host, HostB);
                string body;
                if (entry.Pattern == ProtocolContract.VerifyEmailPath)
                {
                    using var page = await atB.GetAsync($"{ProtocolContract.VerifyEmailPath}?token={Uri.EscapeDataString(link)}");
                    Assert.Equal(HttpStatusCode.OK, page.StatusCode);
                    body = await page.Content.ReadAsStringAsync(Cancellation);
                    using var step = StepPage.Read(body);
                    Assert.Equal(StepNames.LinkExpired, step.RootElement.GetProperty("step").GetString());
                }
                else
                {
                    using var response = await atB.PostAsync(ProtocolContract.VerificationNewLinkPath, new { token = link }, Gatekeep.Tests.Isolation.Identity.SignUpFlow.LinkCsrf(link));
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    body = await response.Content.ReadAsStringAsync(Cancellation);
                    using var step = JsonDocument.Parse(body);
                    Assert.Equal(StepNames.LinkSent, step.RootElement.GetProperty("step").GetString());
                }

                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(jobs, host.Jobs.Jobs.Count);
                Assert.Equal(rowsA, await database.ScalarAsync<string>(
                    $"SELECT string_agg(to_jsonb(t)::text, ';') FROM one_time_token t WHERE tenant_id = '{a.TenantId}'"));
                Assert.Equal(eventsA, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'"));
                Assert.Equal(eventsB, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}'"));
                Assert.Empty(atB.SetCookies);

                using (var verified = await new HostedBrowser(host, HostA).GetAsync($"{ProtocolContract.VerifyEmailPath}?token={Uri.EscapeDataString(link)}"))
                using (var step = StepPage.Read(await verified.Content.ReadAsStringAsync(Cancellation)))
                {
                    Assert.Equal(StepNames.EmailVerified, step.RootElement.GetProperty("step").GetString());
                }

                break;
            }

            case ProtocolContract.ResetPasswordPath:
            case ProtocolContract.ResetCompletePath:
            case ProtocolContract.ResetNewLinkPath:
            {
                // Tenant A's real reset link, from a reset request at A (Story 4.11), at B's host: refused by its prefix
                // before any lookup, as Link expired, or for "Send a new link" the neutral answer with nothing sent. Neither
                // Tenant changes, B logs nothing of A, and the link still opens Reset password at A.
                await database.ExecuteAsync(
                    $"INSERT INTO connection (tenant_id, id, kind) VALUES ('{a.TenantId}', gen_random_uuid(), 'database'), ('{b.TenantId}', gen_random_uuid(), 'database')");
                await ProtocolDatabase.ProvisionSecretClassesAsync(bao, a.TenantId);
                var hash = await Gatekeep.Modules.Authentication.Contracts.AuthenticationContract.HashPasswordAsync(
                    new Gatekeep.Kernel.Secrets.Secret<string>("Correct-Horse-7battery"));
                await database.ExecuteAsync(
                    $"WITH u AS (INSERT INTO \"user\" (tenant_id, id, email, email_verified_at) VALUES ('{a.TenantId}', gen_random_uuid(), 'a.user@example.com', now()) RETURNING id) "
                    + "INSERT INTO password_credential (tenant_id, id, user_id, connection_id, password_hash, status) "
                    + $"SELECT '{a.TenantId}', gen_random_uuid(), u.id, c.id, '{hash}', 'active' FROM u, connection c WHERE c.tenant_id = '{a.TenantId}'");
                var client = await database.CreateWebClientAsync(a.TenantId, [CodeFlowSetup.Callback]);
                var atA = new HostedBrowser(host, HostA);
                using (var begun = await atA.GetAsync(CodeFlow.AuthorizeUrl(client.ClientId, CodeFlowSetup.Callback, Pkce.New())))
                {
                    Assert.True(HostedBrowser.IsLoginRedirect(begun), "A's request didn't go to Login.");
                }

                var login = await atA.LoginStepAsync();
                using (var identified = await atA.PostAsync(ProtocolContract.LoginIdentifierPath, new { stepVersion = login.StepVersion, email = "a.user@example.com" }, login.Csrf))
                using (var opened = await atA.PostAsync(ProtocolContract.ResetOpenPath, new { stepVersion = login.StepVersion + 1 }, login.Csrf))
                using (var requested = await atA.PostAsync(ProtocolContract.ResetPath, new { stepVersion = login.StepVersion + 2, email = "a.user@example.com" }, login.Csrf))
                {
                    using var step = await HostedBrowser.StepAsync(requested);
                    Assert.Equal(StepNames.LinkSent, step.RootElement.GetProperty("step").GetString());
                }

                var link = host.Jobs.Jobs.Last(j => j.TemplateId == Gatekeep.Modules.Notifications.Contracts.NotificationsContract.PasswordResetTemplate).Credential!;
                var rowsA = await database.ScalarAsync<string>(
                    $"SELECT string_agg(to_jsonb(t)::text, ';') FROM one_time_token t WHERE tenant_id = '{a.TenantId}'");
                var credentialsA = await database.ScalarAsync<string>(
                    $"SELECT string_agg(to_jsonb(c)::text, ';') FROM password_credential c WHERE tenant_id = '{a.TenantId}'");
                var eventsA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'");
                var eventsB = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}'");
                var jobs = host.Jobs.Jobs.Count;
                var csrf = Gatekeep.Tests.Isolation.Identity.SignUpFlow.ResetCsrf(link);

                var atB = new HostedBrowser(host, HostB);
                string body;
                if (entry.Pattern == ProtocolContract.ResetPasswordPath)
                {
                    using var page = await atB.GetAsync(Gatekeep.Tests.Isolation.Identity.SignUpFlow.ResetLinkPath(link));
                    Assert.Equal(HttpStatusCode.OK, page.StatusCode);
                    body = await page.Content.ReadAsStringAsync(Cancellation);
                    using var step = StepPage.Read(body);
                    Assert.Equal(StepNames.LinkExpired, step.RootElement.GetProperty("step").GetString());
                }
                else
                {
                    var expected = entry.Pattern == ProtocolContract.ResetCompletePath ? StepNames.LinkExpired : StepNames.LinkSent;
                    using var response = await atB.PostAsync(
                        entry.Pattern, new { token = link, password = "Fresh-Lantern-4orbit", confirm = "Fresh-Lantern-4orbit" }, csrf);
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    body = await response.Content.ReadAsStringAsync(Cancellation);
                    using var step = JsonDocument.Parse(body);
                    Assert.Equal(expected, step.RootElement.GetProperty("step").GetString());
                }

                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(jobs, host.Jobs.Jobs.Count);
                Assert.Equal(rowsA, await database.ScalarAsync<string>(
                    $"SELECT string_agg(to_jsonb(t)::text, ';') FROM one_time_token t WHERE tenant_id = '{a.TenantId}'"));
                Assert.Equal(credentialsA, await database.ScalarAsync<string>(
                    $"SELECT string_agg(to_jsonb(c)::text, ';') FROM password_credential c WHERE tenant_id = '{a.TenantId}'"));
                Assert.Equal(eventsA, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'"));
                Assert.Equal(eventsB, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{b.TenantId}'"));
                Assert.Empty(atB.SetCookies);

                using (var page = await new HostedBrowser(host, HostA).GetAsync(Gatekeep.Tests.Isolation.Identity.SignUpFlow.ResetLinkPath(link)))
                using (var step = StepPage.Read(await page.Content.ReadAsStringAsync(Cancellation)))
                {
                    Assert.Equal(StepNames.ResetPassword, step.RootElement.GetProperty("step").GetString());
                }

                break;
            }

            case ProtocolContract.EndSessionPath:
            case ProtocolContract.LogoutPath:
            {
                // Tenant A's real Session cookie and ID token, presented at B's host (Story 4.13): B's lookup, under B's
                // row-level security, finds no Session, so nothing ends, and B's keys don't verify A's hint, so there is no
                // redirect. The CSRF token is the cookie's own, so only the lookup refuses. A's Session and family live on.
                var flow = await CodeFlowWithin(database, a, b);
                await database.ExecuteAsync(
                    $"UPDATE application SET post_logout_redirect_uris = ARRAY['https://client.code.test/signed-out'] WHERE id = '{flow.ClientA.ApplicationId}'");
                var signedIn = await LogoutFlow.SignInAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, flow.UserA);
                var url = LogoutFlow.EndSessionUrl(signedIn.IdToken, "https://client.code.test/signed-out", "cross-tenant", null);
                using var page = await signedIn.Browser.GetAsync(url);
                var confirmation = await LogoutFlow.PageStepAsync(page);
                Assert.Equal(StepNames.Logout, confirmation.Step);
                var eventsA = await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'");

                var atB = new HostedBrowser(host, HostB);
                atB.Cookies[ProtocolContract.SessionCookie] = signedIn.Browser.Cookies[ProtocolContract.SessionCookie];
                string body;
                if (entry.Pattern == ProtocolContract.EndSessionPath)
                {
                    using var response = await atB.GetAsync(url);
                    body = await response.Content.ReadAsStringAsync(Cancellation);
                    var step = await LogoutFlow.PageStepAsync(response);
                    Assert.Equal(StepNames.LoggedOut, step.Step);
                    Assert.Equal(JsonValueKind.Null, step.Data.GetProperty("redirectTo").ValueKind);
                }
                else
                {
                    using var response = await atB.PostAsync(entry.Pattern, LogoutFlow.Body(confirmation), confirmation.Csrf);
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    body = await response.Content.ReadAsStringAsync(Cancellation);
                    using var step = JsonDocument.Parse(body);
                    Assert.Equal(StepNames.LoggedOut, step.RootElement.GetProperty("step").GetString());
                    Assert.Equal(JsonValueKind.Null, step.RootElement.GetProperty("data").GetProperty("redirectTo").ValueKind);
                }

                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(1L, await database.ScalarAsync<long>($"SELECT count(*) FROM user_session WHERE tenant_id = '{a.TenantId}' AND ended_at IS NULL"));
                Assert.Equal(0L, await database.ScalarAsync<long>("SELECT count(*) FROM audit_event WHERE type_code = 'sessions.access.revoked'"));
                Assert.Equal(eventsA, await database.ScalarAsync<long>($"SELECT count(*) FROM audit_event WHERE tenant_id = '{a.TenantId}'"));
                Assert.All(atB.SetCookies, c => Assert.DoesNotContain("Domain", c, StringComparison.OrdinalIgnoreCase));
                using var refreshed = await CodeFlow.RefreshAsync(host, HostA, flow.ClientA.ClientId, flow.ClientA.Secret, signedIn.Refresh!);
                Assert.Equal(HttpStatusCode.OK, refreshed.Status);
                break;
            }

            case Gatekeep.Modules.Tenancy.Contracts.TenancyContract.ThemeRoute:
            {
                // B's theme stylesheet at the hash B's step pages link (Story 4.1), from B's resolved Tenant only:
                // it names nothing of A, and any other hash is the fixed 404.
                var href = Gatekeep.Modules.Tenancy.Contracts.TenancyContract.Theme(b).Href;
                using var response = await host.Http.GetAsync(new Uri($"http://{HostB}{href}"), Cancellation);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal("text/css", response.Content.Headers.ContentType?.MediaType);
                var body = await response.Content.ReadAsStringAsync(Cancellation);
                Assert.Contains("--gk-color-ac", body, StringComparison.Ordinal);
                Assert.DoesNotContain(HostA, body, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(a.TenantId.ToString(), body, StringComparison.OrdinalIgnoreCase);

                using var other = await host.Http.GetAsync(new Uri($"http://{HostB}/login/theme/0123456789abcdef.css"), Cancellation);
                Assert.Equal(HttpStatusCode.NotFound, other.StatusCode);
                break;
            }

            default:
                Assert.Fail($"{entry} is HostResolved but has no case here: add one to {nameof(Hosted_route_on_Tenant_B_s_host_carries_only_Tenant_B)}.");
                break;
        }
    }

    /// <summary>A web client and a User in Tenant A of <paramref name="database"/>, for a code flow at A.</summary>
    private async Task<CodeFlowSetup> CodeFlowWithin(ProtocolDatabase database, Gatekeep.Modules.Tenancy.Contracts.ResolvedTenant a, Gatekeep.Modules.Tenancy.Contracts.ResolvedTenant b)
    {
        var client = await database.CreateWebClientAsync(a.TenantId, [CodeFlowSetup.Callback]);
        var user = await database.AddUserAsync(a.TenantId);
        return new CodeFlowSetup(database, a, b, client, user, bao);
    }

    private static TheoryData<string, string> Cases(IEnumerable<RouteCase> registry, params CaseKind[] kinds)
    {
        var data = new TheoryData<string, string>();
        foreach (var entry in registry.Where(e => kinds.Contains(e.Kind)))
        {
            data.Add(entry.Method, entry.Pattern);
        }

        return data;
    }

    /// <summary>The entry's pattern with Tenant B in its Tenant parameter and its other values filled in.</summary>
    private static string PathFor(RouteCase entry, string tenant)
    {
        var path = entry.Pattern.Replace("{tenantId}", tenant, StringComparison.Ordinal)
            .Replace("{targetTenantId}", tenant, StringComparison.Ordinal);
        foreach (var (name, value) in entry.RouteValues ?? new Dictionary<string, string>())
        {
            path = path.Replace($"{{{name}}}", Uri.EscapeDataString(value), StringComparison.Ordinal);
        }

        Assert.DoesNotContain("{", path, StringComparison.Ordinal);
        return path;
    }

    /// <summary>
    /// Everything of Tenant B's a leaked call could change, as one value to compare before and after:
    /// its row, settings, roles, Operations, jobs, keys, own Log and the Deployment events naming it.
    /// Each piece is coalesced, so a missing row reads as a value and never makes the whole NULL. The
    /// caller's own refusal, asserted on its own, is left out of the Deployment events and, as its
    /// <c>admin.cross_tenant.rejected</c> (Story 7.4), of B's Log.
    /// </summary>
    private Task<string> StateOfBAsync(Guid caller) =>
        admin.Host.ScalarAsync<string>(
            $"""
            SELECT 'tenant ' || coalesce((SELECT name || '/' || status || '/' || label FROM tenant WHERE id = '{admin.TenantB}'), 'none')
                   || ' settings ' || coalesce((SELECT row_to_json(s)::text FROM tenant_settings AS s WHERE tenant_id = '{admin.TenantB}'), 'none')
                   || ' connection ' || coalesce((SELECT row_to_json(c)::text FROM connection AS c WHERE tenant_id = '{admin.TenantB}'), 'none')
                   || ' roles ' || coalesce((SELECT count(*) FROM tenant_role WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' operations ' || coalesce((SELECT count(*) FROM operation WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' steps ' || coalesce((SELECT count(*) FROM operation_step WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' jobs ' || coalesce((SELECT count(*) FROM job WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' keys ' || coalesce((SELECT count(*) FROM signing_key WHERE tenant_id = '{admin.TenantB}'), 0)
                   || ' events ' || coalesce((SELECT count(*) FROM audit_event WHERE tenant_id = '{admin.TenantB}' AND NOT (type_code = 'admin.cross_tenant.rejected' AND actor_id IS NOT DISTINCT FROM '{caller}'::uuid)), 0)
                   || ' deployment events ' || coalesce((SELECT count(*) FROM deployment_audit_event WHERE target_id = '{admin.TenantB}' AND coalesce(actor_id::text, '') <> '{caller}'), 0)
            """);
}
