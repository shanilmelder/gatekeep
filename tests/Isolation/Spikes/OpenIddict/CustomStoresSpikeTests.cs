using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Tests.Isolation.Custody;
using Gatekeep.Tests.Isolation.Spikes.OpenIddict.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Gatekeep.Tests.Isolation.Spikes.OpenIddict;

/// <summary>
/// Story 2.2: OpenIddict 7.7.2 on custom stores, with every store call in the request's
/// <c>TenantScope</c> (AD-8, AD-13). One or more tests per row of the spike's I/O matrix;
/// <c>docs/spikes/2-2-openiddict-stores.md</c> names each. No assertion compares a token, code or
/// secret value directly, so a failure can't print one: tokens are matched by the hash the
/// store holds, and compared with <see cref="Assert.True(bool, string)"/>.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class CustomStoresSpikeTests(OpenBaoFixture bao, PostgresFixture postgres)
{
    private const string OfflineScope = "openid offline_access";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Stores_mode_runs_with_degraded_mode_off_and_the_settings_AD8_keeps()
    {
        await using var spike = await StartAsync();
        var global = spike.GlobalOptions;

        Assert.False(global.EnableDegradedMode);
        Assert.False(global.DisableTokenStorage);
        Assert.False(global.DisableAuthorizationStorage);
        Assert.False(global.DisableRollingRefreshTokens);
        Assert.True(global.UseReferenceRefreshTokens);
        Assert.Null(global.RefreshTokenReuseLeeway);
        Assert.True(global.DisableScopeValidation);
        Assert.Equal(["S256"], global.CodeChallengeMethods);
        Assert.True(spike.Services.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue.DisableEntityCaching);

        var handlers = global.Handlers.Select(d => d.ServiceDescriptor.ServiceType).ToList();
        Assert.Equal(typeof(SelectTenantOptions), global.Handlers.First(d => d.ContextType == typeof(ProcessRequestContext)).ServiceDescriptor.ServiceType);
        Assert.DoesNotContain(typeof(OpenIddictServerHandlers.ValidateClientSecret), handlers);
        Assert.Contains(typeof(ValidateGatekeepClientSecret), handlers);
        Assert.DoesNotContain(typeof(OpenIddictServerHandlers.Protection.AttachTokenPayload), handlers);
        Assert.Contains(typeof(AttachTenantReferenceId), handlers);
        Assert.Contains(typeof(ValidateGatekeepScopes), handlers);

        // The prefix check runs after RemoveDisallowedCharacters and before any reference lookup.
        int Order(Type type) => global.Handlers.Single(d =>
            d.ContextType == typeof(ValidateTokenContext) && d.ServiceDescriptor.ServiceType == type).Order;
        var prefixCheck = Order(typeof(RejectForeignReferenceIds));
        Assert.True(Order(typeof(OpenIddictServerHandlers.Protection.RemoveDisallowedCharacters)) < prefixCheck);
        Assert.True(prefixCheck < Order(typeof(OpenIddictServerHandlers.Protection.ValidateReferenceTokenIdentifier)));

        // No scope store: resolving the scope manager fails.
        await using (var scope = spike.Services.CreateAsyncScope())
        {
            Assert.ThrowsAny<InvalidOperationException>(() => scope.ServiceProvider.GetService<IOpenIddictScopeManager>());
        }

        // The spike tables: RLS enabled and forced, and gk_hosted can't write Applications or delete anything.
        var database = spike.Database!;
        Assert.Equal(3, await database.CountAsync(
            """
            SELECT count(*) FROM pg_class
            WHERE relname IN ('spike_application', 'spike_authorization', 'spike_token')
              AND relrowsecurity AND relforcerowsecurity
            """));
        Assert.Equal(3, await database.CountAsync(
            """
            SELECT count(*) FROM pg_policies
            WHERE tablename IN ('spike_application', 'spike_authorization', 'spike_token')
              AND policyname = tablename || '_tenant' AND permissive = 'RESTRICTIVE'
            """));
        Assert.Equal(0, await database.CountAsync(
            """
            SELECT count(*) FROM (VALUES
              (has_table_privilege('gk_hosted', 'spike_application', 'INSERT')),
              (has_table_privilege('gk_hosted', 'spike_application', 'UPDATE')),
              (has_table_privilege('gk_hosted', 'spike_authorization', 'DELETE')),
              (has_table_privilege('gk_hosted', 'spike_token', 'DELETE'))) AS p (granted)
            WHERE granted
            """));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Each_completed_code_flow_creates_one_authorization_that_every_token_references()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using var first = await CodeFlowAsync(spike, a);
        using var second = await RefreshAsync(spike, a, RefreshToken(first));
        Assert.Equal(HttpStatusCode.OK, second.Status);
        using var third = await RefreshAsync(spike, a, RefreshToken(second));
        Assert.Equal(HttpStatusCode.OK, third.Status);

        var authorization = await SingleAuthorizationAsync(spike, a);
        Assert.Equal(1, await CountAsync(spike, $"spike_authorization WHERE tenant_id = '{a.Id}' AND type = 'ad-hoc'"));

        // The code, then access, refresh and ID token from the code and from each refresh.
        Assert.Equal(10, await CountAsync(spike, $"spike_token WHERE tenant_id = '{a.Id}'"));
        Assert.Equal(0, await CountAsync(spike, $"spike_token WHERE tenant_id = '{a.Id}' AND authorization_id IS DISTINCT FROM '{authorization}'"));

        // A second completed flow is a second family.
        using var other = await CodeFlowAsync(spike, a);
        Assert.Equal(2, await CountAsync(spike, $"spike_authorization WHERE tenant_id = '{a.Id}'"));
        Assert.Equal(4, await CountAsync(spike, $"spike_token WHERE tenant_id = '{a.Id}' AND authorization_id <> '{authorization}'"));

        Assert.All(spike.Probe.Outcomes, o => Assert.Equal(SpikeRequestOutcome.Committed, o));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Refresh_issues_a_new_refresh_token_and_marks_the_old_one_redeemed()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using var flow = await CodeFlowAsync(spike, a);
        var old = RefreshToken(flow);
        using var rotated = await RefreshAsync(spike, a, old);
        Assert.Equal(HttpStatusCode.OK, rotated.Status);
        var next = RefreshToken(rotated);

        Assert.True(old != next, "The refresh token wasn't rotated.");
        Assert.Equal("redeemed", await TokenStatusAsync(spike, old));
        Assert.Equal(1, await CountAsync(spike, $"spike_token WHERE reference_id = '{Hash(old)}' AND redemption_date IS NOT NULL"));
        Assert.Equal("valid", await TokenStatusAsync(spike, next));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Reused_refresh_token_revokes_its_family_and_the_revocation_and_event_survive_the_rollback()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using var flow = await CodeFlowAsync(spike, a);
        var old = RefreshToken(flow);
        using var rotated = await RefreshAsync(spike, a, old);
        var newest = RefreshToken(rotated);
        var family = await SingleAuthorizationAsync(spike, a);

        using var reused = await RefreshAsync(spike, a, old);
        Assert.Equal(HttpStatusCode.BadRequest, reused.Status);
        Assert.Equal("invalid_grant", Error(reused));
        Assert.False(reused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.Equal(SpikeRequestOutcome.RevocationCommittedAfterRollback, spike.Probe.Outcomes.Last());

        // Every token in the family is revoked in the database, and one audit event committed.
        Assert.Equal(7, await CountAsync(spike, $"spike_token WHERE authorization_id = '{family}'"));
        Assert.Equal(0, await CountAsync(spike, $"spike_token WHERE authorization_id = '{family}' AND status <> 'revoked'"));
        Assert.Equal(1, await AuditEventsAsync(spike));

        // OpenIddict revokes the tokens only: the authorization row itself stays valid.
        Assert.Equal("valid", await AuthorizationStatusAsync(spike, family));
        Assert.Equal(1, await CountAsync(spike,
            $"""
            audit_event e JOIN spike_authorization z ON z.id = '{family}'
            WHERE e.type_code = '{SpikeDatabase.AuditTypeCode}' AND e.tenant_id = '{a.Id}'
              AND e.target_kind = 'client' AND e.target_id = z.application_id
            """));

        // The newest refresh token is refused too, and that refusal revokes nothing new.
        using var refused = await RefreshAsync(spike, a, newest);
        Assert.Equal("invalid_grant", Error(refused));
        Assert.Equal(1, await AuditEventsAsync(spike));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Reuse_revocation_on_the_request_transaction_alone_is_lost_with_the_rollback()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;
        spike.Probe.CommitRevocationAfterRollback = false;

        using var flow = await CodeFlowAsync(spike, a);
        var old = RefreshToken(flow);
        using var rotated = await RefreshAsync(spike, a, old);
        var newest = RefreshToken(rotated);

        using var reused = await RefreshAsync(spike, a, old);
        Assert.Equal("invalid_grant", Error(reused));
        Assert.Equal(SpikeRequestOutcome.RolledBackLosingRevocation, spike.Probe.Outcomes.Last());

        // OpenIddict's own RevokeByAuthorizationIdAsync ran on the request transaction and was rolled back.
        Assert.Equal("valid", await TokenStatusAsync(spike, newest));
        Assert.Equal(0, await AuditEventsAsync(spike));

        using var stillWorks = await RefreshAsync(spike, a, newest);
        Assert.Equal(HttpStatusCode.OK, stillWorks.Status);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Replayed_code_revokes_its_family_and_the_revocation_commits()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        var (code, verifier) = await AuthorizeAsync(spike, a);
        using var redeemed = await RedeemAsync(spike, a, code, verifier);
        Assert.Equal(HttpStatusCode.OK, redeemed.Status);
        var family = await SingleAuthorizationAsync(spike, a);

        using var replayed = await RedeemAsync(spike, a, code, verifier);
        Assert.Equal("invalid_grant", Error(replayed));
        Assert.Equal(SpikeRequestOutcome.RevocationCommittedAfterRollback, spike.Probe.Outcomes.Last());
        Assert.Equal(0, await CountAsync(spike, $"spike_token WHERE authorization_id = '{family}' AND status <> 'revoked'"));
        Assert.Equal(1, await AuditEventsAsync(spike));
        Assert.Equal("valid", await AuthorizationStatusAsync(spike, family));

        using var refused = await RefreshAsync(spike, a, RefreshToken(redeemed));
        Assert.Equal("invalid_grant", Error(refused));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Refresh_under_an_authorization_revoked_in_the_database_is_refused_and_issues_nothing()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using var flow = await CodeFlowAsync(spike, a);
        var family = await SingleAuthorizationAsync(spike, a);
        await spike.Database!.ExecuteAsync($"UPDATE spike_authorization SET status = 'revoked' WHERE id = '{family}'");
        var before = await CountAsync(spike, "spike_token");

        using var refused = await RefreshAsync(spike, a, RefreshToken(flow));
        Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
        Assert.Equal("invalid_grant", Error(refused));
        Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        Assert.False(refused.Body.RootElement.TryGetProperty("refresh_token", out _));
        Assert.Equal(before, await CountAsync(spike, "spike_token"));
        Assert.Equal(SpikeRequestOutcome.RolledBack, spike.Probe.Outcomes.Last());
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task A_row_changed_in_the_database_between_requests_is_seen_because_entity_caching_is_off()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using (var allowed = await ClientCredentialsAsync(spike, a, SpikeClients.ConfidentialSecret))
        {
            Assert.Equal(HttpStatusCode.OK, allowed.Status);
        }

        await spike.Database!.ExecuteAsync(
            $"""
            UPDATE spike_application SET permissions = array_remove(permissions, 'gt:client_credentials')
            WHERE tenant_id = '{a.Id}' AND client_id = '{SpikeClients.Confidential}'
            """);

        using var refused = await ClientCredentialsAsync(spike, a, SpikeClients.ConfidentialSecret);
        Assert.Equal("unauthorized_client", Error(refused));

        // B's row is untouched, so B still issues.
        using var other = await ClientCredentialsAsync(spike, spike.Tenants.B, SpikeClients.ConfidentialSecret);
        Assert.Equal(HttpStatusCode.OK, other.Status);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Confidential_client_is_checked_by_the_Gatekeep_handler_and_its_secret_column_stays_null()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using (var issued = await ClientCredentialsAsync(spike, a, SpikeClients.ConfidentialSecret))
        {
            Assert.Equal(HttpStatusCode.OK, issued.Status);
            var token = new JsonWebToken(issued.Body.RootElement.GetProperty("access_token").GetString()!);
            Assert.Equal(a.Issuer.AbsoluteUri, token.Issuer);
            Assert.Equal(SpikeClients.Confidential, token.Subject);
        }

        var wrong = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        using (var refused = await ClientCredentialsAsync(spike, a, wrong))
        {
            Assert.Equal("invalid_client", Error(refused));
            Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        }

        // No secret at all is OpenIddict's own parameter check, before any client lookup.
        using (var missing = await ClientCredentialsAsync(spike, a, secret: null))
        {
            Assert.Equal("invalid_request", Error(missing));
            Assert.False(missing.Body.RootElement.TryGetProperty("access_token", out _));
        }

        Assert.Equal(0, await CountAsync(spike, "spike_application WHERE client_secret IS NOT NULL"));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Code_and_refresh_token_are_reference_ids_prefixed_with_the_Tenants_public_id()
    {
        await using var spike = await StartAsync();

        foreach (var tenant in spike.Tenants.All)
        {
            var (code, verifier) = await AuthorizeAsync(spike, tenant);
            using var redeemed = await RedeemAsync(spike, tenant, code, verifier);
            Assert.Equal(HttpStatusCode.OK, redeemed.Status);
            var refresh = RefreshToken(redeemed);

            foreach (var (name, value) in new[] { ("code", code), ("refresh token", refresh) })
            {
                var form = new Regex($@"\A{Regex.Escape(tenant.PublicId)}\.(?<random>[A-Za-z0-9_-]+)\z");
                var match = form.Match(value);
                Assert.True(match.Success, $"The {name} isn't {{publicId}}.{{random}} for its Tenant.");
                Assert.True(
                    Base64UrlEncoder.DecodeBytes(match.Groups["random"].Value).Length >= 32,
                    $"The {name} carries fewer than 256 random bits.");

                // The store holds the hash of the whole value, never the value.
                Assert.Equal(1, await CountAsync(spike, $"spike_token WHERE reference_id = '{Hash(value)}'"));
                Assert.Equal(0, await CountAsync(spike, $"spike_token WHERE reference_id LIKE '{tenant.PublicId}.%'"));
            }

            // The access token stays a JWS, not a reference.
            Assert.Equal(3, new JsonWebToken(redeemed.Body.RootElement.GetProperty("access_token").GetString()!).EncodedToken.Count(c => c == '.') + 1);
        }

        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Code_or_refresh_token_from_one_Tenant_is_refused_on_another_before_any_store_lookup()
    {
        await using var spike = await StartAsync();
        var (a, b) = (spike.Tenants.A, spike.Tenants.B);

        using var flow = await CodeFlowAsync(spike, a);
        var refresh = RefreshToken(flow);
        var (code, verifier) = await AuthorizeAsync(spike, a);

        using (var refused = await RefreshAsync(spike, b, refresh))
        {
            Assert.Equal(HttpStatusCode.BadRequest, refused.Status);
            Assert.Equal("invalid_grant", Error(refused));
        }

        using (var refused = await RedeemAsync(spike, b, code, verifier))
        {
            Assert.Equal("invalid_grant", Error(refused));
        }

        // B's token store never saw either value, hashed or not.
        var seenUnderB = spike.Probe.ReferenceLookups.Where(l => l.Tenant == b.Id).Select(l => l.Hash).ToList();
        Assert.DoesNotContain(Hash(refresh), seenUnderB);
        Assert.DoesNotContain(Hash(code), seenUnderB);

        // Positive control: B's own refresh token is looked up, and recorded under B.
        using (var bFlow = await CodeFlowAsync(spike, b))
        {
            var bRefresh = RefreshToken(bFlow);
            using var bRefreshed = await RefreshAsync(spike, b, bRefresh);
            Assert.Equal(HttpStatusCode.OK, bRefreshed.Status);
            Assert.Contains((b.Id, Hash(bRefresh)), spike.Probe.ReferenceLookups);
        }

        // And A's rows in every spike table are invisible under B's scope as gk_hosted.
        await using (var scope = await TenantScope.BeginAsync(spike.Database!.Hosted, b.Id, Cancellation))
        {
            foreach (var table in new[] { "spike_token", "spike_authorization", "spike_application" })
            {
                Assert.True(await CountAsync(spike, $"{table} WHERE tenant_id = '{a.Id}'") > 0, $"A has no {table} rows.");
                var visible = await SpikeSql.QueryAsync(
                    scope.CreateCommandContext(), $"SELECT count(*) FROM {table} WHERE tenant_id = '{a.Id}'", r => r.GetInt64(0), Cancellation);
                Assert.Equal(0, visible[0]);
            }
        }

        Assert.True(await CountAsync(spike, $"spike_token WHERE tenant_id = '{a.Id}'") > 0);
        using var atHome = await RedeemAsync(spike, a, code, verifier);
        Assert.Equal(HttpStatusCode.OK, atHome.Status);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Code_redeemed_with_a_bad_PKCE_verifier_is_refused_and_leaves_the_store_as_it_was()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        var (code, verifier) = await AuthorizeAsync(spike, a);
        var before = await SnapshotAsync(spike);

        var wrong = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        using (var refused = await RedeemAsync(spike, a, code, wrong))
        {
            Assert.Equal("invalid_grant", Error(refused));
        }

        Assert.Equal(SpikeRequestOutcome.RolledBack, spike.Probe.Outcomes.Last());
        Assert.Equal(before, await SnapshotAsync(spike));

        // Nothing marked the code redeemed, so the right verifier still redeems it.
        using var redeemed = await RedeemAsync(spike, a, code, verifier);
        Assert.Equal(HttpStatusCode.OK, redeemed.Status);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Authorize_without_S256_PKCE_is_refused_by_OpenIddict_itself_and_writes_nothing()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;
        var challenge = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        var queries = new[] { "plain", null }.Select(method =>
        {
            var parameters = new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = SpikeClients.Public,
                ["redirect_uri"] = SpikeClients.RedirectUri,
                ["scope"] = OfflineScope,
                ["state"] = "spike-state",
            };
            if (method is not null)
            {
                parameters["code_challenge"] = challenge;
                parameters["code_challenge_method"] = method;
            }

            return QueryString.Create(parameters).ToUriComponent();
        });

        foreach (var query in queries)
        {
            var outcomes = spike.Probe.Outcomes.Count;
            var parameters = await AuthorizeErrorAsync(spike, a, query);

            Assert.Equal("invalid_request", parameters.GetValueOrDefault("error"));
            Assert.False(parameters.ContainsKey("code"), "A code was issued without S256 PKCE.");
            Assert.Equal(outcomes + 1, spike.Probe.Outcomes.Count);
            Assert.Equal(SpikeRequestOutcome.RolledBack, spike.Probe.Outcomes.Last());
        }

        Assert.Equal(0, await CountAsync(spike, "spike_token"));
        Assert.Equal(0, await CountAsync(spike, "spike_authorization"));
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Unknown_scope_is_refused_by_the_Gatekeep_scope_handler_and_writes_nothing()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;
        var challenge = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        var query = QueryString.Create(new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = SpikeClients.Public,
            ["redirect_uri"] = SpikeClients.RedirectUri,
            ["scope"] = "openid unknown_scope",
            ["state"] = "spike-state",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }).ToUriComponent();

        var parameters = await AuthorizeErrorAsync(spike, a, query);
        Assert.Equal("invalid_scope", parameters.GetValueOrDefault("error"));
        Assert.False(parameters.ContainsKey("code"), "A code was issued for an unknown scope.");

        using (var refused = await PostAsync(spike, a, new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = SpikeClients.Confidential,
            ["client_secret"] = SpikeClients.ConfidentialSecret,
            ["scope"] = "unknown_scope",
        }))
        {
            Assert.Equal("invalid_scope", Error(refused));
            Assert.False(refused.Body.RootElement.TryGetProperty("access_token", out _));
        }

        Assert.Equal(0, await CountAsync(spike, "spike_token"));
        Assert.Equal(0, await CountAsync(spike, "spike_authorization"));
        Assert.Equal(0, spike.Probe.Writes);
        Assert.Equal(0, spike.Inert.Uses);
    }

    [Fact]
    public async Task Sign_in_rejected_after_its_writes_rolls_every_write_back()
    {
        await using var spike = await StartAsync();
        var a = spike.Tenants.A;

        using var flow = await CodeFlowAsync(spike, a);
        var refresh = RefreshToken(flow);
        var before = await SnapshotAsync(spike);

        // OpenIddict redeems the refresh token and stores three new tokens, then the sign-in is refused.
        spike.Probe.RejectSignInAfterWrites = true;
        var writes = spike.Probe.Writes;
        using (var refused = await RefreshAsync(spike, a, refresh))
        {
            Assert.Equal("invalid_grant", Error(refused));
        }

        // The writes happened inside the request before the rejection: the redemption, then
        // each new token's insert and its payload update.
        Assert.True(spike.Probe.Writes - writes >= 4, $"Only {spike.Probe.Writes - writes} store writes ran before the rejection.");

        Assert.Equal(SpikeRequestOutcome.RolledBack, spike.Probe.Outcomes.Last());
        Assert.Equal(before, await SnapshotAsync(spike));
        Assert.Equal("valid", await TokenStatusAsync(spike, refresh));

        spike.Probe.RejectSignInAfterWrites = false;
        using var refreshed = await RefreshAsync(spike, a, refresh);
        Assert.Equal(HttpStatusCode.OK, refreshed.Status);
        Assert.Equal(0, spike.Inert.Uses);
    }

    private Task<SpikeServer> StartAsync() => SpikeServer.StartWithStoresAsync(bao, postgres, Cancellation);

    /// <summary>The value the store holds for a reference ID: what OpenIddict's token manager computes.</summary>
    private static string Hash(string value) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string RefreshToken(Response response) =>
        response.Body.RootElement.GetProperty("refresh_token").GetString()
            ?? throw new InvalidOperationException("No refresh token.");

    private static string? Error(Response response) =>
        response.Body.RootElement.TryGetProperty("error", out var error) ? error.GetString() : null;

    private static Task<long> CountAsync(SpikeServer spike, string from) =>
        spike.Database!.CountAsync($"SELECT count(*) FROM {from}");

    private static Task<long> AuditEventsAsync(SpikeServer spike) =>
        CountAsync(spike, $"audit_event WHERE type_code = '{SpikeDatabase.AuditTypeCode}'");

    private static Task<string> TokenStatusAsync(SpikeServer spike, string value) =>
        PostgresFixture.ScalarAsync<string>(spike.Database!.Superuser, $"SELECT status FROM spike_token WHERE reference_id = '{Hash(value)}'");

    private static Task<string> AuthorizationStatusAsync(SpikeServer spike, string id) =>
        PostgresFixture.ScalarAsync<string>(spike.Database!.Superuser, $"SELECT status FROM spike_authorization WHERE id = '{id}'");

    private static Task<string> SingleAuthorizationAsync(SpikeServer spike, SpikeTenant tenant) =>
        PostgresFixture.ScalarAsync<string>(spike.Database!.Superuser, $"SELECT id::text FROM spike_authorization WHERE tenant_id = '{tenant.Id}'");

    /// <summary>Every token and authorization row, without any reference or payload value.</summary>
    private static Task<string> SnapshotAsync(SpikeServer spike) =>
        PostgresFixture.ScalarAsync<string>(
            spike.Database!.Superuser,
            """
            SELECT concat_ws(' / ',
              (SELECT coalesce(string_agg(concat_ws('|', id, status, redemption_date IS NOT NULL, concurrency_token), ',' ORDER BY id), '') FROM spike_token),
              (SELECT coalesce(string_agg(concat_ws('|', id, status, concurrency_token), ',' ORDER BY id), '') FROM spike_authorization))
            """);

    private static async Task<(string Code, string Verifier)> AuthorizeAsync(SpikeServer spike, SpikeTenant tenant)
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var query = QueryString.Create(new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = SpikeClients.Public,
            ["redirect_uri"] = SpikeClients.RedirectUri,
            ["scope"] = OfflineScope,
            ["state"] = "spike-state",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }).ToUriComponent();

        using var response = await spike.Client.GetAsync(new Uri(tenant.Issuer, SpikeServer.AuthorizePath + query), Cancellation);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);

        var location = response.Headers.Location!;
        Assert.Equal(SpikeClients.RedirectUri, location.GetLeftPart(UriPartial.Path));
        var parameters = QueryHelpers.ParseQuery(location.Query);
        Assert.True(parameters.ContainsKey("code"), "The authorization response has no code.");
        Assert.Equal(tenant.Issuer.AbsoluteUri, parameters["iss"].ToString());

        return (parameters["code"].ToString(), verifier);
    }

    /// <summary>
    /// A refused authorization request's parameters: from the redirect, or, when OpenIddict
    /// answers directly, from its body (JSON, or its plain-text <c>key:value</c> lines).
    /// </summary>
    private static async Task<Dictionary<string, string>> AuthorizeErrorAsync(SpikeServer spike, SpikeTenant tenant, string query)
    {
        using var response = await spike.Client.GetAsync(new Uri(tenant.Issuer, SpikeServer.AuthorizePath + query), Cancellation);
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);

        if (response.Headers.Location is { } location)
        {
            return QueryHelpers.ParseQuery(location.Query).ToDictionary(p => p.Key, p => p.Value.ToString());
        }

        var body = await response.Content.ReadAsStringAsync(Cancellation);
        if (response.Content.Headers.ContentType?.MediaType == "application/json")
        {
            using var json = JsonDocument.Parse(body);
            return json.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.ToString());
        }

        return body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0], parts => parts[1]);
    }

    private static async Task<Response> CodeFlowAsync(SpikeServer spike, SpikeTenant tenant)
    {
        var (code, verifier) = await AuthorizeAsync(spike, tenant);
        var response = await RedeemAsync(spike, tenant, code, verifier);
        Assert.Equal(HttpStatusCode.OK, response.Status);
        return response;
    }

    private static Task<Response> RedeemAsync(SpikeServer spike, SpikeTenant tenant, string code, string verifier) =>
        PostAsync(spike, tenant, new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = SpikeClients.Public,
            ["redirect_uri"] = SpikeClients.RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier,
        });

    private static Task<Response> RefreshAsync(SpikeServer spike, SpikeTenant tenant, string refreshToken) =>
        PostAsync(spike, tenant, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = SpikeClients.Public,
            ["refresh_token"] = refreshToken,
        });

    private static Task<Response> ClientCredentialsAsync(SpikeServer spike, SpikeTenant tenant, string? secret)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = SpikeClients.Confidential,
        };
        if (secret is not null)
        {
            form["client_secret"] = secret;
        }

        return PostAsync(spike, tenant, form);
    }

    private static async Task<Response> PostAsync(SpikeServer spike, SpikeTenant tenant, Dictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        using var response = await spike.Client.PostAsync(new Uri(tenant.Issuer, SpikeServer.TokenPath), content, Cancellation);
        return new Response(response.StatusCode, JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation)));
    }

    private sealed record Response(HttpStatusCode Status, JsonDocument Body) : IDisposable
    {
        public void Dispose() => Body.Dispose();
    }
}
