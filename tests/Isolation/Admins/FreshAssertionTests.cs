using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gatekeep.Kernel.Identifiers;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.26: fresh WebAuthn assertions on the real <c>Host.Admin</c> and PostgreSQL, with
/// software authenticators. A grant is bound to its Session, action and target, lives 5 minutes,
/// and is used up by the first request it matches, before the action runs; without one the
/// request checks, or the registration handler's gate, answer 403 <c>fresh_assertion_required</c>.
/// The ceremony verifies as sign-in does, against the Session's own Admin's credentials only.
/// </summary>
public sealed class FreshAssertionTests(PostgresFixture postgres)
{
    private const string Remove = "self.credentials.remove";

    private const string Add = "self.credentials.add";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Remove_without_a_confirmation_is_403_fresh_assertion_required_and_changes_nothing()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var ids = await host.CredentialIdsAsync(cookie);
        var events = await EventsAsync(host);

        using var refused = await host.RemoveCredentialAsync(cookie, csrf, ids[1]);

        await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal(3L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.Equal(events, await EventsAsync(host));
        Assert.Contains("fresh_assertion_required", host.Output, StringComparison.Ordinal);
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Confirm_then_remove_deletes_it_ends_the_other_Sessions_and_keeps_this_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var ids = await host.CredentialIdsAsync(cookie);

        // Two other live Sessions of the same Admin, as other browsers' would be, beside the setup one
        // bootstrap started, which became full with the second credential.
        var (other, _) = await host.SignInAsync(authenticators[1]);
        await host.SignInAsync(authenticators[2]);
        var revokedBefore = await CountAsync(host, "admin.session.revoked");

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, ids[1]);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));

        using var removed = await host.RemoveCredentialAsync(cookie, csrf, ids[1]);

        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        Assert.Equal("no-store", removed.Headers.CacheControl?.ToString());
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM admin_credential WHERE id = '{RowOf(ids[1])}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));

        // Every other live Session ended as revoked, one event each, with the Admin as Actor and target.
        Assert.Equal(3L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM admin_session WHERE end_reason = 'revoked' AND admin_id = '{adminId}'"));
        Assert.Equal(revokedBefore + 3, await CountAsync(host, "admin.session.revoked"));
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT DISTINCT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.credential.removed'"));
        Assert.Equal(1L, await CountAsync(host, "admin.credential.removed"));
        Assert.True(await CountAsync(host, "admin.fresh_assertion.verified") >= 2);

        using (var stale = await host.SendAsync(HttpMethod.Get, AdminHost.CredentialsPath, other))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
        }

        // This Session stays, and lists what is left.
        Assert.Equal([ids[0], ids[2]], await host.CredentialIdsAsync(cookie));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_grant_is_used_once_and_bound_to_its_target_and_its_Session()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(4);
        var ids = await host.CredentialIdsAsync(cookie);

        // Bound to its target: a grant for one credential removes no other, and stays.
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, ids[1]);
        using (var other = await host.RemoveCredentialAsync(cookie, csrf, ids[2]))
        {
            await AssertProblemAsync(other, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));

        // Bound to its Session: another Session of the same Admin can't use it.
        var (second, secondCsrf) = await host.SignInAsync(authenticators[1]);
        using (var elsewhere = await host.RemoveCredentialAsync(second, secondCsrf, ids[1]))
        {
            await AssertProblemAsync(elsewhere, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        // Used once: the first match uses it up, and the same request again needs a new one.
        using (var removed = await host.RemoveCredentialAsync(cookie, csrf, ids[1]))
        {
            Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        }

        using (var again = await host.RemoveCredentialAsync(cookie, csrf, ids[2]))
        {
            await AssertProblemAsync(again, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Equal(3L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task An_expired_grant_is_403()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var ids = await host.CredentialIdsAsync(cookie);
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, ids[2]);

        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "UPDATE admin_fresh_assertion SET created_at = created_at - interval '6 minutes', expires_at = expires_at - interval '6 minutes'");

        using var refused = await host.RemoveCredentialAsync(cookie, csrf, ids[2]);
        await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.Equal(3L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Removal_floor_is_409_with_the_grant_used_up_and_nothing_removable()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);
        var ids = await host.CredentialIdsAsync(cookie);

        var list = await host.CredentialsAsync(cookie);
        Assert.All(list.GetProperty("credentials").EnumerateArray(), c => Assert.False(c.GetProperty("removable").GetBoolean()));

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, ids[0]);
        using var refused = await host.RemoveCredentialAsync(cookie, csrf, ids[0]);

        await AssertProblemAsync(refused, HttpStatusCode.Conflict, "credentials_minimum");
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.Equal(0L, await CountAsync(host, "admin.credential.removed"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Another_Admins_credential_and_a_malformed_ID_are_404()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var (otherSession, _, _) = await host.InsertFullSessionAsync(3);
        var foreign = PublicId.Format(
            PublicIdType.AdminCredential,
            await host.ScalarAsync<Guid>($"SELECT min(c.id::text)::uuid FROM admin_credential AS c JOIN admin AS a ON a.id = c.admin_id WHERE NOT a.deployment_owner"));
        _ = otherSession;

        foreach (var target in new[] { foreign, "nope", PublicId.Format(PublicIdType.AdminCredential, Guid.CreateVersion7()) })
        {
            await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, target);
            using var missing = await host.RemoveCredentialAsync(cookie, csrf, target);
            Assert.True(missing.StatusCode == HttpStatusCode.NotFound, $"{target} answered {(int)missing.StatusCode}.");
            Assert.Empty(await missing.Content.ReadAsByteArrayAsync(Cancellation));
        }

        Assert.Equal(6L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Another_Admins_key_no_UV_a_used_or_replaced_challenge_are_400_with_no_grant()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);
        var (setup, setupCsrf, _) = await host.InsertSetupAdminAsync();
        using var stranger = new SoftwareAuthenticator();
        await host.RegisterAsync(setup, setupCsrf, stranger);
        var events = await EventsAsync(host);

        // Another Admin's own key, in this Admin's Session.
        var (begin, options) = await host.BeginAssertionAsync(cookie, csrf, Add);
        begin.Dispose();
        using (var foreign = await host.CompleteAssertionAsync(cookie, csrf, stranger.Assert(options, AdminHost.Origin)))
        {
            await AssertProblemAsync(foreign, HttpStatusCode.BadRequest, "assertion_refused");
        }

        // No user verification.
        (begin, options) = await host.BeginAssertionAsync(cookie, csrf, Add);
        begin.Dispose();
        using (var unverified = await host.CompleteAssertionAsync(
            cookie, csrf, authenticators[0].Assert(options, AdminHost.Origin, new AssertionTweaks { UserVerified = false })))
        {
            await AssertProblemAsync(unverified, HttpStatusCode.BadRequest, "assertion_refused");
        }

        // Single use: the same challenge answered twice.
        (begin, options) = await host.BeginAssertionAsync(cookie, csrf, Add);
        begin.Dispose();
        using (var first = await host.CompleteAssertionAsync(cookie, csrf, authenticators[0].Assert(options, AdminHost.Origin)))
        {
            Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        }

        using (var replay = await host.CompleteAssertionAsync(cookie, csrf, authenticators[0].Assert(options, AdminHost.Origin)))
        {
            await AssertProblemAsync(replay, HttpStatusCode.BadRequest, "assertion_refused");
        }

        // A newer begin replaces the pending challenge, and the older one answers nothing.
        var (older, olderOptions) = await host.BeginAssertionAsync(cookie, csrf, Remove, "acr_x");
        older.Dispose();
        var (newer, _) = await host.BeginAssertionAsync(cookie, csrf, Remove, "acr_x");
        newer.Dispose();
        using (var replaced = await host.CompleteAssertionAsync(cookie, csrf, authenticators[0].Assert(olderOptions, AdminHost.Origin)))
        {
            await AssertProblemAsync(replaced, HttpStatusCode.BadRequest, "assertion_refused");
        }

        // The one pass made one grant, the add's; every refusal was only logged.
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));
        Assert.Equal(events + 1, await EventsAsync(host));
        Assert.Equal(1L, await CountAsync(host, "admin.fresh_assertion.verified"));
        Assert.Equal(0L, await CountAsync(host, "admin.fresh_assertion.failed"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Counter_regression_is_400_audited_with_the_Admin_as_Actor_and_the_counter_unchanged()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId, authenticators) = await host.OwnerWithCredentialsAsync(2);
        var stored = await host.ScalarAsync<long>(
            $"SELECT sign_count FROM admin_credential WHERE credential_id = '\\x{Convert.ToHexStringLower(authenticators[0].CredentialId)}'");
        Assert.True(stored > 0);

        var (begin, options) = await host.BeginAssertionAsync(cookie, csrf, Add);
        begin.Dispose();
        using var regressed = await host.CompleteAssertionAsync(
            cookie, csrf, authenticators[0].Assert(options, AdminHost.Origin, new AssertionTweaks { SignCount = (uint)stored }));

        await AssertProblemAsync(regressed, HttpStatusCode.BadRequest, "assertion_refused");
        Assert.Equal(
            $"admin {adminId} admin {adminId}",
            await host.ScalarAsync<string>(
                "SELECT actor_kind || ' ' || actor_id || ' ' || target_kind || ' ' || target_id FROM deployment_audit_event WHERE type_code = 'admin.credential.sign_count_regressed'"));
        Assert.Equal(stored, await host.ScalarAsync<long>(
            $"SELECT sign_count FROM admin_credential WHERE credential_id = '\\x{Convert.ToHexStringLower(authenticators[0].CredentialId)}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Theory]
    [InlineData("""{"action":"tenant.users.read","target":null}""", "application/json")]
    [InlineData("""{"action":"tenant.client_secrets.manage","target":null}""", "application/json")]
    [InlineData("""{"action":"x","target":null}""", "application/json")]
    [InlineData("""{"target":"acr_x"}""", "application/json")]
    [InlineData("not json", "application/json")]
    [InlineData("""{"action":"self.credentials.add","target":null}""", "text/plain")]
    public async Task Unknown_or_Tenant_action_or_a_body_that_isnt_JSON_is_400(string body, string contentType)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);

        using var refused = await host.SendAsync(HttpMethod.Post, AdminHost.AssertionsPath, cookie, csrf, AdminHost.Origin, body, contentType: contentType);

        await AssertProblemAsync(refused, HttpStatusCode.BadRequest, "assertion_refused");
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Deployment_action_needs_its_capability_and_the_Owners_grant_is_bound_to_it()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);
        var (admin, adminCsrf, sessionId) = await host.InsertFullSessionAsync();
        var adminId = await host.AdminOfSessionAsync(sessionId);

        var (refused, _) = await host.BeginAssertionAsync(admin, adminCsrf, "deployment.tenants.delete");
        using (refused)
        {
            await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "access_denied");
        }

        Assert.Equal(
            $"1 admin {adminId}",
            await host.ScalarAsync<string>("SELECT count(*) || ' ' || min(actor_kind) || ' ' || min(actor_id::text) FROM deployment_audit_event WHERE type_code = 'admin.access.denied'"));

        await host.ConfirmAsync(cookie, csrf, authenticators[0], "deployment.tenants.delete");
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("deployment.tenants.delete\n\n"))),
            await host.ScalarAsync<string>("SELECT encode(binding_hash, 'hex') FROM admin_fresh_assertion WHERE stage = 'verified'"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Eleventh_ceremony_call_in_15_minutes_is_429_with_Retry_After()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);

        for (var i = 0; i < 5; i++)
        {
            var (begin, _) = await host.BeginAssertionAsync(cookie, csrf, Add);
            begin.Dispose();
            using var complete = await host.CompleteAssertionAsync(cookie, csrf, "{}");
            Assert.Equal(HttpStatusCode.BadRequest, complete.StatusCode);
        }

        var (limited, _) = await host.BeginAssertionAsync(cookie, csrf, Add);
        using (limited)
        {
            await AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
            Assert.True(int.Parse(limited.Headers.GetValues("Retry-After").Single(), System.Globalization.CultureInfo.InvariantCulture) >= 1);
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_restricted_Session_is_refused_the_ceremony_the_list_and_removal()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _) = await host.ClaimedAsync();

        foreach (var (method, path, body) in new[]
        {
            (HttpMethod.Post, AdminHost.AssertionsPath, """{"action":"self.credentials.add"}"""),
            (HttpMethod.Post, AdminHost.AssertionsPath + "/complete", "{}"),
            (HttpMethod.Get, AdminHost.CredentialsPath, (string?)null),
            (HttpMethod.Delete, AdminHost.CredentialsPath + "/" + PublicId.Format(PublicIdType.AdminCredential, Guid.CreateVersion7()), null),
        })
        {
            using var refused = await host.SendAsync(method, path, cookie, csrf, AdminHost.Origin, body);
            Assert.True(refused.StatusCode == HttpStatusCode.Forbidden, $"{method} {path} answered {(int)refused.StatusCode}.");
            Assert.Empty(await refused.Content.ReadAsByteArrayAsync(Cancellation));
        }
    }

    [Fact]
    public async Task Add_needs_a_confirmation_in_a_full_Session_and_then_registers()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);
        using var third = new SoftwareAuthenticator();

        var (refused, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (refused)
        {
            await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_session WHERE registration_challenge_sha256 IS NOT NULL"));

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Add);
        var registered = await host.RegisterAsync(cookie, csrf, third);

        Assert.Equal(3, registered.GetProperty("credentials").GetInt32());
        Assert.True(registered.GetProperty("setupComplete").GetBoolean());
        Assert.Equal(3, (await host.CredentialIdsAsync(cookie)).Count);
        Assert.Equal(3L, await CountAsync(host, "admin.credential.registered"));
        Assert.Equal(1L, await CountAsync(host, "admin.setup.completed"));

        // The grant was used by that begin: the next add needs its own.
        var (again, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (again)
        {
            await AssertProblemAsync(again, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Add_at_the_maximum_is_409_before_any_confirmation()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId, authenticators) = await host.OwnerWithCredentialsAsync(2);
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            $"""
            INSERT INTO admin_credential (id, admin_id, credential_id, public_key, sign_count, aaguid)
            SELECT gen_random_uuid(), '{adminId}', decode(md5(random()::text || n), 'hex'), '\x01', 0, gen_random_uuid()
            FROM generate_series(1, 8) AS n
            """);

        var (full, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (full)
        {
            await AssertProblemAsync(full, HttpStatusCode.Conflict, "credentials_maximum");
        }

        // A grant made anyway isn't spent by the refusal.
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Add);
        var (again, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (again)
        {
            await AssertProblemAsync(again, HttpStatusCode.Conflict, "credentials_maximum");
        }

        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));
        Assert.Equal(10L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Two_completes_storing_the_same_credential_ID_store_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);
        var (second, secondCsrf) = await host.SignInAsync(authenticators[1]);
        using var shared = new SoftwareAuthenticator();

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Add);
        await host.ConfirmAsync(second, secondCsrf, authenticators[1], Add);
        var (a, optionsA) = await host.BeginRegistrationAsync(cookie, csrf);
        a.Dispose();
        var (b, optionsB) = await host.BeginRegistrationAsync(second, secondCsrf);
        b.Dispose();

        var outcomes = await Task.WhenAll(
            host.CompleteRegistrationAsync(cookie, csrf, shared.Attest(optionsA, AdminHost.Origin)),
            host.CompleteRegistrationAsync(second, secondCsrf, shared.Attest(optionsB, AdminHost.Origin)));

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.BadRequest], outcomes.Select(o => o.StatusCode).Order());
        await AssertProblemAsync(outcomes.Single(o => o.StatusCode == HttpStatusCode.BadRequest), HttpStatusCode.BadRequest, "credential_refused");
        Assert.Equal(1L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM admin_credential WHERE credential_id = '\\x{Convert.ToHexStringLower(shared.CredentialId)}'"));
        foreach (var outcome in outcomes)
        {
            outcome.Dispose();
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Backup_flags_are_stored_BS_follows_each_assertion_and_a_changed_BE_is_refused()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var synced = new SoftwareAuthenticator { BackupEligible = true, BackedUp = true };
        using var key = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(synced, key);
        var id = Convert.ToHexStringLower(synced.CredentialId);

        Assert.Equal("t t", await host.ScalarAsync<string>(
            $"SELECT backup_eligible::text::char || ' ' || backed_up::text::char FROM admin_credential WHERE credential_id = '\\x{id}'"));

        // An assertion saying it isn't backed up now: the latest BS is kept, BE stays.
        synced.BackedUp = false;
        var (cookie, _) = await host.SignInAsync(synced);
        Assert.Equal("t f", await host.ScalarAsync<string>(
            $"SELECT backup_eligible::text::char || ' ' || backed_up::text::char FROM admin_credential WHERE credential_id = '\\x{id}'"));

        var list = await host.CredentialsAsync(cookie);
        var first = list.GetProperty("credentials")[0];
        Assert.Equal("passkey", first.GetProperty("kind").GetString());
        Assert.False(first.GetProperty("backedUp").GetBoolean());

        // BE never changes for a credential: an assertion without it isn't this credential's.
        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var changed = await host.CompleteSignInAsync(binding, synced.Assert(options, AdminHost.Origin, new AssertionTweaks { BackupEligible = false }));
        await AssertProblemAsync(changed, HttpStatusCode.BadRequest, "signin_refused");
    }

    [Fact]
    public async Task List_holds_only_the_Admins_own_credentials_and_nothing_secret()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, _, _, authenticators) = await host.OwnerWithCredentialsAsync(2);
        await host.InsertFullSessionAsync(2);

        using var response = await host.SendAsync(HttpMethod.Get, AdminHost.CredentialsPath, cookie);
        var text = await response.Content.ReadAsStringAsync(Cancellation);
        using var json = JsonDocument.Parse(text);
        var credentials = json.RootElement.GetProperty("credentials").EnumerateArray().ToList();

        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal(2, credentials.Count);
        Assert.False(json.RootElement.GetProperty("recoveryCode").GetBoolean());
        Assert.All(credentials, c =>
        {
            Assert.Matches("^acr_[a-z2-7]{26}$", c.GetProperty("id").GetString());
            Assert.Equal("passkey", c.GetProperty("kind").GetString());
            Assert.Equal(
                ["backedUp", "createdAt", "id", "kind", "lastUsedAt", "removable"],
                c.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        });

        // Oldest first: the one signed in with has been used, the second hasn't.
        Assert.Equal(JsonValueKind.String, credentials[0].GetProperty("lastUsedAt").ValueKind);
        Assert.Equal(JsonValueKind.Null, credentials[1].GetProperty("lastUsedAt").ValueKind);

        foreach (var authenticator in authenticators)
        {
            Assert.DoesNotContain(Base64Url.EncodeToString(authenticator.CredentialId), text, StringComparison.Ordinal);
            Assert.DoesNotContain(Convert.ToHexStringLower(authenticator.CredentialId), text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(authenticator.Aaguid.ToString(), text, StringComparison.OrdinalIgnoreCase);
            authenticator.Dispose();
        }
    }

    [Fact]
    public async Task Removing_the_credential_that_confirmed_it_ends_this_Session_too()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, adminId, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var ids = await host.CredentialIdsAsync(cookie);

        // The first credential confirms its own removal.
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, ids[0]);
        using var removed = await host.RemoveCredentialAsync(cookie, csrf, ids[0]);

        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        Assert.Equal("""{"sessionEnded":true}""", await removed.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(string.Empty, AdminHost.CookieValue(removed, AdminHost.Cookie));
        using (var gone = await host.SendAsync(HttpMethod.Get, AdminHost.CredentialsPath, cookie))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, gone.StatusCode);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM admin_session WHERE admin_id = '{adminId}' AND ended_at IS NULL"));
        Assert.Equal(2L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_credential"));
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Confirming_the_same_binding_twice_leaves_one_grant_for_one_action()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);

        await host.ConfirmAsync(cookie, csrf, authenticators[0], Add);
        await host.ConfirmAsync(cookie, csrf, authenticators[1], Add);
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'verified'"));

        var (first, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (first)
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var (second, _) = await host.BeginRegistrationAsync(cookie, csrf);
        using (second)
        {
            await AssertProblemAsync(second, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Removing_a_credential_takes_its_grants_with_it_and_a_repeat_needs_a_new_one()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(3);
        var ids = await host.CredentialIdsAsync(cookie);

        // A grant made with B, for another action; then A confirms B's removal.
        await host.ConfirmAsync(cookie, csrf, authenticators[1], Add);
        await host.ConfirmAsync(cookie, csrf, authenticators[0], Remove, ids[1]);
        using (var removed = await host.RemoveCredentialAsync(cookie, csrf, ids[1]))
        {
            Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        }

        Assert.Equal(0L, await host.ScalarAsync<long>(
            $"SELECT count(*) FROM admin_fresh_assertion WHERE credential_id = '{RowOf(ids[1])}'"));
        Assert.Equal(0L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion"));

        using var again = await host.RemoveCredentialAsync(cookie, csrf, ids[1]);
        await AssertProblemAsync(again, HttpStatusCode.Forbidden, "fresh_assertion_required");
        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task Two_begins_at_once_in_one_Session_take_turns_and_leave_one_challenge()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var (cookie, csrf, _, authenticators) = await host.OwnerWithCredentialsAsync(2);

        var begins = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => host.BeginAssertionAsync(cookie, csrf, Add)));

        Assert.All(begins, b => Assert.Equal(HttpStatusCode.OK, b.Response.StatusCode));
        Assert.Equal(1L, await host.ScalarAsync<long>("SELECT count(*) FROM admin_fresh_assertion WHERE stage = 'challenge'"));
        foreach (var (response, _) in begins)
        {
            response.Dispose();
        }

        Assert.All(authenticators, a => a.Dispose());
    }

    [Fact]
    public async Task A_credential_stored_before_its_flags_were_kept_records_BE_on_its_first_assertion_then_holds_it()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        using var synced = new SoftwareAuthenticator { BackupEligible = true, BackedUp = true };
        using var key = new SoftwareAuthenticator();
        await host.AdminWithCredentialsAsync(synced, key);
        var id = Convert.ToHexStringLower(synced.CredentialId);

        // As the migration leaves every credential registered before it: both flags unknown.
        await PostgresFixture.ExecuteAsync(
            host.Superuser,
            "SET session_replication_role = replica; UPDATE admin_credential SET backup_eligible = NULL, backed_up = NULL; SET session_replication_role = origin;");

        await host.SignInAsync(synced);
        Assert.Equal("t t", await host.ScalarAsync<string>(
            $"SELECT backup_eligible::text::char || ' ' || backed_up::text::char FROM admin_credential WHERE credential_id = '\\x{id}'"));

        var (begin, options, binding) = await host.BeginSignInAsync();
        begin.Dispose();
        using var changed = await host.CompleteSignInAsync(binding, synced.Assert(options, AdminHost.Origin, new AssertionTweaks { BackupEligible = false, BackedUp = false }));
        await AssertProblemAsync(changed, HttpStatusCode.BadRequest, "signin_refused");
    }

    internal static async Task AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
        Assert.Matches("^[0-9a-f]{32}$", json.RootElement.GetProperty("traceId").GetString());
    }

    internal static Task<long> CountAsync(AdminHost host, string code) =>
        host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE type_code = '{code}'");

    private static Task<long> EventsAsync(AdminHost host) => host.ScalarAsync<long>("SELECT count(*) FROM deployment_audit_event");

    private static Guid RowOf(string publicId)
    {
        Assert.True(PublicId.TryParse(PublicIdType.AdminCredential, publicId, out var id));
        return id;
    }
}
