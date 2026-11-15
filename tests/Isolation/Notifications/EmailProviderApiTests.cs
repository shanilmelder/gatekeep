using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Management.Contracts;
using Gatekeep.Tests.Isolation.Admins;
using Gatekeep.Tests.Isolation.Custody;
using Npgsql;
using Xunit;
using static Gatekeep.Tests.Isolation.Tenancy.TenantRequests;

namespace Gatekeep.Tests.Isolation.Notifications;

/// <summary>
/// Story 4.4 (FR-36, FR-46, AD-5, AD-10, AD-20) on the real Host.Admin and PostgreSQL, with the OpenBao stand-in
/// encrypting: <c>GET</c>, <c>PUT</c> and <c>DELETE /api/v1/tenants/{tenantId}/email-provider</c>. Only the path Tenant's
/// Owner saves or removes, each time after a fresh assertion; the secret reaches custody bound to the Tenant and is
/// stored only as the ciphertext custody returned, which <c>gk_admin</c> can't select; and the real OpenBao proves
/// Host.Admin's custody can encrypt under the Tenant's email key but never decrypt. One test or more per row of the
/// story's matrix; no assertion prints a secret.
/// </summary>
[Collection(OpenBaoCollection.Name)]
public sealed class EmailProviderApiTests(PostgresFixture postgres, OpenBaoFixture bao)
{
    private const string Action = "tenant.email_provider.manage";

    private const string Updated = "notifications.email_provider.updated";
    private const string Removed = "notifications.email_provider.removed";

    private const string Denied = "type_code = 'admin.access.denied'";

    private const string SmtpBody =
        """{"kind":"smtp","settings":{"host":"smtp.example.com","port":587,"tls":"starttls","username":"mailer"},"fromAddress":"no-reply@example.com","fromName":"Example","secret":"cnry-smtp-password"}""";

    private const string CustomBody =
        """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com/send"},"fromAddress":"no-reply@example.com","secret":"cnry-header"}""";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task With_no_provider_every_role_reads_configured_false_only()
    {
        await using var setup = await SetupAsync();
        var (viewer, _, _) = await RoleSessionAsync(setup.Host, setup.Tenant, "viewer");

        foreach (var cookie in new[] { setup.Cookie, viewer })
        {
            using var response = await GetAsync(setup.Host, cookie, setup.Tenant);
            Assert.Equal("""{"configured":false}""", await BodyAsync(response));
        }
    }

    [Fact]
    public async Task The_Owner_saves_a_first_provider_and_only_custodys_ciphertext_is_stored_with_one_event()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, SmtpBody);

        var body = await BodyAsync(response);
        using (var json = JsonDocument.Parse(body))
        {
            var root = json.RootElement;
            Assert.Equal(
                ["configured", "kind", "settings", "fromAddress", "fromName", "updatedAt", "secretSet"],
                root.EnumerateObject().Select(p => p.Name));
            Assert.True(root.GetProperty("configured").GetBoolean());
            Assert.Equal("smtp", root.GetProperty("kind").GetString());
            Assert.Equal("""{"host":"smtp.example.com","port":587,"tls":"starttls","username":"mailer"}""", root.GetProperty("settings").GetRawText());
            Assert.Equal("no-reply@example.com", root.GetProperty("fromAddress").GetString());
            Assert.True(root.GetProperty("secretSet").GetBoolean());
        }

        Assert.DoesNotContain("cnry-smtp-password", body, StringComparison.Ordinal);
        Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);

        // Custody got the secret under the Tenant's email key, bound to its ID, and its answer is what is stored.
        var encrypted = Assert.Single(transit.Encrypted);
        Assert.Equal($"email-{setup.Tenant:D}", encrypted.Key);
        Assert.Equal("cnry-smtp-password", encrypted.Plaintext);
        Assert.Equal(setup.Tenant.ToString("D"), encrypted.AssociatedData);
        var stored = await CiphertextAsync(setup.Host, setup.Tenant);
        Assert.Equal(encrypted.Ciphertext, stored);
        Assert.StartsWith("vault:v1:", stored, StringComparison.Ordinal);
        Assert.Equal("smtp", await setup.Host.ScalarAsync<string>($"SELECT kind FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));

        Assert.Equal(1L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code = '{Updated}' AND actor_kind = 'admin' " +
            $"AND actor_id = '{setup.Owner}' AND target_kind = 'tenant' AND target_id = '{setup.Tenant}'"));
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_detail d JOIN audit_event e ON e.id = d.event_id WHERE e.tenant_id = '{setup.Tenant}' AND e.type_code = '{Updated}'"));
        Assert.DoesNotContain("cnry-smtp-password", setup.Host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_Admins_role_may_never_select_the_ciphertext()
    {
        await using var setup = await SetupAsync();
        _ = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var response = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        // In the Tenant's own scope, so the row-level security policy plans, and only the column grant can refuse.
        await using var connection = new NpgsqlConnection(setup.Host.AdminConnection);
        await connection.OpenAsync(Cancellation);
        await using (var scope = new NpgsqlCommand($"SELECT set_config('gatekeep.tenant_id', '{setup.Tenant}', false)", connection))
        {
            await scope.ExecuteNonQueryAsync(Cancellation);
        }

        await using (var allowed = new NpgsqlCommand("SELECT kind FROM email_provider", connection))
        {
            Assert.Equal("smtp", await allowed.ExecuteScalarAsync(Cancellation));
        }

        await using var command = new NpgsqlCommand("SELECT secret_ciphertext FROM email_provider", connection);
        var refused = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteScalarAsync(Cancellation));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, refused.SqlState);
    }

    /// <summary>
    /// The real OpenBao, with Host.Admin's own AppRole: a save through Management encrypts under the Tenant's
    /// <c>email-</c> key, Host.Admin's custody is refused the decrypt, and only Host.Worker's gets the secret back.
    /// </summary>
    [Fact]
    public async Task On_real_custody_Host_Admin_encrypts_but_only_Host_Worker_decrypts()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenant = bao.TenantA;
        await Gatekeep.Tests.Isolation.TestTenants.InsertAsync(postgres.SuperuserConnection(database), tenant);
        using var admin = bao.Custody(OpenBaoFixture.Admin);
        using var worker = bao.Custody(OpenBaoFixture.Worker);

        var management = ManagementContract.CreateEmailProviders(AuditContract.CreateAppender());
        await using (var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database)))
        await using (var scope = await TenantScope.BeginAsync(source, tenant, Cancellation))
        {
            using var settings = JsonDocument.Parse("""{"region":"eu"}""");
            var result = await management.SaveAsync(
                scope.CreateCommandContext(),
                admin,
                new AdminPrincipal(Guid.CreateVersion7(), false),
                new TenantRoleGrant(tenant, TenantRole.Owner),
                tenant,
                new EmailProviderSaveInput("sendgrid", settings.RootElement.Clone(), "no-reply@example.com", null, new Secret<string>("cnry-sendgrid-key")),
                Cancellation);
            Assert.Equal(EmailProviderStatus.Done, result.Status);
            Assert.True(result.Changed);
            await scope.CommitAsync(Cancellation);
        }

        var stored = await PostgresFixture.ScalarAsync<string>(
            postgres.SuperuserConnection(database), $"SELECT secret_ciphertext FROM email_provider WHERE tenant_id = '{tenant}'");
        Assert.Matches("^vault:v[0-9]+:[A-Za-z0-9+/=]+$", stored);
        Assert.DoesNotContain("cnry-sendgrid-key", stored, StringComparison.Ordinal);

        var key = KeyName.ForTenant(TenantKeyClass.Email, tenant);
        var refused = await Assert.ThrowsAsync<KeyCustodyException>(() => admin.DecryptAsync(key, tenant, new KeyCiphertext(stored), Cancellation));
        Assert.Equal(KeyCustodyFailure.Refused, refused.Failure);

        var plaintext = await worker.DecryptAsync(key, tenant, new KeyCiphertext(stored), Cancellation);
        Assert.Equal("cnry-sendgrid-key", plaintext.Use(Encoding.UTF8.GetString));
    }

    [Fact]
    public async Task A_save_of_the_same_settings_with_no_secret_keeps_the_ciphertext_and_changes_the_sender()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await CiphertextAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using var response = await PutAsync(
            setup,
            """{"kind":"smtp","settings":{"host":"smtp.example.com","port":587,"tls":"starttls","username":"mailer"},"fromAddress":"no-reply@example.com","fromName":"Other"}""");

        using (var json = JsonDocument.Parse(await BodyAsync(response)))
        {
            Assert.Equal("Other", json.RootElement.GetProperty("fromName").GetString());
            Assert.True(json.RootElement.GetProperty("secretSet").GetBoolean());
        }

        Assert.Equal(before, await CiphertextAsync(setup.Host, setup.Tenant));
        Assert.Single(transit.Encrypted);
        Assert.Equal("Other", await setup.Host.ScalarAsync<string>($"SELECT from_name FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
        Assert.Equal(2L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    public static TheoryData<string, string> Destinations => new()
    {
        { SmtpBody, """{"kind":"smtp","settings":{"host":"smtp.attacker.example","port":587,"tls":"starttls","username":"mailer"},"fromAddress":"no-reply@example.com"}""" },
        { SmtpBody, """{"kind":"smtp","settings":{"host":"smtp.example.com","port":2525,"tls":"starttls","username":"mailer"},"fromAddress":"no-reply@example.com"}""" },
        { SmtpBody, """{"kind":"smtp","settings":{"host":"smtp.example.com","port":587,"tls":"starttls","username":"other"},"fromAddress":"no-reply@example.com"}""" },
        { CustomBody, """{"kind":"custom_http","settings":{"endpoint":"https://attacker.example/collect"},"fromAddress":"no-reply@example.com"}""" },
        { CustomBody, """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com/send","authHeaderName":"X-Leak"},"fromAddress":"no-reply@example.com"}""" },
        {
            """{"kind":"sendgrid","settings":{"region":"global"},"fromAddress":"no-reply@example.com","secret":"cnry-key"}""",
            """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"no-reply@example.com"}"""
        },
    };

    /// <summary>A stored secret is kept only for the destination it was given for: any other needs a new one.</summary>
    [Theory]
    [MemberData(nameof(Destinations))]
    public async Task A_changed_destination_with_no_secret_is_400_secret_required_and_nothing_is_written(string first, string changed)
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var saved = await PutAsync(setup, first))
        {
            Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        }

        var before = await RowAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, changed);

        Assert.Equal([("secret", "required")], await ErrorsAsync(response));
        Assert.Equal(before, await RowAsync(setup.Host, setup.Tenant));
        Assert.Single(transit.Encrypted);
        Assert.Equal(1L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task Postmarks_message_stream_changes_with_no_secret_and_keeps_it()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, """{"kind":"postmark","settings":{"messageStream":"outbound"},"fromAddress":"no-reply@example.com","secret":"cnry-token"}"""))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await CiphertextAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, """{"kind":"postmark","settings":{"messageStream":"broadcast"},"fromAddress":"no-reply@example.com"}""");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before, await CiphertextAsync(setup.Host, setup.Tenant));
        Assert.Single(transit.Encrypted);
        Assert.Equal(2L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task SMTP_dropping_its_username_with_no_secret_clears_the_ciphertext_with_one_more_event()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        await setup.ConfirmAsync();
        using var response = await PutAsync(
            setup, """{"kind":"smtp","settings":{"host":"smtp.example.com","port":587,"tls":"starttls"},"fromAddress":"no-reply@example.com"}""");

        using (var json = JsonDocument.Parse(await BodyAsync(response)))
        {
            Assert.False(json.RootElement.GetProperty("secretSet").GetBoolean());
        }

        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(secret_ciphertext) FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
        Assert.Single(transit.Encrypted);
        Assert.Equal(2L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task The_same_kind_with_a_new_secret_encrypts_it_and_replaces_the_ciphertext_with_one_more_event()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await CiphertextAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using (var response = await PutAsync(setup, SmtpBody.Replace("cnry-smtp-password", "cnry-smtp-password-2", StringComparison.Ordinal)))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.Equal(2, transit.Encrypted.Count);
        Assert.Equal("cnry-smtp-password-2", transit.Encrypted[1].Plaintext);
        var after = await CiphertextAsync(setup.Host, setup.Tenant);
        Assert.Equal(transit.Encrypted[1].Ciphertext, after);
        Assert.NotEqual(before, after);
        Assert.Equal(2L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task SMTP_gaining_a_username_with_no_secret_is_400_secret_required_and_nothing_is_written()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(
            setup, """{"kind":"smtp","settings":{"host":"smtp.example.com","port":25,"tls":"starttls"},"fromAddress":"no-reply@example.com"}"""))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await RowAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using var response = await PutAsync(
            setup, """{"kind":"smtp","settings":{"host":"smtp.example.com","port":25,"tls":"starttls","username":"mailer"},"fromAddress":"no-reply@example.com"}""");

        Assert.Equal([("secret", "required")], await ErrorsAsync(response));
        Assert.Equal(before, await RowAsync(setup.Host, setup.Tenant));
        Assert.Empty(transit.Encrypted);
        Assert.Equal(1L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task A_change_of_kind_with_no_secret_is_400_secret_required_and_nothing_is_written()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await RowAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"no-reply@example.com"}""");

        Assert.Equal([("secret", "required")], await ErrorsAsync(response));
        Assert.Equal(before, await RowAsync(setup.Host, setup.Tenant));
        Assert.Single(transit.Encrypted);
        Assert.Equal(1L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task An_identical_save_with_no_secret_is_200_and_writes_nothing()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        var before = await RowAsync(setup.Host, setup.Tenant);

        await setup.ConfirmAsync();
        using var response = await PutAsync(
            setup,
            """{"kind":"smtp","settings":{"tls":"starttls","username":"mailer","port":587,"host":"smtp.example.com"},"fromAddress":"no-reply@example.com","fromName":"Example"}""");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(before, await RowAsync(setup.Host, setup.Tenant));
        Assert.Single(transit.Encrypted);
        Assert.Equal(1L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    public static TheoryData<string, string, string> Kinds => new()
    {
        { "smtp", """{"host":"1.1.1.1","port":465,"tls":"implicit"}""", """{"host":"1.1.1.1","port":465,"tls":"implicit"}""" },
        // A username of white space only is none: the provider takes no secret.
        { "smtp", """{"host":"smtp.example.com","port":25,"tls":"starttls","username":"   "}""", """{"host":"smtp.example.com","port":25,"tls":"starttls"}""" },
        { "sendgrid", """{"region":"global"}""", """{"region":"global"}""" },
        { "postmark", """{"messageStream":"outbound-1"}""", """{"messageStream":"outbound-1"}""" },
        { "postmark", "{}", "{}" },
        { "mailgun", """{"domain":"mg.example.com","region":"eu"}""", """{"region":"eu","domain":"mg.example.com"}""" },
        { "ses", """{"region":"eu-west-1","accessKeyId":"AKIAIOSFODNN7EXAMPLE"}""", """{"region":"eu-west-1","accessKeyId":"AKIAIOSFODNN7EXAMPLE"}""" },
        { "custom_http", """{"endpoint":"https://mail.example.com/send"}""", """{"endpoint":"https://mail.example.com/send","authHeaderName":"Authorization"}""" },
        { "custom_http", """{"endpoint":"https://mail.example.com/send","authHeaderName":"X-Api-Key"}""", """{"endpoint":"https://mail.example.com/send","authHeaderName":"X-Api-Key"}""" },
    };

    [Theory]
    [MemberData(nameof(Kinds))]
    public async Task Each_kind_is_stored_and_read_back_with_its_settings(string kind, string settings, string echoed)
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        var secret = kind == "smtp" ? string.Empty : ",\"secret\":\"cnry-provider-secret\"";

        await setup.ConfirmAsync();
        using (var response = await PutAsync(setup, $$"""{"kind":"{{kind}}","settings":{{settings}},"fromAddress":"no-reply@example.com"{{secret}}}"""))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        var (viewer, _, _) = await RoleSessionAsync(setup.Host, setup.Tenant, "viewer");
        using var read = await GetAsync(setup.Host, viewer, setup.Tenant);
        var body = await BodyAsync(read);
        using var json = JsonDocument.Parse(body);
        Assert.Equal(kind, json.RootElement.GetProperty("kind").GetString());
        Assert.Equal(echoed, json.RootElement.GetProperty("settings").GetRawText());
        Assert.Equal(kind != "smtp", json.RootElement.GetProperty("secretSet").GetBoolean());
        Assert.False(json.RootElement.TryGetProperty("fromName", out _));
        Assert.DoesNotContain("cnry-provider-secret", body, StringComparison.Ordinal);
        Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);
        Assert.Equal(kind == "smtp" ? 0 : 1, transit.Encrypted.Count);
        Assert.Equal(kind == "smtp" ? 0L : 1L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(secret_ciphertext) FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
    }

    public static TheoryData<string, string> BadFields => new()
    {
        { """{"kind":"custom_http","settings":{"endpoint":"http://mail.example.com/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://127.0.0.1/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[::1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://10.1.2.3/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://localhost/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://192.0.0.8/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://192.0.2.1/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://198.18.0.1/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://198.19.255.1/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://198.51.100.7/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://203.0.113.5/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://192.88.99.1/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[64:ff9b::a00:1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[64:ff9b::7f00:1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[2002:a00:1::1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[2002:7f00:1::1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[::a00:1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[2001:db8::1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://[::ffff:10.0.0.1]/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://user:pw@mail.example.com/send"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com/send#x"},"fromAddress":"a@example.com","secret":"s"}""", "settings.endpoint:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com","authHeaderName":"Bad Header"},"fromAddress":"a@example.com","secret":"s"}""", "settings.authHeaderName:invalid" },
        // Story 4.5: a header that frames or routes the request is refused.
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com","authHeaderName":"Host"},"fromAddress":"a@example.com","secret":"s"}""", "settings.authHeaderName:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com","authHeaderName":"content-length"},"fromAddress":"a@example.com","secret":"s"}""", "settings.authHeaderName:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com","authHeaderName":"Proxy-Authorization"},"fromAddress":"a@example.com","secret":"s"}""", "settings.authHeaderName:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com","authHeaderName":"Expect"},"fromAddress":"a@example.com","secret":"s"}""", "settings.authHeaderName:invalid" },
        { """{"kind":"custom_http","settings":{"endpoint":"https://mail.example.com","authHeaderName":"keep-alive"},"fromAddress":"a@example.com","secret":"s"}""", "settings.authHeaderName:invalid" },
        { """{"kind":"smtp","settings":{"host":"smtp.example.com","port":0,"tls":"starttls"},"fromAddress":"a@example.com"}""", "settings.port:invalid" },
        { """{"kind":"smtp","settings":{"host":"smtp.example.com","port":"587","tls":"starttls"},"fromAddress":"a@example.com"}""", "settings.port:invalid" },
        { """{"kind":"smtp","settings":{"host":"smtp.example.com","port":25,"tls":"none"},"fromAddress":"a@example.com"}""", "settings.tls:invalid" },
        { """{"kind":"smtp","settings":{"host":"192.168.1.10","port":25,"tls":"starttls"},"fromAddress":"a@example.com"}""", "settings.host:invalid" },
        { """{"kind":"smtp","settings":{"port":25,"tls":"starttls"},"fromAddress":"a@example.com"}""", "settings.host:required" },
        { """{"kind":"smtp","settings":{"host":"smtp.example.com","port":25,"tls":"starttls"},"fromAddress":"a@example.com","secret":"unused"}""", "secret:invalid" },
        { """{"kind":"smtp","settings":{"host":"smtp.example.com","port":25,"tls":"starttls","username":"mailer"},"fromAddress":"a@example.com"}""", "secret:required" },
        { """{"kind":"sendgrid","settings":{"region":"eu","extra":1},"fromAddress":"a@example.com","secret":"s"}""", "settings:invalid" },
        { """{"kind":"sendgrid","settings":{"region":"eu","host":"smtp.example.com"},"fromAddress":"a@example.com","secret":"s"}""", "settings:invalid" },
        { """{"kind":"sendgrid","settings":{"region":"us"},"fromAddress":"a@example.com","secret":"s"}""", "settings.region:invalid" },
        { """{"kind":"ses","settings":{"region":"EU-WEST-1","accessKeyId":"AKIAIOSFODNN7EXAMPLE"},"fromAddress":"a@example.com","secret":"s"}""", "settings.region:invalid" },
        { """{"kind":"ses","settings":{"region":"eu-west-1","accessKeyId":"short"},"fromAddress":"a@example.com","secret":"s"}""", "settings.accessKeyId:invalid" },
        { """{"kind":"mailgun","settings":{"domain":"mg..example.com","region":"eu"},"fromAddress":"a@example.com","secret":"s"}""", "settings.domain:invalid" },
        { """{"kind":"postmark","settings":{"messageStream":"bad stream"},"fromAddress":"a@example.com","secret":"s"}""", "settings.messageStream:invalid" },
        { """{"kind":"pigeon","settings":{},"fromAddress":"a@example.com","secret":"s"}""", "kind:invalid" },
        { """{"settings":{},"fromAddress":"a@example.com","secret":"s"}""", "kind:required" },
        { """{"kind":"sendgrid","settings":{"region":"eu"},"secret":"s"}""", "fromAddress:required" },
        { """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"not an address","secret":"s"}""", "fromAddress:invalid" },
        { """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"a@example.com","fromName":"Bad\u0007Name","secret":"s"}""", "fromName:invalid" },
        { """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"a@example.com","secret":""}""", "secret:invalid" },
        { """{"kind":"sendgrid","settings":{"region":"eu"},"fromAddress":"a@example.com","secret":"a\u0000b"}""", "secret:invalid" },
        { """{"kind":"sendgrid","settings":"eu","fromAddress":"a@example.com","secret":"s"}""", "settings:invalid" },
    };

    [Theory]
    [MemberData(nameof(BadFields))]
    public async Task A_refused_field_is_400_naming_it_and_nothing_is_written(string body, string error)
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, body);

        var errors = await ErrorsAsync(response);
        Assert.Contains((error.Split(':')[0], error.Split(':')[1]), errors);
        Assert.Empty(transit.Encrypted);
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
        Assert.Equal(0L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
    }

    [Fact]
    public async Task Too_long_fields_are_400_too_long()
    {
        await using var setup = await SetupAsync();
        _ = new EmailTransit(setup.Host);

        await setup.ConfirmAsync();
        var body = JsonSerializer.Serialize(new
        {
            kind = "sendgrid",
            settings = new { region = "eu" },
            fromAddress = new string('a', 250) + "@example.com",
            fromName = new string('n', 129),
            secret = new string('s', 4097),
        });
        using var response = await PutAsync(setup, body);

        Assert.Equal(
            [("fromAddress", "too_long"), ("fromName", "too_long"), ("secret", "too_long")],
            (await ErrorsAsync(response)).Order());
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"kind":7,"settings":{},"fromAddress":"a@example.com"}""")]
    [InlineData("null")]
    public async Task A_malformed_body_is_400_with_no_errors_and_nothing_is_written(string body)
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("email_provider_invalid", json.RootElement.GetProperty("code").GetString());
        Assert.False(json.RootElement.TryGetProperty("errors", out _));
        Assert.Empty(transit.Encrypted);
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
    }

    [Fact]
    public async Task Without_a_fresh_assertion_a_save_or_removal_is_403_and_nothing_is_written()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        await SeedAsync(setup.Host, setup.Tenant);
        var before = await RowAsync(setup.Host, setup.Tenant);

        using (var put = await PutAsync(setup, SmtpBody))
        {
            await FreshAssertionTests.AssertProblemAsync(put, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        using (var delete = await DeleteAsync(setup.Host, setup.Cookie, setup.Csrf, setup.Tenant))
        {
            await FreshAssertionTests.AssertProblemAsync(delete, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        // A grant more than 5 minutes old serves neither.
        await setup.ConfirmAsync();
        await PostgresFixture.ExecuteAsync(
            setup.Host.Superuser,
            "UPDATE admin_fresh_assertion SET created_at = created_at - interval '6 minutes', expires_at = expires_at - interval '6 minutes'");
        using (var stale = await PutAsync(setup, SmtpBody))
        {
            await FreshAssertionTests.AssertProblemAsync(stale, HttpStatusCode.Forbidden, "fresh_assertion_required");
        }

        Assert.Empty(transit.Encrypted);
        Assert.Equal(before, await RowAsync(setup.Host, setup.Tenant));
        Assert.Equal(0L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
        Assert.Equal(0L, await TenantEventsAsync(setup.Host, setup.Tenant, Removed));
    }

    [Theory]
    [InlineData("editor")]
    [InlineData("viewer")]
    public async Task An_Editor_or_a_Viewer_is_403_for_a_save_or_removal_audited_and_nothing_changes(string role)
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var transit = new EmailTransit(host);
        var tenant = await InsertAsync(host);
        await SeedAsync(host, tenant);
        var before = await RowAsync(host, tenant);
        var (cookie, csrf, _) = await RoleSessionAsync(host, tenant, role);

        using (var put = await host.SendAsync(HttpMethod.Put, Path(tenant), cookie, csrf, AdminHost.Origin, SmtpBody, [(Header, Id(tenant))]))
        {
            Assert.Equal(HttpStatusCode.Forbidden, put.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(put));
        }

        using (var delete = await DeleteAsync(host, cookie, csrf, tenant))
        {
            Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(delete));
        }

        // Read-only, the same provider every role reads, and never its secret.
        using (var read = await GetAsync(host, cookie, tenant))
        {
            var body = await BodyAsync(read);
            Assert.Contains("\"secretSet\":true", body, StringComparison.Ordinal);
            Assert.DoesNotContain("vault:", body, StringComparison.Ordinal);
        }

        Assert.Empty(transit.Encrypted);
        Assert.Equal(before, await RowAsync(host, tenant));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Updated));
        Assert.Equal(0L, await TenantEventsAsync(host, tenant, Removed));
        Assert.Equal(2L, await host.ScalarAsync<long>($"SELECT count(*) FROM deployment_audit_event WHERE {Denied} AND target_id = '{tenant}'"));
    }

    /// <summary>
    /// A machine principal of the path Tenant, at the request checks' own decision: Host.Admin authenticates no machine
    /// client before Epic 17, so this is as near the endpoint as one can reach. The capability both PUT and DELETE declare
    /// is refused it, and nothing is written.
    /// </summary>
    [Fact]
    public async Task A_machine_principal_of_the_Tenant_is_refused_the_save_and_the_removal_and_nothing_is_written()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenant = Guid.CreateVersion7();
        var superuser = postgres.SuperuserConnection(database);
        await Gatekeep.Tests.Isolation.TestTenants.InsertAsync(superuser, tenant);
        var authorization = AdminsContract.CreateAuthorization(AuditContract.CreateAppender());

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using (var scope = await DeploymentScope.BeginAsync(source, Cancellation))
        {
            var context = scope.CreateCommandContext();
            var machine = TestOnlyMachinePrincipal.For(tenant);
            Assert.False((await authorization.AuthorizeAsync(context, machine, AdminCapabilities.TenantEmailProviderManage, tenant, Cancellation)).Allowed);
            Assert.True((await authorization.AuthorizeAsync(context, machine, AdminCapabilities.TenantConfigurationRead, tenant, Cancellation)).Allowed);
            await scope.CommitAsync(Cancellation);
        }

        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM email_provider"));
        Assert.Equal(0L, await PostgresFixture.ScalarAsync<long>(superuser, "SELECT count(*) FROM audit_event WHERE type_code LIKE 'notifications.%'"));
    }

    [Fact]
    public void A_machine_principal_an_Editor_and_a_Viewer_are_never_allowed_the_change()
    {
        var tenant = Guid.CreateVersion7();
        var capability = AdminCapabilities.TenantEmailProviderManage;

        Assert.False(capability.MachineAllowed);
        Assert.Equal(FreshAssertion.Always, capability.FreshAssertion);
        Assert.False(AdminCapabilities.Allows(capability, new MachinePrincipal(Guid.CreateVersion7(), tenant), null, tenant));
        Assert.False(AdminCapabilities.Allows(capability, new AdminPrincipal(Guid.CreateVersion7(), true), new TenantRoleGrant(tenant, TenantRole.Editor), tenant));
        Assert.False(AdminCapabilities.Allows(capability, new AdminPrincipal(Guid.CreateVersion7(), true), new TenantRoleGrant(tenant, TenantRole.Viewer), tenant));
        Assert.True(AdminCapabilities.Allows(capability, new AdminPrincipal(Guid.CreateVersion7(), false), new TenantRoleGrant(tenant, TenantRole.Owner), tenant));
    }

    [Fact]
    public async Task The_Owner_removes_the_provider_with_one_event_and_removing_none_is_the_same_204_with_none()
    {
        await using var setup = await SetupAsync();
        _ = new EmailTransit(setup.Host);
        await setup.ConfirmAsync();
        using (var first = await PutAsync(setup, SmtpBody))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }

        await setup.ConfirmAsync();
        using (var removed = await DeleteAsync(setup.Host, setup.Cookie, setup.Csrf, setup.Tenant))
        {
            Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
            Assert.Equal("no-store", removed.Headers.CacheControl?.ToString());
        }

        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
        Assert.Equal(1L, await setup.Host.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{setup.Tenant}' AND type_code = '{Removed}' AND actor_kind = 'admin' " +
            $"AND actor_id = '{setup.Owner}' AND target_kind = 'tenant' AND target_id = '{setup.Tenant}'"));

        await setup.ConfirmAsync();
        using (var again = await DeleteAsync(setup.Host, setup.Cookie, setup.Csrf, setup.Tenant))
        {
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }

        Assert.Equal(1L, await TenantEventsAsync(setup.Host, setup.Tenant, Removed));
        using var read = await GetAsync(setup.Host, setup.Cookie, setup.Tenant);
        Assert.Equal("""{"configured":false}""", await BodyAsync(read));
    }

    [Fact]
    public async Task Another_Tenants_Owner_is_403_and_neither_Tenant_changes()
    {
        await using var host = await AdminHost.StartAsync(postgres);
        var transit = new EmailTransit(host);
        var a = await InsertAsync(host);
        var b = await InsertAsync(host);
        await SeedAsync(host, a);
        var before = await RowAsync(host, a);
        var (cookie, csrf, _) = await RoleSessionAsync(host, b, "owner");

        using (var read = await GetAsync(host, cookie, a))
        {
            Assert.Equal(HttpStatusCode.Forbidden, read.StatusCode);
            Assert.Equal("access_denied", await CodeAsync(read));
        }

        using (var put = await host.SendAsync(HttpMethod.Put, Path(a), cookie, csrf, AdminHost.Origin, SmtpBody, [(Header, Id(a))]))
        {
            Assert.Equal(HttpStatusCode.Forbidden, put.StatusCode);
        }

        using (var delete = await DeleteAsync(host, cookie, csrf, a))
        {
            Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        }

        Assert.Empty(transit.Encrypted);
        Assert.Equal(before, await RowAsync(host, a));
        Assert.Equal(0L, await host.ScalarAsync<long>($"SELECT count(*) FROM email_provider WHERE tenant_id = '{b}'"));
    }

    [Fact]
    public async Task Custody_refusing_the_encrypt_is_503_and_nothing_is_written()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host) { Refuse = true };

        await setup.ConfirmAsync();
        using var response = await PutAsync(setup, SmtpBody);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty(transit.Encrypted);
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>($"SELECT count(*) FROM email_provider WHERE tenant_id = '{setup.Tenant}'"));
        Assert.Equal(0L, await TenantEventsAsync(setup.Host, setup.Tenant, Updated));
        Assert.DoesNotContain("cnry-smtp-password", setup.Host.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_different_page_Tenant_is_409_tenant_mismatch_and_nothing_runs()
    {
        await using var setup = await SetupAsync();
        var transit = new EmailTransit(setup.Host);
        var b = await InsertAsync(setup.Host);

        using var response = await setup.Host.SendAsync(
            HttpMethod.Put, Path(setup.Tenant), setup.Cookie, setup.Csrf, AdminHost.Origin, SmtpBody, [(Header, Id(b))]);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("tenant_mismatch", await CodeAsync(response));
        Assert.Empty(transit.Encrypted);
        Assert.Equal(0L, await setup.Host.ScalarAsync<long>("SELECT count(*) FROM email_provider"));
    }

    private static string Path(Guid tenant) => $"/api/v1/tenants/{Id(tenant)}/email-provider";

    private static Task<HttpResponseMessage> GetAsync(AdminHost host, string cookie, Guid tenant) =>
        host.SendAsync(HttpMethod.Get, Path(tenant), cookie);

    private static Task<HttpResponseMessage> PutAsync(Setup setup, string body) =>
        setup.Host.SendAsync(HttpMethod.Put, Path(setup.Tenant), setup.Cookie, setup.Csrf, AdminHost.Origin, body, [(Header, Id(setup.Tenant))]);

    private static Task<HttpResponseMessage> DeleteAsync(AdminHost host, string cookie, string csrf, Guid tenant) =>
        host.SendAsync(HttpMethod.Delete, Path(tenant), cookie, csrf, AdminHost.Origin, headers: [(Header, Id(tenant))]);

    private static async Task<string> BodyAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        return await response.Content.ReadAsStringAsync(Cancellation);
    }

    /// <summary>A 400 <c>email_provider_invalid</c>'s errors, as field and reason; each has a null index.</summary>
    private static async Task<List<(string Field, string Reason)>> ErrorsAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
        Assert.Equal("email_provider_invalid", json.RootElement.GetProperty("code").GetString());
        var errors = json.RootElement.GetProperty("errors").EnumerateArray().ToList();
        Assert.All(errors, e => Assert.Equal(JsonValueKind.Null, e.GetProperty("index").ValueKind));
        return [.. errors.Select(e => (e.GetProperty("field").GetString()!, e.GetProperty("reason").GetString()!))];
    }

    /// <summary>A stored SendGrid provider, as the superuser, with a stand-in ciphertext.</summary>
    private static Task SeedAsync(AdminHost host, Guid tenant) =>
        PostgresFixture.ExecuteAsync(
            host.Superuser,
            "INSERT INTO email_provider (tenant_id, kind, settings, from_address, secret_ciphertext) " +
            $"VALUES ('{tenant}', 'sendgrid', '{{\"region\":\"eu\"}}', 'no-reply@example.com', 'vault:v1:c2VlZGVk')");

    private static Task<string> CiphertextAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<string>($"SELECT secret_ciphertext FROM email_provider WHERE tenant_id = '{tenant}'");

    /// <summary>Every column of the Tenant's row, so any change shows.</summary>
    private static Task<string> RowAsync(AdminHost host, Guid tenant) =>
        host.ScalarAsync<string>($"SELECT coalesce((SELECT to_jsonb(p)::text FROM email_provider p WHERE tenant_id = '{tenant}'), '')");

    private async Task<Setup> SetupAsync()
    {
        var host = await AdminHost.StartAsync(postgres);
        var tenant = await InsertAsync(host);
        var (cookie, csrf, owner, authenticators) = await OwnerOfAsync(host, tenant);
        return new Setup(host, tenant, cookie, csrf, owner, authenticators);
    }

    /// <summary>
    /// The OpenBao stand-in's Transit encrypt for <c>email-</c> keys: each request's key, plaintext and associated data are
    /// recorded, and it answers a ciphertext that holds none of them, or 503 while <see cref="Refuse"/> is set.
    /// </summary>
    private sealed class EmailTransit
    {
        private readonly ConcurrentQueue<Encryption> _encrypted = new();

        public EmailTransit(AdminHost host)
        {
            host.OpenBao.RespondToBody = (path, body) =>
            {
                const string Encrypt = "/transit/encrypt/";
                var at = path.IndexOf(Encrypt, StringComparison.Ordinal);
                if (at < 0)
                {
                    return AdminHost.Custody(path, body);
                }

                var key = path[(at + Encrypt.Length)..].Split('?')[0];
                if (!key.StartsWith("email-", StringComparison.Ordinal))
                {
                    return (403, """{"errors":["permission denied"]}""");
                }

                if (Refuse)
                {
                    return (503, """{"errors":["sealed"]}""");
                }

                using var json = JsonDocument.Parse(body);
                var ciphertext = "vault:v1:" + Convert.ToBase64String(Guid.NewGuid().ToByteArray());
                _encrypted.Enqueue(new Encryption(
                    key,
                    Encoding.UTF8.GetString(Convert.FromBase64String(json.RootElement.GetProperty("plaintext").GetString()!)),
                    Encoding.UTF8.GetString(Convert.FromBase64String(json.RootElement.GetProperty("associated_data").GetString()!)),
                    ciphertext));
                return (200, JsonSerializer.Serialize(new { data = new { ciphertext } }));
            };
        }

        public bool Refuse { get; set; }

        public IReadOnlyList<Encryption> Encrypted => [.. _encrypted];
    }

    private sealed record Encryption(string Key, string Plaintext, string AssociatedData, string Ciphertext);

    /// <summary>One test's Admin host, Tenant and its Owner, whose changes confirm against <see cref="Authenticators"/>.</summary>
    private sealed class Setup(AdminHost host, Guid tenant, string cookie, string csrf, Guid owner, SoftwareAuthenticator[] authenticators) : IAsyncDisposable
    {
        private int _calls;

        public AdminHost Host => host;

        public Guid Tenant => tenant;

        public string Cookie { get; private set; } = cookie;

        public string Csrf { get; private set; } = csrf;

        public Guid Owner => owner;

        /// <summary>Confirms tenant.email_provider.manage in the Tenant: the Tenant begin, the sheet and the complete.</summary>
        public async Task ConfirmAsync()
        {
            // A Session may make only so many fresh-assertion calls (a begin and a complete each).
            if (_calls + 2 > Gatekeep.Kernel.Limits.SecurityLimits.FreshAssertionAttempts)
            {
                (Cookie, Csrf) = await Host.SignInAsync(authenticators[0]);
                _calls = 0;
            }

            _calls += 2;
            var (begin, options) = await BeginAsync(Host, Cookie, Csrf, Tenant, JsonSerializer.Serialize(new { action = Action, target = (string?)null }));
            using (begin)
            {
                Assert.Equal(HttpStatusCode.OK, begin.StatusCode);
            }

            using var complete = await Host.CompleteAssertionAsync(Cookie, Csrf, authenticators[0].Assert(options, AdminHost.Origin));
            Assert.Equal(HttpStatusCode.NoContent, complete.StatusCode);
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var authenticator in authenticators)
            {
                authenticator.Dispose();
            }

            await Host.DisposeAsync();
        }
    }
}
