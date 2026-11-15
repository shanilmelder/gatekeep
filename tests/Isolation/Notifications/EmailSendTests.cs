using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Email;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Notifications.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Tests.Isolation.Jobs;
using Xunit;
using static Gatekeep.Tests.Isolation.Jobs.JobDatabase;

namespace Gatekeep.Tests.Isolation.Notifications;

/// <summary>
/// Story 4.5 (FR-36, AR-18, AD-14, AD-15, AD-26): <c>notifications.email.send</c> through the real job runner, as
/// <c>gk_worker</c>. The recipient is resolved from the User's ID at send time; the link token or code travels only as
/// Transit ciphertext and is erased when the job finishes; the link's host is the Tenant's stored email link base; the
/// template is fixed substitution only; one recipient gets at most five emails in 15 minutes, the rest held back; and each
/// provider kind's adapter reaches its provider through the vetted egress path only, with the request shape and auth it
/// documents. Every path that ends a job writes one event naming the User, and no log line holds an address or a link.
/// </summary>
public sealed class EmailSendTests(PostgresFixture postgres)
{
    private const string Address = "recipient@example.test";
    private const string ProviderSecret = "provider-secret-7d1f3c";
    private const string FromAddress = "no-reply@tenant.example";
    private const string FromName = "Tenant Mail";

    /// <summary>A token with characters a URL must encode.</summary>
    private const string Token = "tok+en/7d1f=3c";

    private static readonly string Sent = NotificationsEvents.EmailSent.Code.Value;
    private static readonly string Undeliverable = NotificationsEvents.EmailUndeliverable.Code.Value;
    private static readonly string HeldBack = NotificationsEvents.EmailHeldBack.Code.Value;

    private static string LinkBase => $"https://{TestTenants.Host(TenantA)}/";

    [Fact]
    public void Type_is_registered_for_one_Tenant_enqueued_by_Hosted_and_Worker_and_run_as_gk_worker()
    {
        var definition = OperationsContract.ProductionRegistry.Find(OperationsContract.SendEmail)!;

        Assert.Equal("notifications.email.send", definition.Type.Value);
        Assert.Equal(NotificationsContract.SendEmailJob, definition.Type);
        Assert.Equal((JobScope.Tenant, TableRegistry.Worker, 5), (definition.Scope, definition.RunAs, definition.MaxAttempts));
        Assert.Equal(new[] { TableRegistry.Hosted, TableRegistry.Worker }, definition.EnqueuingRoles);
        Assert.True(definition.MayCarryCredential);
        Assert.False(definition.NeverDead);
        Assert.Equal(5, NotificationsContract.EmailTemplateIds.Distinct().Count());
    }

    /// <summary>The acceptance path: resolved at send time, ciphertext in the payload, erased after, host from the stored issuer.</summary>
    [Fact]
    public async Task Verification_is_sent_to_the_address_at_send_time_with_the_stored_link_base_and_its_payload_erased()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.VerificationTemplate, Token);

        var ciphertext = await database.ScalarAsync<string>($"SELECT ciphertext FROM job_payload WHERE job_id = '{job}'");
        Assert.StartsWith("vault:v1:", ciphertext, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, ciphertext, StringComparison.Ordinal);
        Assert.DoesNotContain(Address, await database.ScalarAsync<string>($"SELECT ids::text FROM job_payload WHERE job_id = '{job}'"), StringComparison.Ordinal);

        var sender = new RecordingEmailSender();
        var logger = new RecordingLogger();
        await RunAsync(database, custody, sender, logger);

        var send = Assert.Single(sender.Sends);
        var link = $"{LinkBase}login/verify-email?token={Uri.EscapeDataString(Token)}";
        Assert.Equal(("sendgrid", ProviderSecret), (send.Kind, send.Secret));
        Assert.Equal(new EmailMessage(FromAddress, FromName, Address, "Verify your email for Test Tenant",
            $"Confirm this address to finish setting up your Test Tenant account:\n\n{link}\n\nIf you didn't ask for this, ignore this email."),
            send.Message);
        Assert.Contains($"payload-{TenantA}", custody.KeysUsed);
        Assert.Contains($"email-{TenantA}", custody.KeysUsed);

        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job_payload WHERE job_id = '{job}'"));
        Assert.Equal(1L, await EventsAsync(database, Sent, user));
        Assert.Equal(1L, await EventsAsync(database, null, null));
        AssertNoValueLogged(logger, link);
    }

    [Fact]
    public async Task Address_changed_after_enqueue_is_the_one_used()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        await database.SuperuserAsync($"UPDATE \"user\" SET email = 'changed@example.test' WHERE id = '{user}'");

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        Assert.Equal("changed@example.test", Assert.Single(sender.Sends).Message.To);
        Assert.Equal(1L, await EventsAsync(database, Sent, user));
    }

    [Fact]
    public async Task Tenant_override_is_used_and_its_link_goes_to_the_reset_path()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        await OverrideAsync(database, NotificationsContract.PasswordResetTemplate, "Reset at {{tenant_name}}", "Go: {{link}}");
        await EnqueueAsync(database, custody, user, NotificationsContract.PasswordResetTemplate, Token);

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        var message = Assert.Single(sender.Sends).Message;
        Assert.Equal("Reset at Test Tenant", message.Subject);
        Assert.Equal($"Go: {LinkBase}login/reset-password?token={Uri.EscapeDataString(Token)}", message.Body);
    }

    [Fact]
    public async Task Unknown_or_not_allowed_variable_stays_literal_and_nothing_else_is_substituted()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        await OverrideAsync(database, NotificationsContract.PasswordResetTemplate, "Hi", "{{user.password}} {{code}} {{ link }} {{link}}");
        await EnqueueAsync(database, custody, user, NotificationsContract.PasswordResetTemplate, Token);

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        Assert.Equal(
            $"{{{{user.password}}}} {{{{code}}}} {{{{ link }}}} {LinkBase}login/reset-password?token={Uri.EscapeDataString(Token)}",
            Assert.Single(sender.Sends).Message.Body);
    }

    [Fact]
    public async Task Tenant_name_cannot_add_a_header_to_the_subject()
    {
        var (database, custody) = await SetupAsync();
        await database.SuperuserAsync(
            $"SET session_replication_role = replica; UPDATE tenant SET name = E'Evil\\r\\nBcc: victim@example.test' WHERE id = '{TenantA}'; SET session_replication_role = DEFAULT");
        var user = await UserAsync(database, Address);
        await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        var subject = Assert.Single(sender.Sends).Message.Subject;
        Assert.Equal("Security notice for your EvilBcc: victim@example.test account", subject);
        Assert.DoesNotContain('\r', subject);
        Assert.DoesNotContain('\n', subject);
    }

    [Theory]
    [InlineData("no_provider")]
    [InlineData("no_email")]
    [InlineData("no_user")]
    public async Task Nothing_is_sent_without_a_provider_an_email_or_a_User(string missing)
    {
        var (database, custody) = await SetupAsync(provider: missing != "no_provider");
        var user = missing == "no_user" ? Guid.CreateVersion7() : await UserAsync(database, missing == "no_email" ? null : Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.VerificationTemplate, Token);

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
        Assert.Equal(1L, await EventsAsync(database, null, null));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job_payload WHERE job_id = '{job}'"));
    }

    [Fact]
    public async Task Sixth_email_to_one_User_in_the_window_is_held_back_and_never_sent()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var other = await UserAsync(database, "other@example.test");
        var jobs = new List<Guid>();
        for (var i = 0; i < SecurityLimits.EmailPerRecipientLimit + 1; i++)
        {
            jobs.Add(await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null));
        }

        await EnqueueAsync(database, custody, other, NotificationsContract.SecurityNotificationTemplate, credential: null);

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender, runs: jobs.Count + 1);

        Assert.Equal(SecurityLimits.EmailPerRecipientLimit, sender.Sends.Count(s => s.Message.To == Address));
        Assert.Single(sender.Sends, s => s.Message.To == "other@example.test");
        Assert.Equal(5L, await EventsAsync(database, Sent, user));
        Assert.Equal(1L, await EventsAsync(database, HeldBack, user));
        Assert.Equal(1L, await EventsAsync(database, Sent, other));
        foreach (var job in jobs)
        {
            Assert.Equal("done", await database.StatusAsync(job));
        }

        // Counted per User in this Tenant's own counters, never by address.
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt r WHERE strpos(to_jsonb(r)::text, '{Address}') > 0"));
        Assert.Equal(2L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{TenantA}' AND policy = '{NotificationsContract.EmailRecipientPolicy.Code}'"));
    }

    /// <summary>
    /// Each transient attempt rolls back, count and all, and is retried; after the last one the job goes dead, as any
    /// other, with no event written, and the credential goes with the payload.
    /// </summary>
    [Fact]
    public async Task Transient_failure_retries_with_its_count_rolled_back_then_goes_dead_after_the_last_attempt()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.VerificationTemplate, Token);
        var sender = new RecordingEmailSender { Result = EmailSendResult.Transient("http_503") };
        var logger = new RecordingLogger();

        await using (var runner = Runner(database, custody, sender, logger))
        {
            for (var attempt = 1; attempt <= 5; attempt++)
            {
                await database.MakeDueAsync(job);
                Assert.True(await runner.RunOnceAsync(Cancellation));
                Assert.Equal(attempt < 5 ? "pending" : "dead", await database.StatusAsync(job));
                Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{TenantA}'"));
                Assert.Equal(0L, await EventsAsync(database, null, null));
            }
        }

        Assert.Equal(5, sender.Sends.Count);
        Assert.Equal(5, await database.AttemptsAsync(job));
        Assert.Equal("handler_failed", await database.ScalarAsync<string>($"SELECT failure_code FROM job WHERE id = '{job}'"));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM job_payload WHERE job_id = '{job}' AND ciphertext IS NOT NULL"));
        Assert.Equal(0L, await EventsAsync(database, Undeliverable, user));
        Assert.Contains(logger.Lines, l => l.Contains("http_503", StringComparison.Ordinal));
        AssertNoValueLogged(logger, Token);
    }

    [Fact]
    public async Task Missing_sender_fails_fast_reading_and_counting_nothing()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);

        await using (var runner = OperationsContract.CreateRunner(OperationsContract.ProductionRegistry, database.Databases, FastOptions, custody, null))
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }

        Assert.Equal("pending", await database.StatusAsync(job));
        Assert.Equal("handler_failed", await database.ScalarAsync<string>($"SELECT failure_code FROM job WHERE id = '{job}'"));
        Assert.Equal(0L, await EventsAsync(database, null, null));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{TenantA}'"));
    }

    /// <summary>A Tenant no longer active is its deletion's: nothing is sent or written, and the job is done.</summary>
    [Fact]
    public async Task Deleting_Tenant_gets_no_send_and_no_event()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        await database.SuperuserAsync(
            $"SET session_replication_role = replica; UPDATE tenant SET status = 'deleting' WHERE id = '{TenantA}'; SET session_replication_role = DEFAULT");

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(0L, await EventsAsync(database, null, null));
    }

    [Theory]
    [InlineData("a@example.test,b@example.test")]
    [InlineData("a@example.test;b@example.test")]
    [InlineData("Someone <a@example.test>")]
    [InlineData("undisclosed:a@example.test;")]
    [InlineData("a@example.test\r\nBcc: b@example.test")]
    [InlineData("not-an-address")]
    public async Task Stored_address_that_isnt_exactly_one_mailbox_is_undeliverable(string stored)
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, "placeholder@example.test");
        await using (var connection = new Npgsql.NpgsqlConnection(database.SuperuserConnectionString))
        {
            await connection.OpenAsync(Cancellation);
            await using var command = new Npgsql.NpgsqlCommand("UPDATE \"user\" SET email = @email WHERE id = @id", connection);
            command.Parameters.AddWithValue("email", stored);
            command.Parameters.AddWithValue("id", user);
            await command.ExecuteNonQueryAsync(Cancellation);
        }

        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        var sender = new RecordingEmailSender();
        var logger = new RecordingLogger();
        await RunAsync(database, custody, sender, logger);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
        Assert.Contains(logger.Lines, l => l.Contains("invalid_recipient", StringComparison.Ordinal));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{TenantA}'"));
    }

    [Fact]
    public async Task Override_dropping_the_link_is_refused_rather_than_sent_without_it()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        await OverrideAsync(database, NotificationsContract.VerificationTemplate, "Verify {{tenant_name}}", "Just click nothing.");
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.VerificationTemplate, Token);
        var sender = new RecordingEmailSender();
        var logger = new RecordingLogger();

        await RunAsync(database, custody, sender, logger);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
        Assert.Contains(logger.Lines, l => l.Contains("template_invalid", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Credential_that_isnt_UTF8_is_undeliverable_not_retried()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await database.InScopeAsync(TableRegistry.Hosted, TenantA, c => OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody).EnqueueAsync(
            c,
            OperationsContract.SendEmail,
            NotificationsContract.EmailPayload(user, NotificationsContract.OneTimeCodeTemplate, new Secret<byte[]>([0xff, 0xfe, 0x41])),
            null,
            Cancellation));
        var sender = new RecordingEmailSender();
        var logger = new RecordingLogger();

        await RunAsync(database, custody, sender, logger);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
        Assert.Contains(logger.Lines, l => l.Contains("credential_invalid", StringComparison.Ordinal));
    }

    /// <summary>A provider secret bound to another Tenant is rejected by custody: undeliverable, never retried.</summary>
    [Fact]
    public async Task Rejected_provider_secret_is_undeliverable_not_retried()
    {
        var (database, custody) = await SetupAsync(provider: false);
        var foreign = await custody.EncryptAsync(KeyName.ForTenant(TenantKeyClass.Email, TenantB), TenantB, Credential(ProviderSecret), Cancellation);
        await database.SuperuserAsync(
            "INSERT INTO email_provider (tenant_id, kind, settings, from_address, secret_ciphertext) "
            + $"VALUES ('{TenantA}', 'sendgrid', '{{\"region\":\"global\"}}', '{FromAddress}', '{foreign.Value}')");
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        var sender = new RecordingEmailSender();
        var logger = new RecordingLogger();

        await RunAsync(database, custody, sender, logger);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1, await database.AttemptsAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
        Assert.Contains(logger.Lines, l => l.Contains("secret_rejected", StringComparison.Ordinal));
    }

    /// <summary>Custody down while the provider's secret is decrypted: the run rolls back, count and all, and is retried.</summary>
    [Fact]
    public async Task Provider_secret_with_custody_unavailable_is_retried_with_nothing_sent_or_counted()
    {
        var (database, setup) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, setup, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        var custody = new FakeKeyCustody { UnavailableKeyPrefix = "email-" };
        var sender = new RecordingEmailSender();

        await RunAsync(database, custody, sender);

        Assert.Contains($"email-{TenantA}", custody.KeysUsed);
        Assert.Empty(sender.Sends);
        Assert.Equal("pending", await database.StatusAsync(job));

        // The runner gives a custody exception its own fixed code.
        Assert.Equal("custody_failed",await database.ScalarAsync<string>($"SELECT failure_code FROM job WHERE id = '{job}'"));
        Assert.Equal(0L, await EventsAsync(database, null, null));
        Assert.Equal(0L, await database.ScalarAsync<long>($"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{TenantA}'"));
    }

    /// <summary>An HTTP provider that can't be reached is transient: the job is retried.</summary>
    [Fact]
    public async Task HTTP_connect_failure_is_transient_and_the_job_retries()
    {
        var egress = new LoopbackEgress { HttpsPort = 1 };
        using (var direct = egress.Sender())
        {
            Assert.Equal(
                EmailSendResult.Transient("connect_failed"),
                await direct.SendAsync(new EmailTransport { Kind = "custom_http", Endpoint = "https://hooks.mail.test/send", Secret = new(ProviderSecret) }, Message(), Cancellation));
        }

        var (database, custody) = await SetupAsync(kind: "custom_http", settings: """{"endpoint":"https://hooks.mail.test/send","authHeaderName":"X-Api-Key"}""");
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        using var sender = egress.Sender();

        await RunAsync(database, custody, sender);

        Assert.Equal("pending", await database.StatusAsync(job));
        Assert.Equal("handler_failed", await database.ScalarAsync<string>($"SELECT failure_code FROM job WHERE id = '{job}'"));
        Assert.Equal(0L, await EventsAsync(database, null, null));
    }

    [Fact]
    public async Task Migration_template_ID_check_is_exactly_the_five_contract_IDs()
    {
        var database = await CreateAsync(postgres, registry: null);

        var definition = await database.ScalarAsync<string>(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'email_template_id' AND conrelid = 'email_template'::regclass");
        var ids = System.Text.RegularExpressions.Regex.Matches(definition, "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .Select(m => Guid.Parse(m.Value))
            .ToHashSet();

        Assert.True(ids.SetEquals(NotificationsContract.EmailTemplateIds), definition);
        Assert.Equal(5, ids.Count);
    }

    [Fact]
    public async Task Permanent_failure_is_undeliverable_and_not_retried()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        var sender = new RecordingEmailSender { Result = EmailSendResult.Permanent("http_401") };

        await RunAsync(database, custody, sender);

        Assert.Single(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1, await database.AttemptsAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
    }

    [Theory]
    [InlineData("account_locked_with_credential")]
    [InlineData("verification_without_credential")]
    [InlineData("code_without_credential")]
    [InlineData("unknown_template")]
    public async Task Credential_misuse_or_an_unknown_template_is_refused(string scenario)
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        var (template, credential) = scenario switch
        {
            "account_locked_with_credential" => (NotificationsContract.AccountLockedTemplate, Token),
            "verification_without_credential" => (NotificationsContract.VerificationTemplate, (string?)null),
            "code_without_credential" => (NotificationsContract.OneTimeCodeTemplate, null),
            _ => (Guid.CreateVersion7(), null),
        };
        var job = await EnqueueAsync(database, custody, user, template, credential);

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        Assert.Empty(sender.Sends);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));

        // The limit is applied before the template is read or rendered, so a refused message still counts once.
        Assert.Equal(1L, await database.ScalarAsync<long>(
            $"SELECT count(*) FROM tenant_attempt WHERE tenant_id = '{TenantA}' AND policy = '{NotificationsContract.EmailRecipientPolicy.Code}'"));
    }

    [Fact]
    public async Task One_time_code_is_sent_as_written()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);
        await EnqueueAsync(database, custody, user, NotificationsContract.OneTimeCodeTemplate, "493027");

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        var message = Assert.Single(sender.Sends).Message;
        Assert.Equal(("Your Test Tenant code", "Your code is 493027. It expires soon. Don't share it."), (message.Subject, message.Body));
    }

    [Fact]
    public async Task Worker_enqueues_a_notice_but_never_a_credential_without_custody()
    {
        var (database, custody) = await SetupAsync();
        var user = await UserAsync(database, Address);

        var job = await database.InScopeAsync(TableRegistry.Worker, TenantA, c => OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null)
            .EnqueueAsync(c, OperationsContract.SendEmail, NotificationsContract.EmailPayload(user, NotificationsContract.AccountLockedTemplate), null, Cancellation));
        await Assert.ThrowsAsync<InvalidOperationException>(() => database.InScopeAsync(TableRegistry.Worker, TenantA, c =>
            OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody: null).EnqueueAsync(
                c,
                OperationsContract.SendEmail,
                NotificationsContract.EmailPayload(user, NotificationsContract.VerificationTemplate, Credential(Token)),
                null,
                Cancellation)));

        var sender = new RecordingEmailSender();
        await RunAsync(database, custody, sender);

        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal("Your Test Tenant account is locked", Assert.Single(sender.Sends).Message.Subject);
    }

    [Fact]
    public async Task Custom_HTTP_endpoint_resolving_to_a_private_address_is_refused_by_egress_and_undeliverable()
    {
        var (database, custody) = await SetupAsync(kind: "custom_http", settings: """{"endpoint":"https://hooks.mail.test/send","authHeaderName":"X-Api-Key"}""");
        var user = await UserAsync(database, Address);
        var job = await EnqueueAsync(database, custody, user, NotificationsContract.SecurityNotificationTemplate, credential: null);
        await using var sink = await ProviderSink.StartAsync();
        var egress = new LoopbackEgress { HttpsPort = sink.Port, Resolve = [IPAddress.Parse("10.0.0.1")] };
        using var sender = egress.Sender();

        await RunAsync(database, custody, sender);

        Assert.Empty(egress.Dialled);
        Assert.Empty(sink.Requests);
        Assert.Equal("done", await database.StatusAsync(job));
        Assert.Equal(1L, await EventsAsync(database, Undeliverable, user));
    }

    [Fact]
    public async Task SMTP_through_the_runner_sends_one_message_to_the_resolved_address()
    {
        var (database, custody) = await SetupAsync(kind: "smtp", settings: $$"""{"host":"{{TestCertificates.SmtpHost}}","port":587,"tls":"starttls","username":"mailer"}""");
        var user = await UserAsync(database, Address);
        await EnqueueAsync(database, custody, user, NotificationsContract.VerificationTemplate, Token);
        await using var smtp = new FakeSmtpServer().Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        await RunAsync(database, custody, sender);

        var session = Assert.Single(smtp.Sessions);
        Assert.True(session.Tls);
        Assert.Equal(("mailer", ProviderSecret), (session.AuthUser, session.AuthPassword));
        Assert.Equal(new[] { Address }, session.Recipients);
        Assert.Equal(new[] { new IPEndPoint(LoopbackEgress.ResolvedAddress, 587) }, egress.Dialled);
        Assert.Equal(1L, await EventsAsync(database, Sent, user));
    }

    [Fact]
    public async Task SMTP_STARTTLS_authenticates_over_TLS_and_sends_one_plain_text_message()
    {
        await using var smtp = new FakeSmtpServer().Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("starttls", username: "mailer"), Message(), Cancellation);

        Assert.Equal(EmailSendResult.Sent, result);
        var session = Assert.Single(smtp.Sessions);
        Assert.StartsWith("EHLO ", session.Commands[0], StringComparison.Ordinal);
        Assert.Equal("STARTTLS", session.Commands[1]);
        Assert.True(session.Tls);

        // AUTH only after STARTTLS: the credential never crosses a plain connection.
        Assert.True(session.Commands.ToList().IndexOf("AUTH") > session.Commands.ToList().IndexOf("STARTTLS"));
        Assert.Equal(("mailer", ProviderSecret), (session.AuthUser, session.AuthPassword));
        Assert.Equal(FromAddress, session.MailFrom);
        Assert.Equal(new[] { Address }, session.Recipients);
        Assert.Contains("Subject: Hello there", session.Data, StringComparison.Ordinal);
        Assert.Contains("Content-Type: text/plain", session.Data, StringComparison.Ordinal);
        Assert.DoesNotContain("text/html", session.Data, StringComparison.Ordinal);
        Assert.Equal(new[] { new IPEndPoint(LoopbackEgress.ResolvedAddress, 587) }, egress.Dialled);
    }

    [Fact]
    public async Task SMTP_implicit_TLS_without_a_username_sends_without_AUTH()
    {
        await using var smtp = new FakeSmtpServer { Implicit = true }.Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("implicit", username: null), Message(), Cancellation);

        Assert.Equal(EmailSendResult.Sent, result);
        var session = Assert.Single(smtp.Sessions);
        Assert.True(session.Tls);
        Assert.DoesNotContain("STARTTLS", session.Commands);
        Assert.DoesNotContain("AUTH", session.Commands);
        Assert.Equal(new[] { Address }, session.Recipients);
    }

    [Fact]
    public async Task SMTP_refused_credentials_are_permanent_and_no_mail_follows()
    {
        await using var smtp = new FakeSmtpServer { RejectAuth = true }.Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("starttls", username: "mailer"), Message(), Cancellation);

        Assert.Equal(EmailSendResult.Permanent("smtp_auth"), result);
        await WaitForSessionAsync(smtp);
        var commands = smtp.Sessions.Single().Commands;
        Assert.Contains("AUTH", commands);
        Assert.DoesNotContain(commands, c => c.StartsWith("MAIL", StringComparison.Ordinal));
    }

    /// <summary>The server queued the message: a connection dropped on QUIT doesn't make it a failure, or a resend.</summary>
    [Fact]
    public async Task SMTP_connection_dropped_on_QUIT_after_the_message_is_accepted_is_still_sent()
    {
        await using var smtp = new FakeSmtpServer { DropOnQuit = true }.Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("starttls", username: "mailer"), Message(), Cancellation);

        Assert.Equal(EmailSendResult.Sent, result);
        await WaitForSessionAsync(smtp);
        var session = smtp.Sessions.Single();
        Assert.Single(session.Commands, c => c == "DATA");
        Assert.Contains("QUIT", session.Commands);
        Assert.NotNull(session.Data);
    }

    [Fact]
    public async Task SMTP_server_offering_no_STARTTLS_is_refused_rather_than_sent_in_plaintext()
    {
        await using var smtp = new FakeSmtpServer { OfferStartTls = false }.Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("starttls", username: "mailer"), Message(), Cancellation);

        Assert.Equal(EmailSendResult.Permanent("smtp_unsupported"), result);
        await WaitForSessionAsync(smtp);
        Assert.DoesNotContain(smtp.Sessions.Single().Commands, c => c.StartsWith("MAIL", StringComparison.Ordinal) || c == "AUTH");
    }

    [Theory]
    [InlineData("550 5.1.1 No such user", EmailSendOutcome.Permanent, "smtp_550")]
    [InlineData("451 4.3.0 Try again later", EmailSendOutcome.Transient, "smtp_451")]
    public async Task SMTP_refused_recipient_is_permanent_and_a_4xx_is_transient(string reply, EmailSendOutcome outcome, string reason)
    {
        await using var smtp = new FakeSmtpServer { RecipientReply = reply }.Start();
        var egress = new LoopbackEgress { SmtpPort = smtp.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("starttls", username: null), Message(), Cancellation);

        Assert.Equal(new EmailSendResult(outcome, reason), result);
    }

    [Fact]
    public async Task SMTP_connect_failure_is_transient_and_a_private_host_is_refused()
    {
        var closed = new LoopbackEgress { SmtpPort = 1 };
        using (var sender = closed.Sender())
        {
            Assert.Equal(EmailSendOutcome.Transient, (await sender.SendAsync(Smtp("starttls", null), Message(), Cancellation)).Outcome);
        }

        var refused = new LoopbackEgress { Resolve = [IPAddress.Parse("192.168.1.20")] };
        using (var sender = refused.Sender())
        {
            Assert.Equal(EmailSendResult.Permanent("egress_refused"), await sender.SendAsync(Smtp("starttls", null), Message(), Cancellation));
        }

        Assert.Empty(refused.Dialled);
    }

    [Fact]
    public async Task SendGrid_posts_its_mail_send_shape_with_a_bearer_key()
    {
        await using var sink = await ProviderSink.StartAsync();
        var (request, result) = await PostAsync(sink, new EmailTransport { Kind = "sendgrid", Region = "global", Secret = new(ProviderSecret) });

        Assert.Equal(EmailSendResult.Sent, result);
        Assert.Equal(("POST", "api.sendgrid.com", "/v3/mail/send"), (request.Method, request.Host, request.PathAndQuery));
        Assert.Equal($"Bearer {ProviderSecret}", request.Headers["Authorization"]);
        var body = JsonNode.Parse(request.Text)!;
        Assert.Equal(Address, (string?)body["personalizations"]![0]!["to"]![0]!["email"]);
        Assert.Equal((FromAddress, FromName), ((string?)body["from"]!["email"], (string?)body["from"]!["name"]));
        Assert.Equal("Hello there", (string?)body["subject"]);
        Assert.Equal(("text/plain", "Plain body"), ((string?)body["content"]![0]!["type"], (string?)body["content"]![0]!["value"]));
        Assert.Single(body["content"]!.AsArray());

        var (eu, _) = await PostAsync(sink, new EmailTransport { Kind = "sendgrid", Region = "eu", Secret = new(ProviderSecret) });
        Assert.Equal("api.eu.sendgrid.com", eu.Host);
    }

    [Fact]
    public async Task Postmark_posts_with_its_server_token_and_message_stream()
    {
        await using var sink = await ProviderSink.StartAsync();
        sink.Status = 200;
        var (request, result) = await PostAsync(sink, new EmailTransport { Kind = "postmark", Secret = new(ProviderSecret) });

        Assert.Equal(EmailSendResult.Sent, result);
        Assert.Equal(("POST", "api.postmarkapp.com", "/email"), (request.Method, request.Host, request.PathAndQuery));
        Assert.Equal(ProviderSecret, request.Headers["X-Postmark-Server-Token"]);
        Assert.False(request.Headers.ContainsKey("Authorization"));
        var body = JsonNode.Parse(request.Text)!;
        Assert.Equal($"{FromName} <{FromAddress}>", (string?)body["From"]);
        Assert.Equal((Address, "Hello there", "Plain body", "outbound"), ((string?)body["To"], (string?)body["Subject"], (string?)body["TextBody"], (string?)body["MessageStream"]));
        Assert.Null(body["HtmlBody"]);

        var (stream, _) = await PostAsync(sink, new EmailTransport { Kind = "postmark", MessageStream = "notices", Secret = new(ProviderSecret) });
        Assert.Equal("notices", (string?)JsonNode.Parse(stream.Text)!["MessageStream"]);
    }

    [Fact]
    public async Task Mailgun_posts_a_form_with_basic_auth_to_its_domain()
    {
        await using var sink = await ProviderSink.StartAsync();
        sink.Status = 200;
        var (request, result) = await PostAsync(sink, new EmailTransport { Kind = "mailgun", Domain = "mg.tenant.example", Region = "us", Secret = new(ProviderSecret) });

        Assert.Equal(EmailSendResult.Sent, result);
        Assert.Equal(("POST", "api.mailgun.net", "/v3/mg.tenant.example/messages"), (request.Method, request.Host, request.PathAndQuery));
        Assert.Equal($"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"api:{ProviderSecret}"))}", request.Headers["Authorization"]);
        Assert.StartsWith("application/x-www-form-urlencoded", request.Headers["Content-Type"], StringComparison.Ordinal);
        var form = request.Text.Split('&').Select(p => p.Split('=')).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
        Assert.Equal(Address, form["to"]);
        Assert.Equal("Hello there", form["subject"]);
        Assert.Equal("Plain body", form["text"]);
        Assert.Equal($"{FromName} <{FromAddress}>", form["from"]);
        Assert.False(form.ContainsKey("html"));

        var (eu, _) = await PostAsync(sink, new EmailTransport { Kind = "mailgun", Domain = "mg.tenant.example", Region = "eu", Secret = new(ProviderSecret) });
        Assert.Equal("api.eu.mailgun.net", eu.Host);
    }

    [Fact]
    public async Task SES_posts_its_v2_shape_signed_with_SigV4_for_ses()
    {
        await using var sink = await ProviderSink.StartAsync();
        sink.Status = 200;
        var now = new DateTimeOffset(2026, 11, 16, 9, 30, 0, TimeSpan.Zero);
        var (request, result) = await PostAsync(
            sink,
            new EmailTransport { Kind = "ses", Region = "eu-west-1", AccessKeyId = "AKIDEXAMPLE00000", Secret = new(ProviderSecret) },
            new FixedTime(now));

        Assert.Equal(EmailSendResult.Sent, result);
        Assert.Equal(("POST", "email.eu-west-1.amazonaws.com", "/v2/email/outbound-emails"), (request.Method, request.Host, request.PathAndQuery));
        Assert.StartsWith(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE00000/20261116/eu-west-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=",
            request.Headers["Authorization"],
            StringComparison.Ordinal);
        Assert.Equal("20261116T093000Z", request.Headers["x-amz-date"]);
        Assert.DoesNotContain(ProviderSecret, string.Join('\n', request.Headers.Values), StringComparison.Ordinal);
        var body = JsonNode.Parse(request.Text)!;
        Assert.Equal(Address, (string?)body["Destination"]!["ToAddresses"]![0]);
        Assert.Equal("Hello there", (string?)body["Content"]!["Simple"]!["Subject"]!["Data"]);
        Assert.Equal("Plain body", (string?)body["Content"]!["Simple"]!["Body"]!["Text"]!["Data"]);
        Assert.Null(body["Content"]!["Simple"]!["Body"]!["Html"]);

        // A known answer, computed here from AWS's documented steps rather than by SigV4: the service scope is ses.
        Assert.Equal(
            ExpectedSesSignature(request, "eu-west-1", "20261116", "20261116T093000Z"),
            request.Headers["Authorization"][(request.Headers["Authorization"].LastIndexOf('=') + 1)..]);
    }

    [Fact]
    public async Task SES_region_is_checked_again_at_send()
    {
        await using var sink = await ProviderSink.StartAsync();

        var egress = new LoopbackEgress { HttpsPort = sink.Port };
        using var sender = egress.Sender();
        var result = await sender.SendAsync(
            new EmailTransport { Kind = "ses", Region = "evil.example/x#", AccessKeyId = "AKIDEXAMPLE00000", Secret = new(ProviderSecret) },
            Message(),
            Cancellation);

        Assert.Equal(EmailSendResult.Permanent("invalid_settings"), result);
        Assert.Empty(egress.Dialled);
    }

    [Theory]
    [InlineData("Host")]
    [InlineData("content-length")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Cookie")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Connection")]
    [InlineData("TE")]
    [InlineData("Expect")]
    [InlineData("Keep-Alive")]
    [InlineData("Bad Header")]
    public async Task Custom_HTTP_header_that_frames_or_routes_the_request_is_refused_at_send(string header)
    {
        await using var sink = await ProviderSink.StartAsync();
        var egress = new LoopbackEgress { HttpsPort = sink.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(
            new EmailTransport { Kind = "custom_http", Endpoint = "https://hooks.mail.test/send", AuthHeaderName = header, Secret = new(ProviderSecret) },
            Message(),
            Cancellation);

        Assert.Equal(EmailSendResult.Permanent("invalid_settings"), result);
        Assert.Empty(sink.Requests);
    }

    [Fact]
    public async Task Non_ASCII_From_name_is_RFC_2047_encoded_in_header_style_fields()
    {
        await using var sink = await ProviderSink.StartAsync();
        sink.Status = 200;
        var egress = new LoopbackEgress { HttpsPort = sink.Port };
        using var sender = egress.Sender();
        var message = Message() with { FromName = "Zoë Ångström" };

        await sender.SendAsync(new EmailTransport { Kind = "postmark", Secret = new(ProviderSecret) }, message, Cancellation);

        var from = (string?)JsonNode.Parse(Assert.Single(sink.Requests).Text)!["From"];
        Assert.StartsWith("=?utf-8?", from, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith($"<{FromAddress}>", from, StringComparison.Ordinal);
        Assert.True(from!.All(char.IsAscii), from);
        Assert.Equal("Zoë Ångström", MimeKit.MailboxAddress.Parse(from!).Name);
    }

    [Fact]
    public async Task SMTP_port_out_of_range_is_permanent()
    {
        var egress = new LoopbackEgress();
        using var sender = egress.Sender();

        var result = await sender.SendAsync(Smtp("starttls", null) with { Port = 70000 }, Message(), Cancellation);

        Assert.Equal(EmailSendResult.Permanent("invalid_settings"), result);
        Assert.Empty(egress.Dialled);
    }

    /// <summary>A certificate no trusted root issued is refused before AUTH or MAIL, over SMTP and HTTP alike.</summary>
    [Fact]
    public async Task Untrusted_certificate_is_refused_before_anything_is_sent()
    {
        await using var smtp = new FakeSmtpServer { Certificate = TestCertificates.Untrusted }.Start();
        await using var sink = await ProviderSink.StartAsync(TestCertificates.Untrusted);
        var egress = new LoopbackEgress { SmtpPort = smtp.Port, HttpsPort = sink.Port };
        using var sender = egress.Sender();

        var viaSmtp = await sender.SendAsync(Smtp("starttls", username: "mailer"), Message(), Cancellation);
        var viaHttp = await sender.SendAsync(
            new EmailTransport { Kind = "custom_http", Endpoint = "https://hooks.mail.test/send", Secret = new(ProviderSecret) },
            Message(),
            Cancellation);

        Assert.Equal(EmailSendResult.Transient("tls_failed"), viaSmtp);
        Assert.Equal(EmailSendResult.Transient("connect_failed"), viaHttp);
        await WaitForSessionAsync(smtp);
        Assert.DoesNotContain(smtp.Sessions.Single().Commands, c => c == "AUTH" || c.StartsWith("MAIL", StringComparison.Ordinal));
        Assert.Empty(sink.Requests);
    }

    [Fact]
    public async Task Custom_HTTP_posts_its_JSON_with_the_secret_in_the_named_header()
    {
        await using var sink = await ProviderSink.StartAsync();
        var (request, result) = await PostAsync(
            sink,
            new EmailTransport { Kind = "custom_http", Endpoint = "https://hooks.mail.test/v1/send?x=1", AuthHeaderName = "X-Api-Key", Secret = new(ProviderSecret) });

        Assert.Equal(EmailSendResult.Sent, result);
        Assert.Equal(("POST", "hooks.mail.test", "/v1/send?x=1"), (request.Method, request.Host, request.PathAndQuery));
        Assert.Equal(ProviderSecret, request.Headers["X-Api-Key"]);
        var body = JsonNode.Parse(request.Text)!;
        Assert.Equal((FromAddress, FromName), ((string?)body["from"]!["address"], (string?)body["from"]!["name"]));
        Assert.Equal((Address, "Hello there", "Plain body"), ((string?)body["to"], (string?)body["subject"], (string?)body["text"]));
        Assert.Equal(new[] { "from", "to", "subject", "text" }, body.AsObject().Select(p => p.Key));
    }

    [Theory]
    [InlineData(202, EmailSendOutcome.Sent)]
    [InlineData(302, EmailSendOutcome.Permanent)]
    [InlineData(400, EmailSendOutcome.Permanent)]
    [InlineData(401, EmailSendOutcome.Permanent)]
    [InlineData(429, EmailSendOutcome.Transient)]
    [InlineData(503, EmailSendOutcome.Transient)]
    public async Task Provider_answer_decides_sent_permanent_or_transient(int status, EmailSendOutcome outcome)
    {
        await using var sink = await ProviderSink.StartAsync();
        sink.Status = status;

        var (_, result) = await PostAsync(sink, new EmailTransport { Kind = "custom_http", Endpoint = "https://hooks.mail.test/send", Secret = new(ProviderSecret) });

        Assert.Equal(outcome, result.Outcome);
        Assert.Equal(outcome == EmailSendOutcome.Sent ? "sent" : string.Create(CultureInfo.InvariantCulture, $"http_{status}"), result.Reason);
    }

    [Fact]
    public async Task Plain_HTTP_endpoint_is_refused_by_egress()
    {
        await using var sink = await ProviderSink.StartAsync();
        var egress = new LoopbackEgress { HttpsPort = sink.Port };
        using var sender = egress.Sender();

        var result = await sender.SendAsync(
            new EmailTransport { Kind = "custom_http", Endpoint = "http://hooks.mail.test/send", Secret = new(ProviderSecret) },
            Message(),
            Cancellation);

        Assert.Equal(EmailSendResult.Permanent("egress_refused"), result);
        Assert.Empty(egress.Dialled);
    }

    private static EmailMessage Message() => new(FromAddress, FromName, Address, "Hello there", "Plain body");

    private static EmailTransport Smtp(string tls, string? username) => new()
    {
        Kind = "smtp",
        Host = TestCertificates.SmtpHost,
        Port = tls == "implicit" ? 465 : 587,
        Tls = tls,
        Username = username,
        Secret = username is null ? null : new(ProviderSecret),
    };

    private static async Task<(ProviderRequest Request, EmailSendResult Result)> PostAsync(ProviderSink sink, EmailTransport transport, TimeProvider? time = null)
    {
        var egress = new LoopbackEgress { HttpsPort = sink.Port };
        using var sender = egress.Sender(time);
        var before = sink.Requests.Count;

        var result = await sender.SendAsync(transport, Message(), Cancellation);

        Assert.All(egress.Dialled, d => Assert.Equal(new IPEndPoint(LoopbackEgress.ResolvedAddress, 443), d));
        return (sink.Requests.Skip(before).Single(), result);
    }

    private static async Task WaitForSessionAsync(FakeSmtpServer smtp)
    {
        for (var i = 0; i < 100 && smtp.Sessions.Count == 0; i++)
        {
            await Task.Delay(50, Cancellation);
        }
    }

    private static Secret<byte[]> Credential(string value) => new(Encoding.UTF8.GetBytes(value));

    /// <summary>The SigV4 signature AWS documents for the request as received, scoped to service <c>ses</c>.</summary>
    private static string ExpectedSesSignature(ProviderRequest request, string region, string date, string amzDate)
    {
        static byte[] Hmac(byte[] key, string data) => System.Security.Cryptography.HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(data));
        static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

        var payloadHash = Hex(System.Security.Cryptography.SHA256.HashData(request.Body));
        Assert.Equal(payloadHash, request.Headers["x-amz-content-sha256"]);
        var canonical = string.Join(
            '\n',
            "POST",
            "/v2/email/outbound-emails",
            string.Empty,
            $"content-type:{request.Headers["Content-Type"]}\nhost:{request.Host}\nx-amz-content-sha256:{payloadHash}\nx-amz-date:{amzDate}\n",
            "content-type;host;x-amz-content-sha256;x-amz-date",
            payloadHash);
        var scope = $"{date}/{region}/ses/aws4_request";
        var toSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{scope}\n{Hex(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))}";
        var key = Hmac(Hmac(Hmac(Hmac(Encoding.UTF8.GetBytes("AWS4" + ProviderSecret), date), region), "ses"), "aws4_request");
        return Hex(Hmac(key, toSign));
    }

    private async Task<(JobDatabase Database, FakeKeyCustody Custody)> SetupAsync(
        bool provider = true,
        string kind = "sendgrid",
        string settings = """{"region":"global"}""")
    {
        var database = await CreateAsync(postgres, registry: null);
        var custody = new FakeKeyCustody();
        if (provider)
        {
            var ciphertext = await custody.EncryptAsync(
                KeyName.ForTenant(TenantKeyClass.Email, TenantA),
                TenantA,
                Credential(ProviderSecret),
                Cancellation);
            await database.SuperuserAsync(
                "INSERT INTO email_provider (tenant_id, kind, settings, from_address, from_name, secret_ciphertext) "
                + $"VALUES ('{TenantA}', '{kind}', '{settings}', '{FromAddress}', '{FromName}', '{ciphertext.Value}')");
        }

        return (database, custody);
    }

    private static async Task<Guid> UserAsync(JobDatabase database, string? email)
    {
        var id = Guid.CreateVersion7();
        await database.SuperuserAsync(
            $"INSERT INTO \"user\" (tenant_id, id, email) VALUES ('{TenantA}', '{id}', {(email is null ? "NULL" : $"'{email}'")})");
        return id;
    }

    private static Task OverrideAsync(JobDatabase database, Guid template, string subject, string body) =>
        database.SuperuserAsync(
            $"INSERT INTO email_template (tenant_id, template_id, subject, body) VALUES ('{TenantA}', '{template}', '{subject}', '{body}')");

    /// <summary>Enqueued as Host.Hosted will (Stories 4.7 and 4.11): the only role that can encrypt a credential.</summary>
    private static Task<Guid> EnqueueAsync(JobDatabase database, FakeKeyCustody custody, Guid user, Guid template, string? credential) =>
        database.InScopeAsync(TableRegistry.Hosted, TenantA, c => OperationsContract.CreateEnqueuer(OperationsContract.ProductionRegistry, custody).EnqueueAsync(
            c,
            OperationsContract.SendEmail,
            NotificationsContract.EmailPayload(user, template, credential is null ? null : Credential(credential)),
            null,
            Cancellation));

    private static IJobRunner Runner(JobDatabase database, FakeKeyCustody custody, IEmailSender sender, RecordingLogger? logger = null) =>
        OperationsContract.CreateRunner(OperationsContract.ProductionRegistry, database.Databases, FastOptions, custody, logger, email: sender);

    private static async Task RunAsync(JobDatabase database, FakeKeyCustody custody, IEmailSender sender, RecordingLogger? logger = null, int runs = 1)
    {
        await using var runner = Runner(database, custody, sender, logger);
        for (var i = 0; i < runs; i++)
        {
            Assert.True(await runner.RunOnceAsync(Cancellation));
        }
    }

    /// <summary>Events on Tenant A's chain of <paramref name="type"/> (any, when null) targeting <paramref name="user"/> (any, when null).</summary>
    private static Task<long> EventsAsync(JobDatabase database, string? type, Guid? user) =>
        database.ScalarAsync<long>(
            $"SELECT count(*) FROM audit_event WHERE tenant_id = '{TenantA}'"
            + (type is null ? string.Empty : $" AND type_code = '{type}'")
            + (user is null ? string.Empty : $" AND target_kind = 'user' AND target_id = '{user}'"));

    private static void AssertNoValueLogged(RecordingLogger logger, string link)
    {
        var text = string.Join('\n', logger.Lines);
        foreach (var value in new[] { Address, Token, Uri.EscapeDataString(Token), link, ProviderSecret })
        {
            Assert.DoesNotContain(value, text, StringComparison.Ordinal);
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
