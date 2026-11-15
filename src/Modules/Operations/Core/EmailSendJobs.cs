using System.Security.Cryptography;
using System.Text;
using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Email;
using Gatekeep.Kernel.Limits;
using Gatekeep.Kernel.RateLimiting;
using Gatekeep.Kernel.Secrets;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Authentication.Contracts;
using Gatekeep.Modules.Identity.Contracts;
using Gatekeep.Modules.Notifications.Contracts;
using Gatekeep.Modules.Operations.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Microsoft.Extensions.Logging;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// The Story 4.5 send job, <c>notifications.email.send</c> (FR-36, AR-18, AD-15), as <c>gk_worker</c> in its Tenant's
/// scope and one transaction. In order: it reads the Tenant's provider; resolves the recipient from the User's ID, now,
/// and requires exactly one mailbox; counts the send against the User's per-recipient limit; renders the Tenant's
/// template, decrypting the job's link token or code at the moment of use; then decrypts the provider's secret and sends
/// through <see cref="IEmailSender"/>. Each path that ends the job writes one Tenant event targeting the User, with no
/// address, link or code: sent, undeliverable, or held back. A transient failure throws, so the whole run rolls back,
/// its count with it, and the runner retries with backoff; an exhausted job goes dead, as any other.
/// </summary>
internal static class EmailSendJobs
{
    /// <summary>The job's attempts: after the last one fails transiently, the job goes dead.</summary>
    public const int MaxAttempts = 5;

    private static readonly IAuditAppender Appender = AuditContract.CreateAppender();

    private static readonly IRateLimiter Limiter = AuthenticationContract.CreateAttemptLimiter();

    private static readonly ITenants Tenants = TenancyContract.CreateTenants(Appender);

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static async Task SendAsync(JobRun run, CancellationToken cancellationToken)
    {
        // Misconfiguration fails fast, before anything is read or counted: the runner retries, then the job goes dead.
        var custody = run.Services.Custody
            ?? throw new InvalidOperationException("Host.Worker has no key custody to decrypt the email provider's secret.");
        var sender = run.Services.Email
            ?? throw new InvalidOperationException("Host.Worker has no email sender.");

        var context = run.Context;
        var tenantId = context.TenantId ?? throw new InvalidOperationException("An email is sent for one Tenant.");
        var userId = run.Ids.TryGetValue(NotificationsContract.EmailUserIdName, out var user) ? user : (Guid?)null;
        var templateId = run.Ids.TryGetValue(NotificationsContract.EmailTemplateIdName, out var template) ? template : (Guid?)null;

        // A Tenant no longer active is its deletion's to purge: nothing is sent or written for it.
        var tenant = await Tenants.GetEmailIdentityAsync(context, tenantId, cancellationToken);
        if (tenant is not { Status: TenantStatus.Active })
        {
            Log(run, "tenant_inactive");
            return;
        }

        // 1. The provider, as stored now.
        var delivery = await NotificationsContract.ReadEmailDeliveryAsync(context, cancellationToken);
        if (delivery is null)
        {
            await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, "no_provider", cancellationToken);
            return;
        }

        // 2. The recipient, resolved from the User now, so an address changed after the job was queued is the one used.
        var to = userId is { } id ? await IdentityContract.ReadEmailAsync(context, id, cancellationToken) : null;
        if (to is null)
        {
            await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, "no_recipient", cancellationToken);
            return;
        }

        // Exactly one mailbox: a stored list could otherwise fan out under one User's count.
        if (!NotificationsContract.IsSingleMailbox(to))
        {
            await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, "invalid_recipient", cancellationToken);
            return;
        }

        // 3. The per-recipient limit, in this run's transaction: a retried send rolls its count back.
        var decision = await Limiter.AttemptAsync(context, NotificationsContract.EmailRecipientPolicy, userId!.Value.ToString("D"), cancellationToken);
        if (!decision.Allowed)
        {
            await EndAsync(run, NotificationsEvents.EmailHeldBack, userId, "held_back", cancellationToken);
            return;
        }

        // 4. The template, with the credential decrypted only now.
        var text = templateId is { } templateValue
            ? await NotificationsContract.ReadEmailTemplateAsync(context, templateValue, cancellationToken)
            : null;
        if (text is null)
        {
            await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, "unknown_template", cancellationToken);
            return;
        }

        string? credential = null;
        if (run.HasCredential)
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(SecurityLimits.KeyCustodyCallTimeout);
            var secret = await run.DecryptCredentialAsync(limit.Token).WaitAsync(limit.Token);
            try
            {
                credential = secret.Use(bytes =>
                {
                    try
                    {
                        return StrictUtf8.GetString(bytes);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(bytes);
                    }
                });
            }
            catch (DecoderFallbackException)
            {
                await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, "credential_invalid", cancellationToken);
                return;
            }
        }

        var render = NotificationsContract.RenderEmail(templateId!.Value, text, tenant.Name, tenant.EmailLinkBase, credential);
        if (render.Status != EmailRenderStatus.Rendered)
        {
            await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, Code(render.Status), cancellationToken);
            return;
        }

        // 5. The provider's secret, decrypted at the moment of use, then the send. A rejected secret never decrypts.
        EmailTransport transport;
        try
        {
            transport = await NotificationsContract.CreateEmailTransportAsync(delivery, tenantId, custody, cancellationToken);
        }
        catch (KeyCustodyException e) when (e.Failure != KeyCustodyFailure.Unavailable)
        {
            await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, "secret_rejected", cancellationToken);
            return;
        }

        var message = new EmailMessage(delivery.Provider.FromAddress, delivery.Provider.FromName, to, render.Subject!, render.Body!);
        var result = await sender.SendAsync(transport, message, cancellationToken);

        switch (result.Outcome)
        {
            case EmailSendOutcome.Sent:
                await EndAsync(run, NotificationsEvents.EmailSent, userId, result.Reason, cancellationToken);
                return;
            case EmailSendOutcome.Permanent:
                await EndAsync(run, NotificationsEvents.EmailUndeliverable, userId, result.Reason, cancellationToken);
                return;
            default:
                // The reason is a fixed code. The runner keeps only its own fixed failure code and retries, then the job
                // goes dead once its attempts are spent.
                run.Services.Logger?.LogWarning(
                    "Email job {JobId} couldn't send on attempt {Attempt}: {Reason}. The runner retries it until its attempts run out.",
                    run.JobId,
                    run.Attempt,
                    result.Reason);
                throw new EmailDeferredException();
        }
    }

    private static string Code(EmailRenderStatus status) => status switch
    {
        EmailRenderStatus.UnknownTemplate => "unknown_template",
        EmailRenderStatus.CredentialMissing => "credential_missing",
        EmailRenderStatus.CredentialRefused => "credential_refused",
        EmailRenderStatus.TemplateInvalid => "template_invalid",
        _ => "not_rendered",
    };

    private static async Task EndAsync(
        JobRun run,
        AuditEventDefinition definition,
        Guid? userId,
        string reason,
        CancellationToken cancellationToken)
    {
        var target = userId is { } id && id != Guid.Empty ? AuditTargetKind.User : (AuditTargetKind?)null;
        await Appender.AppendAsync(
            run.Context,
            new AuditEvent(definition.Code, Actor.System, target, target is null ? null : userId),
            detail: null,
            cancellationToken);
        Log(run, reason);
    }

    /// <summary>The job and a fixed reason code only: never an address, link, code or provider setting.</summary>
    private static void Log(JobRun run, string reason) =>
        run.Services.Logger?.LogInformation("Email job {JobId} finished: {Reason}.", run.JobId, reason);

    /// <summary>The provider may accept the email later: the run rolls back and the runner retries it.</summary>
    private sealed class EmailDeferredException() : Exception("The email provider failed transiently; the send will be retried.");
}
