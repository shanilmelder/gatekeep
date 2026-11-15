using Gatekeep.Modules.Notifications.Contracts;
using Xunit;

namespace Gatekeep.Tests.Isolation.Notifications;

/// <summary>
/// Story 4.5: fixed substitution only. Each allowed <c>{{name}}</c> is replaced by literal text in one pass; anything else
/// stays as written; no substituted value is expanded again; the subject loses every CR and LF; the link is the stored
/// email link base, the template's path and the URL-encoded token; and each template takes a credential exactly when it
/// sends a link or a code. The five defaults name the Tenant, never Gatekeep.
/// </summary>
public sealed class EmailTemplateRendererTests
{
    private const string LinkBase = "https://acme.tenants.gatekeep.test/";

    [Fact]
    public void Five_templates_with_fixed_IDs_each_have_a_default_naming_the_Tenant_never_Gatekeep()
    {
        Assert.Equal(
            new[]
            {
                Guid.Parse("01930000-0000-7000-8000-0000000045e1"),
                Guid.Parse("01930000-0000-7000-8000-0000000045e2"),
                Guid.Parse("01930000-0000-7000-8000-0000000045e3"),
                Guid.Parse("01930000-0000-7000-8000-0000000045e4"),
                Guid.Parse("01930000-0000-7000-8000-0000000045e5"),
            },
            NotificationsContract.EmailTemplateIds);
        Assert.Equal(
            new[]
            {
                NotificationsContract.VerificationTemplate,
                NotificationsContract.PasswordResetTemplate,
                NotificationsContract.OneTimeCodeTemplate,
                NotificationsContract.AccountLockedTemplate,
                NotificationsContract.SecurityNotificationTemplate,
            },
            NotificationsContract.EmailTemplateIds);

        foreach (var id in NotificationsContract.EmailTemplateIds)
        {
            var text = NotificationsContract.DefaultEmailTemplate(id)!;
            Assert.Contains("{{tenant_name}}", text.Subject, StringComparison.Ordinal);
            Assert.DoesNotContain("Gatekeep", text.Subject + text.Body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain('<', text.Body);
        }

        Assert.Null(NotificationsContract.DefaultEmailTemplate(Guid.CreateVersion7()));
    }

    [Theory]
    [InlineData("verification", "login/verify-email")]
    [InlineData("password_reset", "login/reset-password")]
    public void Link_is_the_stored_base_the_templates_path_and_the_encoded_token(string template, string path)
    {
        var id = template == "verification" ? NotificationsContract.VerificationTemplate : NotificationsContract.PasswordResetTemplate;

        var render = NotificationsContract.RenderEmail(id, new("s", "{{link}}"), "Acme", LinkBase, "a+b/c=d&e f");

        Assert.Equal(EmailRenderStatus.Rendered, render.Status);
        Assert.Equal($"{LinkBase}{path}?token=a%2Bb%2Fc%3Dd%26e%20f", render.Body);
    }

    [Fact]
    public void A_base_without_its_slash_still_makes_one_path()
    {
        var render = NotificationsContract.RenderEmail(
            NotificationsContract.VerificationTemplate, new("s", "{{link}}"), "Acme", "https://acme.example:8443", "t");

        Assert.Equal("https://acme.example:8443/login/verify-email?token=t", render.Body);
    }

    [Fact]
    public void Substituted_values_are_never_expanded_again()
    {
        var render = NotificationsContract.RenderEmail(
            NotificationsContract.OneTimeCodeTemplate, new("{{tenant_name}}", "{{tenant_name}} {{code}}"), "{{code}}", LinkBase, "{{tenant_name}}");

        Assert.Equal(("{{code}}", "{{code}} {{tenant_name}}"), (render.Subject, render.Body));
    }

    [Fact]
    public void Unknown_and_not_allowed_variables_stay_as_written()
    {
        var render = NotificationsContract.RenderEmail(
            NotificationsContract.AccountLockedTemplate,
            new("Hi", "{{user.password}} {{link}} {{code}} {{TENANT_NAME}} {{ tenant_name }} {{tenant_name}} {{{tenant_name}}} {{"),
            "Acme",
            LinkBase,
            null);

        Assert.Equal("{{user.password}} {{link}} {{code}} {{TENANT_NAME}} {{ tenant_name }} Acme {Acme} {{", render.Body);
    }

    [Fact]
    public void Subject_loses_every_CR_and_LF_and_the_body_keeps_its_lines()
    {
        var render = NotificationsContract.RenderEmail(
            NotificationsContract.SecurityNotificationTemplate, new("A\r\n{{tenant_name}}\n", "a\r\nb"), "x\r\nBcc: y@example.test", LinkBase, null);

        Assert.Equal("AxBcc: y@example.test", render.Subject);
        Assert.Equal("a\r\nb", render.Body);
    }

    [Theory]
    [InlineData("verification", null, EmailRenderStatus.CredentialMissing)]
    [InlineData("password_reset", null, EmailRenderStatus.CredentialMissing)]
    [InlineData("one_time_code", null, EmailRenderStatus.CredentialMissing)]
    [InlineData("account_locked", "t", EmailRenderStatus.CredentialRefused)]
    [InlineData("security_notification", "t", EmailRenderStatus.CredentialRefused)]
    [InlineData("verification", "t", EmailRenderStatus.Rendered)]
    [InlineData("account_locked", null, EmailRenderStatus.Rendered)]
    [InlineData("unknown", null, EmailRenderStatus.UnknownTemplate)]
    public void A_template_takes_a_credential_exactly_when_it_sends_a_link_or_code(string template, string? credential, EmailRenderStatus status)
    {
        var id = template switch
        {
            "verification" => NotificationsContract.VerificationTemplate,
            "password_reset" => NotificationsContract.PasswordResetTemplate,
            "one_time_code" => NotificationsContract.OneTimeCodeTemplate,
            "account_locked" => NotificationsContract.AccountLockedTemplate,
            "security_notification" => NotificationsContract.SecurityNotificationTemplate,
            _ => Guid.CreateVersion7(),
        };

        var render = NotificationsContract.RenderEmail(id, new("s", "{{link}} {{code}}"), "Acme", LinkBase, credential);

        Assert.Equal(status, render.Status);
        if (status != EmailRenderStatus.Rendered)
        {
            Assert.Null(render.Subject);
            Assert.Null(render.Body);
        }
    }

    [Theory]
    [InlineData("verification", "Hi", "No link here", EmailRenderStatus.TemplateInvalid)]
    [InlineData("password_reset", "Hi", "{{code}}", EmailRenderStatus.TemplateInvalid)]
    [InlineData("one_time_code", "Hi", "{{link}}", EmailRenderStatus.TemplateInvalid)]
    [InlineData("verification", "{{link}}", "Body", EmailRenderStatus.Rendered)]
    [InlineData("one_time_code", "Code", "{{code}}", EmailRenderStatus.Rendered)]
    public void A_link_or_code_template_without_its_variable_is_refused(string template, string subject, string body, EmailRenderStatus status)
    {
        var id = template switch
        {
            "verification" => NotificationsContract.VerificationTemplate,
            "password_reset" => NotificationsContract.PasswordResetTemplate,
            _ => NotificationsContract.OneTimeCodeTemplate,
        };

        Assert.Equal(status, NotificationsContract.RenderEmail(id, new(subject, body), "Acme", LinkBase, "t").Status);
    }

    [Fact]
    public void A_render_prints_neither_subject_nor_body()
    {
        var render = NotificationsContract.RenderEmail(NotificationsContract.OneTimeCodeTemplate, new("s", "{{code}}"), "Acme", LinkBase, "493027");

        Assert.Equal("EmailRender Rendered", render.ToString());
    }
}
