using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Notifications.Contracts;

namespace Gatekeep.Modules.Notifications.Core;

/// <summary>
/// The SQL on <c>email_template</c> (Story 4.5): a Tenant's overrides of the five templates, one row each at most. Story
/// 15.4 writes them; Host.Worker reads them to send, and deletes them in a Tenant's purge.
/// </summary>
internal static class EmailTemplateStore
{
    private const string Select = "SELECT subject, body FROM email_template WHERE tenant_id = @tenant_id AND template_id = @template_id";

    internal const string Delete = "DELETE FROM email_template WHERE tenant_id = @tenant_id";

    /// <summary>The Tenant's override of the template, else its default; null when the ID is none of the five.</summary>
    public static async Task<EmailTemplateText?> ReadAsync(CommandContext context, Guid templateId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A Tenant's email templates are read in that Tenant's own scope.");

        if (EmailTemplateDefaults.Find(templateId) is not { } template)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = Select;
        EmailProviderStore.Add(command, "tenant_id", tenantId);
        EmailProviderStore.Add(command, "template_id", templateId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new EmailTemplateText(reader.GetString(0), reader.GetString(1))
            : template.Default;
    }
}
