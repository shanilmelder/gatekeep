using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Identity.Core;

/// <summary>
/// A User's email address, read by ID at the moment it is needed (Story 4.5): Host.Worker resolves a recipient this way
/// when it sends, so a change after the email was queued is what counts. Story 4.7 writes it; this only reads.
/// </summary>
internal static class UserEmails
{
    private const string Select = "SELECT email FROM \"user\" WHERE tenant_id = @tenant_id AND id = @id";

    public static async Task<string?> ReadAsync(CommandContext context, Guid userId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var tenantId = context.TenantId
            ?? throw new InvalidOperationException("A User's email is read in its Tenant's own scope.");

        await using var command = context.CreateCommand();
        command.CommandText = Select;
        Add(command, "tenant_id", tenantId);
        Add(command, "id", userId);
        return await command.ExecuteScalarAsync(cancellationToken) as string;
    }

    private static void Add(System.Data.Common.DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
