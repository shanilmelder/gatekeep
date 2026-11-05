using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>The creator's Owner role, inserted with the Tenant it was just created for (Story 1.27), and an Admin's Tenant IDs (Story 1.28).</summary>
internal sealed class AdminTenantRoles : IAdminTenantRoles
{
    private const string InsertOwner =
        "INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES (@tenant_id, @admin_id, 'owner')";

    private const string SelectTenantIds = "SELECT tenant_id FROM tenant_role WHERE admin_id = @admin_id";

    public async Task GrantCreatorOwnerAsync(CommandContext context, Guid adminId, Guid tenantId, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        if (adminId == Guid.Empty || tenantId == Guid.Empty)
        {
            throw new ArgumentException("A Tenant Role names an Admin and a Tenant.");
        }

        await using var command = context.CreateCommand();
        command.CommandText = InsertOwner;
        AdminSessions.Add(command, "tenant_id", tenantId);
        AdminSessions.Add(command, "admin_id", adminId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Guid>> ListTenantIdsAsync(CommandContext context, Guid adminId, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        if (adminId == Guid.Empty)
        {
            throw new ArgumentException("An Admin has an ID.", nameof(adminId));
        }

        var ids = new List<Guid>();
        await using var command = context.CreateCommand();
        command.CommandText = SelectTenantIds;
        AdminSessions.Add(command, "admin_id", adminId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            ids.Add(reader.GetGuid(0));
        }

        return ids;
    }
}
