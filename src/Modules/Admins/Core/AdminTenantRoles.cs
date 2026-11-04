using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>The creator's Owner role, inserted with the Tenant it was just created for (Story 1.27).</summary>
internal sealed class AdminTenantRoles : IAdminTenantRoles
{
    private const string InsertOwner =
        "INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES (@tenant_id, @admin_id, 'owner')";

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
}
