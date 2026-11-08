using Gatekeep.Kernel.Audit;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Modules.Admins.Core;

/// <summary>
/// The authorizer over <c>tenant_role</c> (Story 1.24). Each call that needs a Tenant Role, an
/// Admin's with a path Tenant, makes one indexed primary-key read of it in the caller's
/// transaction, then applies the pure <see cref="AdminCapabilities.Allows"/>; nothing is cached
/// between calls. <see cref="AuthorizeAsync"/> returns the grant it read, so a request answers
/// from that one read and doesn't read the role again.
/// </summary>
internal sealed class AdminAuthorization(IAuditAppender appender) : IAdminAuthorization
{
    private const string FindRole = "SELECT role FROM tenant_role WHERE tenant_id = @tenant_id AND admin_id = @admin_id";

    private static readonly AuditTypeCode Denied = AdminsEvents.AccessDenied.Code;

    private static readonly AuditTypeCode Rejected = AdminsEvents.CrossTenantRejected.Code;

    public async Task<CapabilityDecision> AuthorizeAsync(
        CommandContext context,
        Principal principal,
        Capability capability,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(capability);

        var grant = capability.Scope == CapabilityScope.Tenant
            ? await GrantAsync(context, principal, tenantId, cancellationToken)
            : null;

        return new CapabilityDecision(AdminCapabilities.Allows(capability, principal, grant, tenantId), capability.FreshAssertion, grant);
    }

    public async Task<IReadOnlyList<Capability>> HeldAsync(
        CommandContext context,
        Principal principal,
        CapabilityScope scope,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(principal);
        if (!Enum.IsDefined(scope))
        {
            throw new ArgumentOutOfRangeException(nameof(scope));
        }

        var grant = scope == CapabilityScope.Tenant
            ? await GrantAsync(context, principal, tenantId, cancellationToken)
            : null;

        return AdminCapabilities.Held(principal, scope, grant, tenantId);
    }

    public async Task DenyAsync(CommandContext context, AdminPrincipal principal, Guid? tenantId, CancellationToken cancellationToken)
    {
        AdminSessions.RequireDeployment(context);
        ArgumentNullException.ThrowIfNull(principal);
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A path Tenant is never the empty UUID.", nameof(tenantId));
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(Denied, Actor.Admin(principal.AdminId), tenantId is null ? null : AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);
    }

    public async Task RejectCrossTenantAsync(CommandContext context, AdminPrincipal principal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(principal);
        if (context.TenantId is not { } tenantId)
        {
            throw new InvalidOperationException("A cross-Tenant rejection goes on the refused Tenant's own chain, in its Tenant scope.");
        }

        await appender.AppendAsync(
            context,
            new AuditEvent(Rejected, Actor.Admin(principal.AdminId), AuditTargetKind.Tenant, tenantId),
            detail: null,
            cancellationToken);
    }

    /// <summary>An Admin's role in the path Tenant, read now. None for a machine, or with no path Tenant.</summary>
    private static async Task<TenantRoleGrant?> GrantAsync(
        CommandContext context,
        Principal principal,
        Guid? tenantId,
        CancellationToken cancellationToken)
    {
        if (principal is not AdminPrincipal admin || tenantId is not { } tenant || tenant == Guid.Empty)
        {
            return null;
        }

        await using var command = context.CreateCommand();
        command.CommandText = FindRole;
        AdminSessions.Add(command, "tenant_id", tenant);
        AdminSessions.Add(command, "admin_id", admin.AdminId);

        return await command.ExecuteScalarAsync(cancellationToken) is string role
            ? new TenantRoleGrant(tenant, ParseRole(role))
            : null;
    }

    private static TenantRole ParseRole(string code) => code switch
    {
        "viewer" => TenantRole.Viewer,
        "editor" => TenantRole.Editor,
        "owner" => TenantRole.Owner,
        _ => throw new InvalidOperationException("A Tenant Role has an unknown value."),
    };
}
