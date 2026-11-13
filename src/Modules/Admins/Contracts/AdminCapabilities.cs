using System.Collections.Frozen;
using System.Text.RegularExpressions;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>Where a capability applies: the whole Deployment, or the one Tenant a path names.</summary>
public enum CapabilityScope
{
    Deployment,
    Tenant,
}

/// <summary>The Tenant Roles an Admin can hold in a Tenant (FR-39, A-3). One per Admin per Tenant.</summary>
public enum TenantRole
{
    Viewer,
    Editor,
    Owner,
}

/// <summary>
/// When a capability needs a fresh WebAuthn assertion (FR-46). A <c>When…</c> value is a
/// predicate on the target, which the handler evaluates (AD-20). Story 1.26 enforces it.
/// </summary>
public enum FreshAssertion
{
    Never,
    Always,
    WhenProdTenant,
    WhenLoweringPolicy,
}

/// <summary>
/// One action an Admin, or a machine client, may be allowed (AD-20). Its invariants hold at
/// construction: a fresh-assertion capability is never machine-allowed (V-1); a Deployment one
/// is never machine-allowed (AD-19) and is held by no Tenant Role; a Tenant one is held by at
/// least one Tenant Role. Its name is <c>{scope}.{object}.{action}</c>.
/// </summary>
public sealed partial class Capability
{
    /// <exception cref="ArgumentException">The name or the flags break an invariant.</exception>
    public Capability(string name, CapabilityScope scope, IEnumerable<TenantRole> roles, bool machineAllowed, FreshAssertion freshAssertion)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(roles);

        if (!Enum.IsDefined(scope))
        {
            throw new ArgumentOutOfRangeException(nameof(scope));
        }

        if (!Enum.IsDefined(freshAssertion))
        {
            throw new ArgumentOutOfRangeException(nameof(freshAssertion));
        }

        if (!NamePattern().IsMatch(name)
            || !name.StartsWith(scope == CapabilityScope.Deployment ? "deployment." : "tenant.", StringComparison.Ordinal))
        {
            throw new ArgumentException($"A capability name is {{scope}}.{{object}}.{{action}} in its own scope: {name}.", nameof(name));
        }

        var held = roles.ToFrozenSet();
        if (held.Any(r => !Enum.IsDefined(r)))
        {
            throw new ArgumentOutOfRangeException(nameof(roles));
        }

        if (freshAssertion != FreshAssertion.Never && machineAllowed)
        {
            throw new ArgumentException($"{name}: a fresh-assertion capability is never machine-allowed (V-1).", nameof(machineAllowed));
        }

        if (scope == CapabilityScope.Deployment && machineAllowed)
        {
            throw new ArgumentException($"{name}: a Deployment capability is never machine-allowed (AD-19).", nameof(machineAllowed));
        }

        if (scope == CapabilityScope.Deployment && held.Count != 0)
        {
            throw new ArgumentException($"{name}: no Tenant Role holds a Deployment capability.", nameof(roles));
        }

        if (scope == CapabilityScope.Tenant && held.Count == 0)
        {
            throw new ArgumentException($"{name}: a Tenant capability is held by at least one Tenant Role.", nameof(roles));
        }

        Name = name;
        Scope = scope;
        Roles = held;
        MachineAllowed = machineAllowed;
        FreshAssertion = freshAssertion;
    }

    public string Name { get; }

    public CapabilityScope Scope { get; }

    /// <summary>The Tenant Roles that hold it in their Tenant. Empty for a Deployment capability.</summary>
    public IReadOnlySet<TenantRole> Roles { get; }

    /// <summary>Whether a machine client of the path Tenant may be allowed it (FR-42).</summary>
    public bool MachineAllowed { get; }

    public FreshAssertion FreshAssertion { get; }

    public override string ToString() => Name;

    [GeneratedRegex(@"\A(?:deployment|tenant)\.[a-z_]+\.[a-z_]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();
}

/// <summary>An Admin's Tenant Role in one Tenant, as <c>tenant_role</c> holds it.</summary>
public sealed record TenantRoleGrant(Guid TenantId, TenantRole Role);

/// <summary>
/// The capability table (NFR-5, AR-15, AD-20): the only encoding of the FR-39 matrix, split
/// where <see cref="Capability.FreshAssertion"/> or <see cref="Capability.MachineAllowed"/>
/// differ. No handler, request check, OpenAPI transformer or UI restates a role-to-action rule:
/// each reads it from here. <see cref="Allows"/> is the one decision over it.
/// </summary>
public static class AdminCapabilities
{
    private static readonly TenantRole[] Everyone = [TenantRole.Viewer, TenantRole.Editor, TenantRole.Owner];

    private static readonly TenantRole[] Editors = [TenantRole.Editor, TenantRole.Owner];

    private static readonly TenantRole[] Owners = [TenantRole.Owner];

    // FR-39: Read configuration and Users.
    public static readonly Capability TenantConfigurationRead = Tenant("tenant.configuration.read", Everyone, true, FreshAssertion.Never);
    public static readonly Capability TenantUsersRead = Tenant("tenant.users.read", Everyone, true, FreshAssertion.Never);

    /// <summary>Log summaries, without raw detail.</summary>
    public static readonly Capability TenantLogsRead = Tenant("tenant.logs.read", Everyone, true, FreshAssertion.Never);

    // FR-39: Read raw Log detail with personal data.
    public static readonly Capability TenantLogDetailRead = Tenant("tenant.log_detail.read", Editors, true, FreshAssertion.Never);

    // FR-39: Manage Applications, APIs, Roles, Users, theme and templates.

    /// <summary>Everything about Applications but their callback URLs.</summary>
    public static readonly Capability TenantApplicationsManage = Tenant("tenant.applications.manage", Editors, true, FreshAssertion.Never);

    /// <summary>Creating an Application with callback URLs, or changing them: fresh in a Prod Tenant (FR-46, ADV-22).</summary>
    public static readonly Capability TenantApplicationCallbacksManage = Tenant("tenant.application_callbacks.manage", Editors, false, FreshAssertion.WhenProdTenant);
    public static readonly Capability TenantApisManage = Tenant("tenant.apis.manage", Editors, true, FreshAssertion.Never);

    /// <summary>User RBAC Roles (FR-32), not Tenant Roles.</summary>
    public static readonly Capability TenantRolesManage = Tenant("tenant.roles.manage", Editors, true, FreshAssertion.Never);
    public static readonly Capability TenantUsersManage = Tenant("tenant.users.manage", Editors, true, FreshAssertion.Never);
    public static readonly Capability TenantThemeManage = Tenant("tenant.theme.manage", Editors, true, FreshAssertion.Never);
    public static readonly Capability TenantTemplatesManage = Tenant("tenant.templates.manage", Editors, true, FreshAssertion.Never);

    // FR-39: Configure Tenant settings, enable or disable Connections, export configuration.
    public static readonly Capability TenantSettingsManage = Tenant("tenant.settings.manage", Editors, true, FreshAssertion.Never);
    public static readonly Capability TenantConnectionsToggle = Tenant("tenant.connections.toggle", Editors, true, FreshAssertion.Never);
    public static readonly Capability TenantConfigurationExport = Tenant("tenant.configuration.export", Editors, true, FreshAssertion.Never);

    // FR-39: Manage client secrets, password policy, MFA policy, Connection credentials, email provider and Tenant label.
    public static readonly Capability TenantClientSecretsManage = Tenant("tenant.client_secrets.manage", Owners, false, FreshAssertion.Always);
    public static readonly Capability TenantPasswordPolicyManage = Tenant("tenant.password_policy.manage", Owners, true, FreshAssertion.Never);
    public static readonly Capability TenantMfaPolicyManage = Tenant("tenant.mfa_policy.manage", Owners, false, FreshAssertion.WhenLoweringPolicy);
    public static readonly Capability TenantConnectionCredentialsManage = Tenant("tenant.connection_credentials.manage", Owners, true, FreshAssertion.Never);
    public static readonly Capability TenantEmailProviderManage = Tenant("tenant.email_provider.manage", Owners, false, FreshAssertion.Always);
    public static readonly Capability TenantLabelManage = Tenant("tenant.label.manage", Owners, false, FreshAssertion.WhenProdTenant);

    // FR-39: Rotate or revoke Signing Keys; grant Management API access.
    /// <summary>Story 9.2: rotating on demand is for Tenant Owners only; a machine principal is refused, as Epic 9 says.</summary>
    public static readonly Capability TenantSigningKeysRotate = Tenant("tenant.signing_keys.rotate", Owners, false, FreshAssertion.Never);
    public static readonly Capability TenantSigningKeysRevoke = Tenant("tenant.signing_keys.revoke", Owners, false, FreshAssertion.Always);
    public static readonly Capability TenantManagementAccessGrant = Tenant("tenant.management_access.grant", Owners, false, FreshAssertion.Always);

    // FR-39: Export or erase User data; run FR-50 Tenant actions.
    public static readonly Capability TenantUserDataExport = Tenant("tenant.user_data.export", Owners, true, FreshAssertion.Never);
    public static readonly Capability TenantUserDataErase = Tenant("tenant.user_data.erase", Owners, true, FreshAssertion.Never);
    public static readonly Capability TenantIncidentResponseRun = Tenant("tenant.incident_response.run", Owners, false, FreshAssertion.Always);

    // The Deployment Owner's own (FR-7, FR-39, FR-40, FR-50, Story 8.1): no Tenant Role holds them, and no machine.
    public static readonly Capability DeploymentTenantsRead = Deployment("deployment.tenants.read", FreshAssertion.Never);
    public static readonly Capability DeploymentTenantsCreate = Deployment("deployment.tenants.create", FreshAssertion.Never);
    public static readonly Capability DeploymentTenantsDelete = Deployment("deployment.tenants.delete", FreshAssertion.Always);
    public static readonly Capability DeploymentAdminsRead = Deployment("deployment.admins.read", FreshAssertion.Never);

    /// <summary>Inviting and removing Admins, granting Tenant Roles and resetting credentials.</summary>
    public static readonly Capability DeploymentAdminsManage = Deployment("deployment.admins.manage", FreshAssertion.Always);
    public static readonly Capability DeploymentEmailProviderManage = Deployment("deployment.email_provider.manage", FreshAssertion.Always);
    public static readonly Capability DeploymentIncidentResponseRun = Deployment("deployment.incident_response.run", FreshAssertion.Always);
    public static readonly Capability DeploymentLogRead = Deployment("deployment.log.read", FreshAssertion.Never);

    /// <summary>Every capability, in this fixed order, each once and each also a named field above.</summary>
    public static readonly IReadOnlyList<Capability> All = Unique(
    [
        TenantConfigurationRead,
        TenantUsersRead,
        TenantLogsRead,
        TenantLogDetailRead,
        TenantApplicationsManage,
        TenantApplicationCallbacksManage,
        TenantApisManage,
        TenantRolesManage,
        TenantUsersManage,
        TenantThemeManage,
        TenantTemplatesManage,
        TenantSettingsManage,
        TenantConnectionsToggle,
        TenantConfigurationExport,
        TenantClientSecretsManage,
        TenantPasswordPolicyManage,
        TenantMfaPolicyManage,
        TenantConnectionCredentialsManage,
        TenantEmailProviderManage,
        TenantLabelManage,
        TenantSigningKeysRotate,
        TenantSigningKeysRevoke,
        TenantManagementAccessGrant,
        TenantUserDataExport,
        TenantUserDataErase,
        TenantIncidentResponseRun,
        DeploymentTenantsRead,
        DeploymentTenantsCreate,
        DeploymentTenantsDelete,
        DeploymentAdminsRead,
        DeploymentAdminsManage,
        DeploymentEmailProviderManage,
        DeploymentIncidentResponseRun,
        DeploymentLogRead,
    ]);

    /// <summary>The capability named <paramref name="name"/>, or null when the table has none.</summary>
    public static Capability? Find(string name) => All.FirstOrDefault(c => c.Name == name);

    /// <summary>
    /// The decision, with no I/O. A Deployment capability is allowed only to an Admin who is the
    /// Deployment Owner, never to a machine and never through a Tenant Role. A Tenant capability is
    /// allowed to an Admin only with a path Tenant and their <paramref name="grant"/> in that very
    /// Tenant holding a role in <see cref="Capability.Roles"/>: being Deployment Owner adds nothing
    /// in a Tenant. To a machine, only with a path Tenant that is the machine's own (AD-19) and when
    /// <see cref="Capability.MachineAllowed"/>. Everything else is denied.
    /// <see cref="Capability.FreshAssertion"/> isn't evaluated here.
    /// </summary>
    public static bool Allows(Capability capability, Principal principal, TenantRoleGrant? grant, Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(principal);

        if (capability.Scope == CapabilityScope.Deployment)
        {
            return principal is AdminPrincipal { DeploymentOwner: true };
        }

        if (tenantId is not { } tenant || tenant == Guid.Empty)
        {
            return false;
        }

        return principal switch
        {
            AdminPrincipal => grant is not null && grant.TenantId == tenant && capability.Roles.Contains(grant.Role),
            MachinePrincipal machine => machine.TenantId == tenant && capability.MachineAllowed,
            _ => false,
        };
    }

    /// <summary>
    /// The capabilities of <paramref name="scope"/> that <see cref="Allows"/> gives
    /// <paramref name="principal"/> with <paramref name="grant"/> in the path Tenant
    /// <paramref name="tenantId"/>, in table order. No I/O: it reuses the grant a decision read.
    /// </summary>
    public static IReadOnlyList<Capability> Held(Principal principal, CapabilityScope scope, TenantRoleGrant? grant, Guid? tenantId)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (!Enum.IsDefined(scope))
        {
            throw new ArgumentOutOfRangeException(nameof(scope));
        }

        return [.. All.Where(c => c.Scope == scope && Allows(c, principal, grant, tenantId))];
    }

    private static Capability Tenant(string name, TenantRole[] roles, bool machineAllowed, FreshAssertion freshAssertion) =>
        new(name, CapabilityScope.Tenant, roles, machineAllowed, freshAssertion);

    private static Capability Deployment(string name, FreshAssertion freshAssertion) =>
        new(name, CapabilityScope.Deployment, [], machineAllowed: false, freshAssertion);

    private static IReadOnlyList<Capability> Unique(Capability[] capabilities)
    {
        var duplicate = capabilities.GroupBy(c => c.Name, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
        {
            throw new InvalidOperationException($"The capability table names {duplicate.Key} twice.");
        }

        return Array.AsReadOnly(capabilities);
    }
}
