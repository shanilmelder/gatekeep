namespace Gatekeep.Tests.Architecture;

/// <summary>How a job type, rate-limit policy or in-process cache is scoped (FR-8, AD-14, AD-15).</summary>
public abstract record KeyScope
{
    /// <summary>Keyed by Tenant: one Tenant's entries, counts or work never reach another's.</summary>
    public static readonly KeyScope Tenant = new TenantKeyed();

    /// <summary>One for the whole Deployment, for the reason given, which must say why this isn't one Tenant's job, and how each Tenant it touches is scoped.</summary>
    public static KeyScope DeploymentWide(string reason) => new DeploymentWideScope(reason);

    public sealed record TenantKeyed : KeyScope
    {
        public override string ToString() => "Tenant";
    }

    public sealed record DeploymentWideScope(string Reason) : KeyScope
    {
        public override string ToString() => $"DeploymentWide({Reason})";
    }
}

/// <summary>
/// Story 1.31 (FR-8, AD-14, AD-15, SM-2): the code-owned registries of every job type, rate-limit
/// policy and in-process cache in <c>src</c>, each declared Tenant-keyed or Deployment-wide. The
/// types themselves are discovered by <see cref="TenantKeyedTypeTests"/>, never listed by hand
/// there: a new one that isn't here fails the build until it is classified.
/// </summary>
public static class TenantKeyedTypes
{
    /// <summary>
    /// Every job type in <c>OperationsContract.ProductionRegistry</c>. A <see cref="KeyScope.Tenant"/>
    /// type must be <c>JobScope.Tenant</c> there, so its row carries a <c>tenant_id</c> the guard checks.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, KeyScope> Jobs = new Dictionary<string, KeyScope>(StringComparer.Ordinal)
    {
        ["operations.job.purge"] = KeyScope.DeploymentWide("Deletes finished rows of the control table job only; reads no Tenant data."),
        ["operations.operation.run"] = KeyScope.DeploymentWide("Fans an Operation out into one operations.operation.step job per Tenant; touches control tables only."),
        ["operations.operation.step"] = KeyScope.Tenant,
        ["audit.retention.sweep"] = KeyScope.DeploymentWide("Fans out one audit.retention.apply job per Tenant; reads only the tenant list."),
        ["audit.retention.apply"] = KeyScope.Tenant,
        ["audit.retention.deployment"] = KeyScope.DeploymentWide("Applies retention to the Deployment chain, a control table."),
        ["audit.chain.purge"] = KeyScope.Tenant,
        ["keys.tenant_keys.backfill"] = KeyScope.DeploymentWide("Not one Tenant's job: it finds every active Tenant missing keys. Each Tenant it touches is backfilled in its own Tenant scope, one at a time (AD-4)."),
        ["keys.signing_keys.rotate"] = KeyScope.DeploymentWide("Not one Tenant's job: it checks every active Tenant's key ages daily. Each Tenant it touches is rotated in its own Tenant scope, one at a time (AD-4)."),
        ["keys.signing_key.destroy"] = KeyScope.Tenant,
        ["keys.transit_keys.sweep"] = KeyScope.DeploymentWide("Not one Tenant's job: it lists every key in custody. Each key's row is read in that key's own Tenant scope, and only orphaned sig- and mgmt- keys are deleted."),
    };

    /// <summary>
    /// Every static <c>RateLimitPolicy</c> field in <c>src</c>, as <c>{declaring type}.{field}</c>.
    /// Every policy today counts Deployment-scoped Admin attempts in <c>admin_attempt</c>, and the
    /// Admins limiter throws on a Tenant context. Story 2.5 adds the Tenant counters (AD-14), and Epic 10 builds sign-in backoff on them.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, KeyScope> RateLimitPolicies = new Dictionary<string, KeyScope>(StringComparer.Ordinal)
    {
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.BootstrapClaimPolicy"] = KeyScope.DeploymentWide("Bootstrap claims per client, before any Tenant exists (AD-31)."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.CredentialRegistrationPolicy"] = KeyScope.DeploymentWide("Admin credential registration per Admin Session; Admins are Deployment-scoped."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.SignInBeginPolicy"] = KeyScope.DeploymentWide("Admin sign-in per client on the Admin hostname; no Tenant names it."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.SignInCompletePolicy"] = KeyScope.DeploymentWide("Admin sign-in per client on the Admin hostname; no Tenant names it."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.AccessDeniedAuditPolicy"] = KeyScope.DeploymentWide("Caps denial events per Admin on the Deployment chain (Story 1.24)."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.FreshAssertionPolicy"] = KeyScope.DeploymentWide("Fresh assertions per Admin Session; Admins are Deployment-scoped."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.RecoveryCodePolicy"] = KeyScope.DeploymentWide("Admin Recovery Code use per client; Admins are Deployment-scoped."),
        ["Gatekeep.Modules.Admins.Contracts.AdminsContract.RecoveryCodeDeploymentPolicy"] = KeyScope.DeploymentWide("One Deployment-wide cap on Admin Recovery Code use."),
    };

    /// <summary>
    /// Every field in <c>src</c> of type <c>ConcurrentDictionary&lt;,&gt;</c>, <c>IMemoryCache</c> or
    /// <c>MemoryCache</c>, as <c>{declaring type}.{field}</c>. A <see cref="KeyScope.Tenant"/> cache
    /// must be keyed by a Tenant ID: a <see cref="Guid"/>, or a key type with a <c>TenantId</c> member.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, KeyScope> Caches = new Dictionary<string, KeyScope>(StringComparer.Ordinal)
    {
        // AD-10 and AD-11's named exceptions: each Tenant's runtime, keyed by its Tenant ID.
        ["Gatekeep.Modules.Protocol.Core.TenantRuntimes._entries"] = KeyScope.Tenant,
    };
}
