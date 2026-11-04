using Gatekeep.Kernel.Persistence;

namespace Gatekeep.Modules.Admins.Contracts;

/// <summary>Who is asking for a capability: an Admin, or a machine client of one Tenant.</summary>
public abstract record Principal
{
    private protected Principal()
    {
    }
}

/// <summary>An authenticated Admin, as the request checks build it from their Admin Session.</summary>
public sealed record AdminPrincipal(Guid AdminId, bool DeploymentOwner) : Principal;

/// <summary>
/// A machine client of one Tenant (FR-42). Nothing under <c>src/</c> builds one until the
/// Management API validates its tokens (Epic 17); an architecture test holds it to that, and
/// tests build one through their own test-only type.
/// </summary>
public sealed record MachinePrincipal(Guid ClientId, Guid TenantId) : Principal;

/// <summary>
/// Whether a capability was allowed, and the fresh assertion it then needs, which isn't
/// evaluated here: Story 1.26 enforces it, and the handler evaluates a <c>When…</c> predicate.
/// <see cref="Grant"/> is the Tenant Role the decision read, if any, so the caller can answer the
/// rest of the request from that one read (<see cref="AdminCapabilities.Held"/>) and never from a
/// second one that could disagree.
/// </summary>
public sealed record CapabilityDecision(bool Allowed, FreshAssertion FreshAssertion, TenantRoleGrant? Grant = null);

/// <summary>
/// The authorizer over <see cref="AdminCapabilities"/> (AD-20). It runs as <c>gk_admin</c>, in a
/// Deployment scope, in the caller's transaction. For an Admin and a path Tenant it reads their
/// <c>tenant_role</c> row there on every call and caches nothing, so a role removed mid-session
/// counts on the next request. It never reads <c>tenant</c>, which Tenancy owns (AD-1): an
/// unknown Tenant and a Tenant the Admin holds no role in get the same answer. The Tenant comes
/// only from the caller, which takes it from the path (AD-4, AD-19).
/// </summary>
public interface IAdminAuthorization
{
    /// <summary>The decision on <paramref name="capability"/> for <paramref name="principal"/> in the path Tenant <paramref name="tenantId"/>, if any.</summary>
    Task<CapabilityDecision> AuthorizeAsync(
        CommandContext context,
        Principal principal,
        Capability capability,
        Guid? tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// The capabilities of <paramref name="scope"/> that <paramref name="principal"/> holds, in the
    /// path Tenant <paramref name="tenantId"/> for the Tenant scope, in table order.
    /// </summary>
    Task<IReadOnlyList<Capability>> HeldAsync(
        CommandContext context,
        Principal principal,
        CapabilityScope scope,
        Guid? tenantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Appends <see cref="AdminsEvents.AccessDenied"/> on the Deployment chain, in the caller's
    /// transaction: the Actor is the Admin, and the target the path Tenant when the path named a
    /// well-formed one, whether or not it exists. It holds no capability name, Session ID or CSRF token.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="tenantId"/> is the empty UUID.</exception>
    [StateChanging]
    Task DenyAsync(CommandContext context, AdminPrincipal principal, Guid? tenantId, CancellationToken cancellationToken);
}
