using Gatekeep.Modules.Admins.Contracts;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// A machine client of one Tenant with no token behind it, for testing machine denial at handler
/// level before the Management API exists (Story 1.24, AC 3). Test only: nothing under
/// <c>src/</c> builds a <see cref="MachinePrincipal"/> until Epic 17 validates Management API
/// tokens, which an architecture test enforces, and a test checks this type stays here.
/// </summary>
internal static class TestOnlyMachinePrincipal
{
    /// <summary>A new machine client of <paramref name="tenantId"/>.</summary>
    public static MachinePrincipal For(Guid tenantId) => new(Guid.CreateVersion7(), tenantId);
}
