using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Admins.Contracts;
using Gatekeep.Modules.Audit.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Admins;

/// <summary>
/// Story 1.24, NFR-5, AR-15, AD-20, FR-39, FR-42, FR-46: the capability table is the FR-39 matrix
/// and nothing more. Generated: every principal, Owner or not, with each Tenant Role or none in the
/// path Tenant, or a role only in another Tenant, and machine clients of the path Tenant and
/// another, against every capability with and without a path Tenant, is allowed exactly what the
/// PRD rows written out here say, so nothing outside the table is ever allowed. Goldens: each Tenant
/// capability is in exactly one FR-39 row with that row's roles; the fresh-assertion capabilities
/// are exactly FR-46's list; and every one of them, and every Deployment capability, is
/// machine-denied. At handler level, on a migrated database, a test-only machine principal through
/// the real authorizer gets exactly its Tenant's machine-allowed capabilities and nothing else.
/// </summary>
public sealed class CapabilityMatrixTests(PostgresFixture postgres)
{
    private static readonly Guid TenantA = Guid.Parse("01900000-0000-7000-8000-00000000c0a1");

    private static readonly Guid TenantB = Guid.Parse("01900000-0000-7000-8000-00000000c0b2");

    private static readonly TenantRole[] Everyone = [TenantRole.Viewer, TenantRole.Editor, TenantRole.Owner];

    private static readonly TenantRole[] Editors = [TenantRole.Editor, TenantRole.Owner];

    private static readonly TenantRole[] Owners = [TenantRole.Owner];

    /// <summary>FR-39's matrix, its rows as the PRD words them, each with the roles that hold it and its capabilities.</summary>
    private static readonly (string Row, TenantRole[] Roles, string[] Capabilities)[] Fr39 =
    [
        ("Read configuration and Users", Everyone, ["tenant.configuration.read", "tenant.users.read", "tenant.logs.read"]),
        ("Read raw Log detail with personal data", Editors, ["tenant.log_detail.read"]),
        (
            "Manage Applications, APIs, Roles, Users, theme and templates",
            Editors,
            [
                "tenant.applications.manage", "tenant.application_callbacks.manage", "tenant.apis.manage", "tenant.roles.manage",
                "tenant.users.manage", "tenant.theme.manage", "tenant.templates.manage",
            ]),
        (
            "Configure Tenant settings, enable or disable Connections, export configuration",
            Editors,
            ["tenant.settings.manage", "tenant.connections.toggle", "tenant.configuration.export"]),
        (
            "Manage client secrets, password policy, MFA policy, Connection credentials, email provider and Tenant label",
            Owners,
            [
                "tenant.client_secrets.manage", "tenant.password_policy.manage", "tenant.mfa_policy.manage",
                "tenant.connection_credentials.manage", "tenant.email_provider.manage", "tenant.label.manage",
            ]),
        (
            "Rotate or revoke Signing Keys; grant Management API access",
            Owners,
            ["tenant.signing_keys.rotate", "tenant.signing_keys.revoke", "tenant.management_access.grant"]),
        (
            "Export or erase User data; run FR-50 Tenant actions",
            Owners,
            ["tenant.user_data.export", "tenant.user_data.erase", "tenant.incident_response.run"]),
    ];

    /// <summary>FR-46's fresh-assertion actions, as the PRD words them, each with its capabilities.</summary>
    private static readonly (string Action, string[] Capabilities)[] Fr46 =
    [
        ("Admin grant or removal", ["deployment.admins.manage"]),
        ("Signing Key revocation", ["tenant.signing_keys.revoke"]),
        ("lowering MFA policy", ["tenant.mfa_policy.manage"]),
        ("changing a Prod Tenant's callback URLs", ["tenant.application_callbacks.manage"]),
        ("or label", ["tenant.label.manage"]),
        ("rotating a client secret", ["tenant.client_secrets.manage"]),
        ("changing the email provider", ["tenant.email_provider.manage", "deployment.email_provider.manage"]),
        ("granting Management API access", ["tenant.management_access.grant"]),
        ("Tenant deletion", ["deployment.tenants.delete"]),
        ("FR-50 actions", ["tenant.incident_response.run", "deployment.incident_response.run"]),
    ];

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public void Generated_matrix_allows_nothing_outside_the_PRD_rows()
    {
        var checkedCases = 0;
        foreach (var principal in Principals())
        {
            foreach (var capability in AdminCapabilities.All)
            {
                foreach (var tenant in new Guid?[] { TenantA, null })
                {
                    var expected = Expected(capability, principal.Principal, principal.Grant, tenant);
                    Assert.True(
                        AdminCapabilities.Allows(capability, principal.Principal, principal.Grant, tenant) == expected,
                        $"{principal.Name} on {capability.Name} with path Tenant {(tenant is null ? "none" : "A")}: expected {(expected ? "allowed" : "denied")}.");
                    checkedCases++;
                }
            }
        }

        // 16 principals, 34 capabilities, with and without a path Tenant.
        Assert.Equal(16 * 34 * 2, checkedCases);
    }

    [Fact]
    public void Table_holds_34_uniquely_named_capabilities_each_a_named_field()
    {
        Assert.Equal(34, AdminCapabilities.All.Count);
        Assert.Equal(AdminCapabilities.All.Count, AdminCapabilities.All.Select(c => c.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.All(AdminCapabilities.All, c => Assert.Matches(@"\A(?:deployment|tenant)\.[a-z_]+\.[a-z_]+\z", c.Name));

        var fields = typeof(AdminCapabilities).GetFields()
            .Where(f => f.FieldType == typeof(Capability))
            .Select(f => (Capability)f.GetValue(null)!)
            .ToList();
        Assert.Equal(AdminCapabilities.All.Count, fields.Count);
        Assert.All(AdminCapabilities.All, c => Assert.Contains(c, fields));

        Assert.Null(AdminCapabilities.Find("tenant.nothing.read"));
        Assert.Same(AdminCapabilities.TenantConfigurationRead, AdminCapabilities.Find("tenant.configuration.read"));
    }

    [Fact]
    public void Every_Tenant_capability_is_in_exactly_one_FR39_row_with_its_roles()
    {
        var tenantCapabilities = AdminCapabilities.All.Where(c => c.Scope == CapabilityScope.Tenant).ToList();

        Assert.Equal(26, tenantCapabilities.Count);
        foreach (var capability in tenantCapabilities)
        {
            var row = Assert.Single(Fr39, r => r.Capabilities.Contains(capability.Name));
            Assert.Equal(row.Roles.Order(), capability.Roles.Order());
        }

        // And every name a row maps is in the table, as a Tenant capability.
        Assert.All(Fr39.SelectMany(r => r.Capabilities), n => Assert.Contains(tenantCapabilities, c => c.Name == n));
        Assert.All(AdminCapabilities.All.Where(c => c.Scope == CapabilityScope.Deployment), c => Assert.Empty(c.Roles));
    }

    [Fact]
    public void Every_Tenant_Role_holds_the_capability_that_gates_the_capability_list()
    {
        // GET /api/v1/tenants/{tenantId}/capabilities needs tenant.configuration.read: a role
        // without it would see no list at all, not an empty one.
        Assert.Equal(Enum.GetValues<TenantRole>().Order(), AdminCapabilities.TenantConfigurationRead.Roles.Order());
    }

    [Fact]
    public void Fresh_assertion_capabilities_are_exactly_FR46s_list()
    {
        Assert.Equal(
            Fr46.SelectMany(a => a.Capabilities).Order(StringComparer.Ordinal),
            AdminCapabilities.All.Where(c => c.FreshAssertion != FreshAssertion.Never).Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Every_fresh_assertion_and_every_Deployment_capability_is_machine_denied()
    {
        Assert.All(
            AdminCapabilities.All.Where(c => c.FreshAssertion != FreshAssertion.Never || c.Scope == CapabilityScope.Deployment),
            c => Assert.False(c.MachineAllowed, c.Name));

        // FR-42 literally: everything else is machine-allowed.
        Assert.All(
            AdminCapabilities.All.Where(c => c.FreshAssertion == FreshAssertion.Never && c.Scope == CapabilityScope.Tenant),
            c => Assert.True(c.MachineAllowed, c.Name));
    }

    public static TheoryData<string, CapabilityScope, TenantRole[], bool, FreshAssertion> BrokenInvariants => new()
    {
        // V-1: a fresh-assertion capability is never machine-allowed.
        { "tenant.thing.do", CapabilityScope.Tenant, [TenantRole.Owner], true, FreshAssertion.Always },
        { "tenant.thing.do", CapabilityScope.Tenant, [TenantRole.Owner], true, FreshAssertion.WhenProdTenant },
        // AD-19: a Deployment capability is never machine-allowed.
        { "deployment.thing.do", CapabilityScope.Deployment, [], true, FreshAssertion.Never },
        // No Tenant Role holds a Deployment capability; a Tenant one is held by at least one.
        { "deployment.thing.do", CapabilityScope.Deployment, [TenantRole.Owner], false, FreshAssertion.Never },
        { "tenant.thing.do", CapabilityScope.Tenant, [], false, FreshAssertion.Never },
        // The name is {scope}.{object}.{action}, in its own scope.
        { "tenant.thing", CapabilityScope.Tenant, [TenantRole.Owner], false, FreshAssertion.Never },
        { "Tenant.thing.do", CapabilityScope.Tenant, [TenantRole.Owner], false, FreshAssertion.Never },
        { "deployment.thing.do", CapabilityScope.Tenant, [TenantRole.Owner], false, FreshAssertion.Never },
        { "tenant.thing.do", CapabilityScope.Deployment, [], false, FreshAssertion.Never },
        { "tenant.thing.do\n", CapabilityScope.Tenant, [TenantRole.Owner], false, FreshAssertion.Never },
    };

    [Theory]
    [MemberData(nameof(BrokenInvariants))]
    public void Capability_refuses_a_broken_invariant(string name, CapabilityScope scope, TenantRole[] roles, bool machineAllowed, FreshAssertion fresh)
    {
        Assert.ThrowsAny<ArgumentException>(() => new Capability(name, scope, roles, machineAllowed, fresh));
    }

    [Fact]
    public async Task Machine_principal_at_handler_level_follows_MachineAllowed_and_its_own_Tenant()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(
            postgres.SuperuserConnection(database),
            TestTenants.InsertSql(TenantA, TenantB));
        var authorization = AdminsContract.CreateAuthorization(AuditContract.CreateAppender());
        var machine = TestOnlyMachinePrincipal.For(TenantA);

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);
        var context = scope.CreateCommandContext();

        var allowed = new List<string>();
        foreach (var capability in AdminCapabilities.All)
        {
            var inA = await authorization.AuthorizeAsync(context, machine, capability, TenantA, Cancellation);
            var inB = await authorization.AuthorizeAsync(context, machine, capability, TenantB, Cancellation);
            var none = await authorization.AuthorizeAsync(context, machine, capability, null, Cancellation);

            Assert.False(inB.Allowed, $"{capability.Name} in another Tenant");
            Assert.False(none.Allowed, $"{capability.Name} with no Tenant");
            Assert.Equal(capability.FreshAssertion, inA.FreshAssertion);
            if (inA.Allowed)
            {
                allowed.Add(capability.Name);
            }
        }

        var expected = AdminCapabilities.All.Where(c => c.Scope == CapabilityScope.Tenant && c.MachineAllowed).Select(c => c.Name).ToList();
        Assert.Equal(expected, allowed);
        Assert.Equal(18, expected.Count);
        Assert.DoesNotContain(allowed, n => n.StartsWith("deployment.", StringComparison.Ordinal));

        Assert.Equal(expected, (await authorization.HeldAsync(context, machine, CapabilityScope.Tenant, TenantA, Cancellation)).Select(c => c.Name));
        Assert.Empty(await authorization.HeldAsync(context, machine, CapabilityScope.Tenant, TenantB, Cancellation));
        Assert.Empty(await authorization.HeldAsync(context, machine, CapabilityScope.Deployment, null, Cancellation));
    }

    [Fact]
    public async Task Authorizer_serves_a_Deployment_scope_only()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        await PostgresFixture.ExecuteAsync(postgres.SuperuserConnection(database), TestTenants.InsertSql(TenantA));
        var authorization = AdminsContract.CreateAuthorization(AuditContract.CreateAppender());

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, TenantA, Cancellation);

        await Assert.ThrowsAsync<InvalidOperationException>(() => authorization.AuthorizeAsync(
            scope.CreateCommandContext(), TestOnlyMachinePrincipal.For(TenantA), AdminCapabilities.TenantConfigurationRead, TenantA, Cancellation));
    }

    [Fact]
    public void Test_only_machine_principal_lives_only_under_tests()
    {
        Assert.Equal(typeof(CapabilityMatrixTests).Assembly, typeof(TestOnlyMachinePrincipal).Assembly);

        var offenders = Directory
            .EnumerateFiles(Path.Combine(BuildOutput.RepositoryRoot(), "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => File.ReadAllText(f).Contains(nameof(TestOnlyMachinePrincipal), StringComparison.Ordinal));

        Assert.Empty(offenders);
    }

    /// <summary>The rule, from the PRD rows above, not the table: only the machine flags are the table's (asserted separately).</summary>
    private static bool Expected(Capability capability, Principal principal, TenantRoleGrant? grant, Guid? tenant)
    {
        if (capability.Name.StartsWith("deployment.", StringComparison.Ordinal))
        {
            return principal is AdminPrincipal { DeploymentOwner: true };
        }

        if (tenant is null)
        {
            return false;
        }

        return principal switch
        {
            AdminPrincipal => grant is not null && grant.TenantId == tenant
                && Fr39.Single(r => r.Capabilities.Contains(capability.Name)).Roles.Contains(grant.Role),
            MachinePrincipal machine => machine.TenantId == tenant && capability.MachineAllowed,
            _ => false,
        };
    }

    /// <summary>
    /// Admins, Owner or not, with no role, each role in the path Tenant A, or each role in B only;
    /// and machine clients of A and of B.
    /// </summary>
    private static IEnumerable<(string Name, Principal Principal, TenantRoleGrant? Grant)> Principals()
    {
        foreach (var owner in new[] { false, true })
        {
            var admin = new AdminPrincipal(Guid.CreateVersion7(), owner);
            var who = owner ? "Deployment Owner" : "Admin";
            yield return ($"{who} with no role", admin, null);
            foreach (var role in Everyone)
            {
                yield return ($"{who} as {role} in A", admin, new TenantRoleGrant(TenantA, role));
                yield return ($"{who} as {role} in B only", admin, new TenantRoleGrant(TenantB, role));
            }
        }

        yield return ("machine of A", TestOnlyMachinePrincipal.For(TenantA), null);
        yield return ("machine of B", TestOnlyMachinePrincipal.For(TenantB), null);
    }
}
