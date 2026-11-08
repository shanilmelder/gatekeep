using Gatekeep.Adapters.Postgres.Schema;
using Gatekeep.Kernel.Persistence;
using Gatekeep.Modules.Audit.Contracts;
using Gatekeep.Modules.Tenancy.Contracts;
using Npgsql;
using Xunit;

namespace Gatekeep.Tests.Isolation.Tenancy;

/// <summary>
/// Story 9.1 (AD-6): <see cref="ITenants.GetIssuerAsync"/> reads a Tenant's stored issuer as gk_admin,
/// in that Tenant's own scope only, whatever its status; an unknown Tenant has none.
/// </summary>
public sealed class TenantIssuerTests(PostgresFixture postgres)
{
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("active")]
    [InlineData("creating")]
    public async Task The_stored_issuer_is_read_in_the_Tenants_own_scope(string status)
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var tenant = Guid.CreateVersion7();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), tenant, status: status);

        Assert.Equal($"https://{TestTenants.Host(tenant)}/", await IssuerAsync(database, tenant, tenant));
    }

    [Fact]
    public async Task An_unknown_Tenant_has_no_issuer()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var unknown = Guid.CreateVersion7();

        Assert.Null(await IssuerAsync(database, unknown, unknown));
    }

    [Fact]
    public async Task Another_Tenants_scope_or_a_Deployment_scope_is_refused()
    {
        var database = await postgres.NewMigratedDatabaseAsync();
        var a = Guid.CreateVersion7();
        var b = Guid.CreateVersion7();
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), a);
        await TestTenants.InsertAsync(postgres.SuperuserConnection(database), b);

        await Assert.ThrowsAsync<InvalidOperationException>(() => IssuerAsync(database, b, a));

        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await DeploymentScope.BeginAsync(source, Cancellation);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TenancyContract.CreateTenants(AuditContract.CreateAppender()).GetIssuerAsync(scope.CreateCommandContext(), a, Cancellation));
    }

    private async Task<string?> IssuerAsync(string database, Guid scopeTenant, Guid tenant)
    {
        await using var source = NpgsqlDataSource.Create(postgres.RoleConnection(TableRegistry.Admin, database));
        await using var scope = await TenantScope.BeginAsync(source, scopeTenant, Cancellation);
        var issuer = await TenancyContract.CreateTenants(AuditContract.CreateAppender()).GetIssuerAsync(scope.CreateCommandContext(), tenant, Cancellation);
        await scope.CommitAsync(Cancellation);
        return issuer;
    }
}
