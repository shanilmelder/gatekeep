using System.Globalization;

namespace Gatekeep.Tests.Isolation;

/// <summary>
/// Valid <c>tenant</c> rows for tests that need a Tenant but not its creation (Story 1.27): every
/// column a created Tenant has, with a host, issuer and RP ID unique to its ID. Written as the
/// superuser, since only Tenant creation writes them otherwise. <see cref="InsertSql"/> is for a
/// test that writes them inside its own SQL.
/// </summary>
internal static class TestTenants
{
    /// <summary>The zone test Tenants' hosts sit under.</summary>
    public const string Zone = "tenants.gatekeep.test";

    /// <summary>The host a test Tenant gets unless the test names one: unique to its ID.</summary>
    public static string Host(Guid id) => $"t-{id:N}.{Zone}";

    /// <summary>
    /// SQL inserting each of <paramref name="ids"/> as an <c>active</c> Tenant, with no trailing
    /// semicolon. Its host isn't inserted: <see cref="InsertAsync"/> does that. The superuser writes it
    /// with triggers off (<c>session_replication_role = replica</c>), since only a creation Operation
    /// makes a real Tenant active, and turns them back on after.
    /// </summary>
    public static string InsertSql(params Guid[] ids) => InsertSql(ids.Select(id => (id, Host(id))));

    /// <summary><see cref="InsertSql(Guid[])"/> for IDs a test keeps as text.</summary>
    public static string InsertSql(params string[] ids) => InsertSql([.. ids.Select(Guid.Parse)]);

    /// <summary>
    /// Inserts the Tenant and, when <paramref name="host"/> is given, its <c>subdomain</c> host, as the
    /// superuser, with <paramref name="label"/> and <paramref name="name"/> (Story 1.28).
    /// </summary>
    public static async Task InsertAsync(string connection, Guid id, string? host = null, string status = "active", string label = "dev", string name = "Test Tenant")
    {
        var statement = InsertSql([(id, host ?? Host(id))], status, label, name);
        if (host is not null)
        {
            statement = $"{Replica}; INSERT INTO tenant_host (host, tenant_id, kind) VALUES ('{host}', '{id}', 'subdomain'); {statement}";
        }

        await PostgresFixture.ExecuteAsync(connection, statement);
    }

    /// <summary>
    /// SQL inserting a <c>machine</c> Application (Story 2.5) for each of <paramref name="ids"/> in
    /// <paramref name="tenant"/>, with no secret and no trailing semicolon, for a test that needs a row
    /// to reference: <c>signin_transaction</c>, <c>authorization</c> and <c>token</c> reference one.
    /// </summary>
    public static string ApplicationSql(Guid tenant, params Guid[] ids) =>
        "INSERT INTO application (tenant_id, id, name, kind, grant_types, created_at) VALUES "
        + string.Join(", ", ids.Select(id => $"('{tenant}', '{id}', 'Test Application', 'machine', ARRAY['client_credentials'], now())"));

    private const string Replica = "SET session_replication_role = replica";

    private const string Origin = "SET session_replication_role = DEFAULT";

    /// <summary>
    /// Gives <paramref name="adminId"/> <paramref name="role"/> (<c>viewer</c>, <c>editor</c> or
    /// <c>owner</c>) in the Tenant, as the superuser: no route grants a role but the creator's
    /// before Story 8.4.
    /// </summary>
    public static Task GrantRoleAsync(string connection, Guid tenantId, Guid adminId, string role) =>
        PostgresFixture.ExecuteAsync(
            connection,
            $"INSERT INTO tenant_role (tenant_id, admin_id, role) VALUES ('{tenantId}', '{adminId}', '{role}')");

    private static string InsertSql(IEnumerable<(Guid Id, string Host)> tenants, string status = "active", string label = "dev", string name = "Test Tenant") =>
        Replica + "; INSERT INTO tenant (id, name, label, status, issuer, rp_id, email_link_base) VALUES "
        + string.Join(", ", tenants.Select(t => string.Create(
            CultureInfo.InvariantCulture,
            $"('{t.Id}', '{name.Replace("'", "''", StringComparison.Ordinal)}', '{label}', '{status}', 'https://{t.Host}/', '{t.Host}', 'https://{t.Host}/')")))
        + "; " + Origin;
}
