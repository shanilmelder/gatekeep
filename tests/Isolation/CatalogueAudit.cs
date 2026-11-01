using Gatekeep.Adapters.Postgres.Schema;
using Npgsql;

namespace Gatekeep.Tests.Isolation;

/// <summary>
/// The AD-3 catalogue check: compares a database with a registry and names every
/// difference. It takes its connection so a test can check an uncommitted bad change.
/// </summary>
internal static class CatalogueAudit
{
    private const string Schema = "public";

    private const string RestrictiveExpression = "(tenant_id = (current_setting('gatekeep.tenant_id'::text))::uuid)";

    public static async Task<IReadOnlyList<string>> CheckAsync(
        NpgsqlConnection connection,
        IReadOnlyList<TableEntry> registry)
    {
        var problems = new List<string>();

        foreach (var entry in registry.Where(e => string.IsNullOrWhiteSpace(e.Owner)))
        {
            problems.Add($"{entry.Name}: registry entry has no owner.");
        }

        await CheckTablesAsync(connection, registry, problems);
        await CheckGrantsAsync(connection, registry, problems);
        await CheckRolesAsync(connection, problems);
        await CheckTenantDefaultsAsync(connection, problems);
        await CheckSchemaAsync(connection, problems);
        await CheckDatabaseAsync(connection, problems);

        foreach (var entry in registry.Where(e => e.Class == TableClass.Tenant))
        {
            await CheckTenantColumnAsync(connection, entry.Name, problems);
        }

        await CheckPoliciesAsync(connection, registry, problems);
        await CheckForeignKeysAsync(connection, registry, problems);

        return problems;
    }

    private static async Task CheckTablesAsync(
        NpgsqlConnection connection,
        IReadOnlyList<TableEntry> registry,
        List<string> problems)
    {
        // Every relation in every user schema, so a view or another schema can't hide a table.
        var rows = await QueryAsync(
            connection,
            """
            SELECT n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner),
                   c.relrowsecurity::text, c.relforcerowsecurity::text
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg\_toast%'
              AND n.nspname NOT LIKE 'pg\_temp%'
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
            """);

        foreach (var row in rows)
        {
            var (schema, name, kind, owner, rowSecurity, forceRowSecurity) = (row[0], row[1], row[2], row[3], row[4], row[5]);

            if (owner != TableRegistry.Migrator)
            {
                problems.Add($"{name}: owned by {owner}, not {TableRegistry.Migrator}.");
            }

            if (kind == "S")
            {
                continue;
            }

            var entry = registry.SingleOrDefault(e => schema == Schema && e.Name == name);
            if (entry is null)
            {
                problems.Add($"{schema}.{name}: not in the table registry.");
                continue;
            }

            var isTenant = entry.Class == TableClass.Tenant;
            if (rowSecurity != (isTenant ? "true" : "false"))
            {
                problems.Add($"{name}: ENABLE ROW LEVEL SECURITY is {rowSecurity} for class {entry.Class}.");
            }

            if (forceRowSecurity != (isTenant ? "true" : "false"))
            {
                problems.Add($"{name}: FORCE ROW LEVEL SECURITY is {forceRowSecurity} for class {entry.Class}.");
            }
        }

        foreach (var entry in registry.Where(e => !rows.Any(r => r[0] == Schema && r[1] == e.Name)))
        {
            problems.Add($"{entry.Name}: in the registry but not in the database.");
        }
    }

    private static async Task CheckGrantsAsync(
        NpgsqlConnection connection,
        IReadOnlyList<TableEntry> registry,
        List<string> problems)
    {
        // aclexplode reports grantee 0 for PUBLIC, which information_schema can hide.
        var rows = await QueryAsync(
            connection,
            """
            SELECT n.nspname, c.relname,
                   CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                   a.privilege_type, '', a.is_grantable::text
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            CROSS JOIN LATERAL aclexplode(c.relacl) a
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg\_toast%'
              AND a.grantee <> c.relowner
            UNION ALL
            SELECT n.nspname, c.relname,
                   CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                   a.privilege_type, att.attname, a.is_grantable::text
            FROM pg_attribute att
            JOIN pg_class c ON c.oid = att.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            CROSS JOIN LATERAL aclexplode(att.attacl) a
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg\_toast%'
              AND a.grantee <> c.relowner
            """);

        static string Grant(string[] r) =>
            r[4].Length == 0 ? $"{r[0]}.{r[1]} {r[2]} {r[3]}" : $"{r[0]}.{r[1]}.{r[4]} {r[2]} {r[3]}";

        var actual = rows.Select(Grant).ToHashSet();

        problems.AddRange(rows.Where(r => r[5] == "true").Select(r => $"Grant option not allowed: {Grant(r)}."));

        var expected = registry
            .SelectMany(e => e.Grants.SelectMany(g => g.Value.Select(p => $"{Schema}.{e.Name} {g.Key} {p}")))
            .ToHashSet();

        problems.AddRange(actual.Except(expected).Order().Select(g => $"Grant not in the registry: {g}."));
        problems.AddRange(expected.Except(actual).Order().Select(g => $"Grant missing from the database: {g}."));
    }

    private static async Task CheckRolesAsync(NpgsqlConnection connection, List<string> problems)
    {
        var rows = await QueryAsync(
            connection,
            """
            SELECT r.rolname, r.rolsuper::text, r.rolbypassrls::text, r.rolcreaterole::text, r.rolcreatedb::text,
                   EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid)::text,
                   r.rolreplication::text,
                   EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = r.oid)::text
            FROM pg_roles r
            WHERE r.rolname LIKE 'gk\_%'
            """);

        var expected = TableRegistry.RuntimeRoles.Append(TableRegistry.Migrator).Order().ToList();
        var actual = rows.Select(r => r[0]).Order().ToList();

        if (!expected.SequenceEqual(actual))
        {
            problems.Add($"Roles are [{string.Join(", ", actual)}], not [{string.Join(", ", expected)}].");
        }

        foreach (var row in rows)
        {
            AddIfTrue(row[1], $"{row[0]}: holds superuser.");
            AddIfTrue(row[2], $"{row[0]}: holds BYPASSRLS.");
            AddIfTrue(row[3], $"{row[0]}: holds CREATEROLE.");
            AddIfTrue(row[4], $"{row[0]}: holds CREATEDB.");
            AddIfTrue(row[5], $"{row[0]}: is a member of another role.");
            AddIfTrue(row[6], $"{row[0]}: holds REPLICATION.");
            AddIfTrue(row[7], $"{row[0]}: has members.");
        }

        void AddIfTrue(string value, string problem)
        {
            if (value == "true")
            {
                problems.Add(problem);
            }
        }
    }

    private static async Task CheckTenantDefaultsAsync(NpgsqlConnection connection, List<string> problems)
    {
        // A stored default would make an unscoped query run silently as that Tenant.
        var rows = await QueryAsync(
            connection,
            """
            SELECT coalesce(r.rolname::text, 'all roles'), coalesce(d.datname::text, 'all databases'), setting
            FROM pg_db_role_setting s
            LEFT JOIN pg_roles r ON r.oid = s.setrole
            LEFT JOIN pg_database d ON d.oid = s.setdatabase
            CROSS JOIN LATERAL unnest(s.setconfig) AS setting
            WHERE setting LIKE '%gatekeep.tenant_id%'
            """);

        problems.AddRange(rows.Select(r => $"Tenant setting default for {r[0]} in {r[1]}: {r[2]}."));
    }

    private static async Task CheckDatabaseAsync(NpgsqlConnection connection, List<string> problems)
    {
        var rows = await QueryAsync(
            connection,
            """
            SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                   a.privilege_type, a.is_grantable::text
            FROM pg_database d
            CROSS JOIN LATERAL aclexplode(d.datacl) a
            WHERE d.datname = current_database() AND a.grantee <> d.datdba
            """);

        var actual = rows
            .Select(r => r[2] == "true" ? $"{r[0]} {r[1]} WITH GRANT OPTION" : $"{r[0]} {r[1]}")
            .ToHashSet();
        var expected = TableRegistry.RuntimeRoles.Append(TableRegistry.Migrator).Select(r => $"{r} CONNECT").ToHashSet();

        problems.AddRange(actual.Except(expected).Order().Select(g => $"Database grant not allowed: {g}."));
        problems.AddRange(expected.Except(actual).Order().Select(g => $"Database grant missing: {g}."));
    }

    private static async Task CheckSchemaAsync(NpgsqlConnection connection, List<string> problems)
    {
        var owner = await QueryAsync(
            connection,
            $"SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = '{Schema}'");

        if (owner[0][0] != TableRegistry.Migrator)
        {
            problems.Add($"Schema {Schema}: owned by {owner[0][0]}, not {TableRegistry.Migrator}.");
        }

        var rows = await QueryAsync(
            connection,
            $"""
            SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, a.privilege_type
            FROM pg_namespace n
            CROSS JOIN LATERAL aclexplode(n.nspacl) a
            WHERE n.nspname = '{Schema}' AND a.grantee <> n.nspowner
            """);

        var actual = rows.Select(r => $"{r[0]} {r[1]}").ToHashSet();
        var expected = TableRegistry.RuntimeRoles.Select(r => $"{r} USAGE").ToHashSet();

        problems.AddRange(actual.Except(expected).Order().Select(g => $"Schema grant not allowed: {g}."));
        problems.AddRange(expected.Except(actual).Order().Select(g => $"Schema grant missing: {g}."));
    }

    private static async Task CheckTenantColumnAsync(NpgsqlConnection connection, string table, List<string> problems)
    {
        var rows = await QueryAsync(
            connection,
            $"""
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = '{Schema}' AND table_name = '{table}' AND column_name = 'tenant_id'
            """);

        if (rows is not [["uuid", "NO"]])
        {
            problems.Add($"{table}: needs tenant_id uuid NOT NULL.");
        }
    }

    private static async Task CheckPoliciesAsync(
        NpgsqlConnection connection,
        IReadOnlyList<TableEntry> registry,
        List<string> problems)
    {
        var rows = await QueryAsync(
            connection,
            """
            SELECT tablename, permissive, cmd, array_to_string(roles, ','), coalesce(qual, ''), coalesce(with_check, '')
            FROM pg_policies
            """);

        foreach (var entry in registry)
        {
            var policies = rows.Where(r => r[0] == entry.Name).Select(r => string.Join("|", r.Skip(1))).Order().ToList();

            string[] expected = entry.Class == TableClass.Tenant
                ?
                [
                    "PERMISSIVE|ALL|public|true|true",
                    $"RESTRICTIVE|ALL|public|{RestrictiveExpression}|{RestrictiveExpression}",
                ]
                : [];

            if (!policies.SequenceEqual(expected))
            {
                problems.Add($"{entry.Name}: policies are [{string.Join("; ", policies)}], not the AD-3 pair.");
            }
        }
    }

    private static async Task CheckForeignKeysAsync(
        NpgsqlConnection connection,
        IReadOnlyList<TableEntry> registry,
        List<string> problems)
    {
        var rows = await QueryAsync(
            connection,
            """
            SELECT con.conname, con.conrelid::regclass::text, con.confrelid::regclass::text,
                   con.confdeltype::text,
                   (SELECT coalesce(bool_or(child.attname = 'tenant_id' AND parent.attname = 'tenant_id'), false)
                    FROM unnest(con.conkey, con.confkey) WITH ORDINALITY AS pair (child_column, parent_column, position)
                    JOIN pg_attribute child ON child.attrelid = con.conrelid AND child.attnum = pair.child_column
                    JOIN pg_attribute parent ON parent.attrelid = con.confrelid AND parent.attnum = pair.parent_column
                   )::text
            FROM pg_constraint con
            WHERE con.contype = 'f'
            """);

        var tenantTables = registry.Where(e => e.Class == TableClass.Tenant).Select(e => e.Name).ToHashSet();

        foreach (var row in rows)
        {
            if (row[3] != "r")
            {
                problems.Add($"{row[0]}: foreign key isn't ON DELETE RESTRICT.");
            }

            var betweenTenantTables = tenantTables.Contains(row[1]) && tenantTables.Contains(row[2]);
            if (betweenTenantTables && row[4] != "true")
            {
                problems.Add($"{row[0]}: foreign key between tenant tables isn't composite on tenant_id.");
            }
        }
    }

    private static async Task<List<string[]>> QueryAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync();

        var rows = new List<string[]>();
        while (await reader.ReadAsync())
        {
            var row = new string[reader.FieldCount];
            for (var i = 0; i < row.Length; i++)
            {
                row[i] = reader.GetString(i);
            }

            rows.Add(row);
        }

        return rows;
    }
}
