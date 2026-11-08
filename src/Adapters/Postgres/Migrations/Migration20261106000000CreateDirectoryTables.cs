using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 2.5 (FR-13, AD-8, AD-9, AD-14, AD-24, AD-27): Client Credentials.
/// <list type="bullet">
/// <item>Directory's <c>application</c>: one row per Application, of a checked kind (<c>machine</c> for now)
/// and a checked set of grant types. It has no secret column: OpenIddict's stays empty.</item>
/// <item>Directory's <c>client_secret</c>: only the 32-byte SHA-256 of a secret, unique per Tenant, with
/// its optional end (<c>expires_at</c>, for Epic 3's rotation overlap) and revocation.</item>
/// <item>Authentication's <c>tenant_attempt</c>: <c>UNLOGGED</c> Tenant attempt counters, the
/// <c>admin_attempt</c> shape keyed by Tenant as well (AD-14). A crash empties it, which AD-14 accepts.</item>
/// <item>Story 2.6's deferral: <c>signin_transaction</c>, <c>authorization</c> and <c>token</c> reference
/// their Application, <c>ON DELETE RESTRICT</c>.</item>
/// </list>
/// Each table has the forced row-level security pair, the row guard, and only the grants its users need:
/// Host.Hosted reads Applications and secrets and counts attempts; Host.Admin creates Applications
/// (Epic 3 adds its API); Tenant deletion's purges, as <c>gk_worker</c>, delete every row.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261106000000_CreateDirectoryTables")]
public sealed class Migration20261106000000CreateDirectoryTables : Migration
{
    private static readonly string[] Tables = ["application", "client_secret", "tenant_attempt"];

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        var sql =
            """
            CREATE TABLE application (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              name text NOT NULL CONSTRAINT application_name CHECK (char_length(name) BETWEEN 1 AND 200),
              kind text NOT NULL CONSTRAINT application_kind CHECK (kind IN ('machine')),
              grant_types text[] NOT NULL DEFAULT '{}'
                CONSTRAINT application_grant_types
                CHECK (grant_types <@ ARRAY['client_credentials', 'authorization_code', 'refresh_token']::text[]),
              audiences text[] NOT NULL DEFAULT '{}',
              created_at timestamptz NOT NULL,
              PRIMARY KEY (tenant_id, id)
            );

            -- Only the SHA-256 of the whole {tenantPublicId}.{random} secret is stored (AD-24).
            CREATE TABLE client_secret (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              application_id uuid NOT NULL,
              secret_hash bytea NOT NULL CONSTRAINT client_secret_hash_length CHECK (octet_length(secret_hash) = 32),
              created_at timestamptz NOT NULL,
              expires_at timestamptz NULL,
              revoked_at timestamptz NULL,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, secret_hash),
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT
            );

            CREATE INDEX client_secret_application ON client_secret (tenant_id, application_id);

            -- The subject is a 32-byte SHA-256 only, and the policy a checked code, so no raw source
            -- address or credential can be stored.
            CREATE UNLOGGED TABLE tenant_attempt (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              policy text NOT NULL
                CONSTRAINT tenant_attempt_policy_code
                CHECK (policy ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$' AND char_length(policy) <= 128),
              subject_hash bytea NOT NULL
                CONSTRAINT tenant_attempt_subject_hash_length CHECK (octet_length(subject_hash) = 32),
              window_start timestamptz NOT NULL,
              attempts integer NOT NULL CHECK (attempts >= 1),
              PRIMARY KEY (tenant_id, policy, subject_hash)
            );

            -- Story 2.6's deferral: every Application reference is checked now. Validating the existing
            -- rows reads every Tenant's, which forced row-level security would refuse the owner, so it is
            -- lifted for the check only, inside this one transaction, and put back at once.
            ALTER TABLE signin_transaction NO FORCE ROW LEVEL SECURITY;
            ALTER TABLE "authorization" NO FORCE ROW LEVEL SECURITY;
            ALTER TABLE token NO FORCE ROW LEVEL SECURITY;

            ALTER TABLE signin_transaction ADD CONSTRAINT signin_transaction_application_fkey
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT;
            ALTER TABLE "authorization" ADD CONSTRAINT authorization_application_fkey
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT;
            ALTER TABLE token ADD CONSTRAINT token_application_fkey
              FOREIGN KEY (tenant_id, application_id) REFERENCES application (tenant_id, id) ON DELETE RESTRICT;

            ALTER TABLE signin_transaction FORCE ROW LEVEL SECURITY;
            ALTER TABLE "authorization" FORCE ROW LEVEL SECURITY;
            ALTER TABLE token FORCE ROW LEVEL SECURITY;

            -- So the RESTRICT check on an Application's delete or purge reads an index, not the table.
            -- "authorization" and token already have theirs (authorization_application, token_application,
            -- from ConstrainSessionEndReason).
            CREATE INDEX signin_transaction_application ON signin_transaction (tenant_id, application_id);


            """;

        foreach (var table in Tables)
        {
            sql += $"""
                ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
                ALTER TABLE {table} FORCE ROW LEVEL SECURITY;

                CREATE POLICY {table}_permissive ON {table}
                  AS PERMISSIVE FOR ALL
                  USING (true)
                  WITH CHECK (true);

                CREATE POLICY {table}_tenant ON {table}
                  AS RESTRICTIVE FOR ALL
                  USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
                  WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

                -- No row reaches a Tenant once its deletion has started (Story 1.29).
                CREATE TRIGGER tenant_row_guard BEFORE INSERT ON {table}
                  FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');


                """;
        }

        sql +=
            """
            -- Host.Hosted authenticates clients and counts token requests. Host.Admin creates Applications.
            GRANT SELECT ON application TO gk_hosted;
            GRANT SELECT ON client_secret TO gk_hosted;
            GRANT SELECT, INSERT ON application TO gk_admin;
            GRANT SELECT, INSERT ON client_secret TO gk_admin;
            GRANT SELECT, INSERT ON tenant_attempt TO gk_hosted;
            GRANT UPDATE (window_start, attempts) ON tenant_attempt TO gk_hosted;

            -- Tenant deletion's purges, in the Tenant's own scope: only the column each WHERE reads.
            GRANT SELECT (tenant_id), DELETE ON application TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON client_secret TO gk_worker;
            GRANT SELECT (tenant_id), DELETE ON tenant_attempt TO gk_worker;
            """;

        migrationBuilder.Sql(sql);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
