using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// The Identity <c>user</c>, the Sessions <c>user_session</c>, <c>authorization</c> and
/// <c>token</c>, and the Authentication <c>signin_transaction</c> (AD-12, AD-13). The
/// <c>application_id</c> columns have no foreign key yet: the <c>application</c> table is
/// Story 2.5's, and its migration adds them.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261102090000_CreateSessionTables")]
public sealed class Migration20261102090000CreateSessionTables : Migration
{
    private static readonly string[] Tables =
        ["\"user\"", "user_session", "\"authorization\"", "token", "signin_transaction"];

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        var sql =
            """
            -- Minimal: later stories add the profile columns.
            CREATE TABLE "user" (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              created_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, id)
            );

            -- Only the SHA-256 of the 256-bit Session identifier is stored, never the value.
            CREATE TABLE user_session (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              user_id uuid NOT NULL,
              id_hash bytea NOT NULL CHECK (octet_length(id_hash) = 32),
              amr text[] NOT NULL CHECK (cardinality(amr) > 0),
              auth_time timestamptz NOT NULL,
              -- No foreign key: Connections arrive later.
              connection_id uuid NULL,
              idle_expires_at timestamptz NOT NULL,
              absolute_expires_at timestamptz NOT NULL,
              created_at timestamptz NOT NULL,
              ended_at timestamptz NULL,
              end_reason text NULL,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, id_hash),
              FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE RESTRICT,
              CHECK (idle_expires_at <= absolute_expires_at),
              CHECK ((ended_at IS NULL) = (end_reason IS NULL))
            );

            CREATE INDEX user_session_user ON user_session (tenant_id, user_id);

            -- OpenIddict's authorization entity. An ad-hoc one is a Token Family, anchored to one Session (AD-13).
            CREATE TABLE "authorization" (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              application_id uuid NULL,
              user_session_id uuid NOT NULL,
              subject text NULL,
              status text NOT NULL,
              type text NOT NULL,
              scopes text[] NOT NULL DEFAULT '{}',
              creation_date timestamptz NULL,
              properties jsonb NOT NULL DEFAULT '{}',
              concurrency_token uuid NOT NULL,
              PRIMARY KEY (tenant_id, id),
              FOREIGN KEY (tenant_id, user_session_id) REFERENCES user_session (tenant_id, id) ON DELETE RESTRICT
            );

            CREATE INDEX authorization_user_session ON "authorization" (tenant_id, user_session_id);

            -- OpenIddict's token entity. reference_id holds only OpenIddict's obfuscated form, a
            -- base64 SHA-256: a raw {tenantPublicId}.{random} value has a dot and is refused.
            CREATE TABLE token (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              application_id uuid NULL,
              authorization_id uuid NULL,
              subject text NULL,
              type text NOT NULL,
              status text NOT NULL,
              reference_id text NULL CHECK (reference_id ~ '^[A-Za-z0-9+/_-]{43}=?$'),
              payload text NULL,
              creation_date timestamptz NULL,
              expiration_date timestamptz NULL,
              redemption_date timestamptz NULL,
              properties jsonb NOT NULL DEFAULT '{}',
              concurrency_token uuid NOT NULL,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, reference_id),
              FOREIGN KEY (tenant_id, authorization_id) REFERENCES "authorization" (tenant_id, id) ON DELETE RESTRICT
            );

            CREATE INDEX token_authorization ON token (tenant_id, authorization_id);

            -- A sign-in in progress (AD-12). Only the SHA-256 of the __Host-gk_txn value is stored.
            CREATE TABLE signin_transaction (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              application_id uuid NOT NULL,
              binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
              parameters jsonb NOT NULL,
              completed_steps text[] NOT NULL DEFAULT '{}',
              created_at timestamptz NOT NULL,
              expires_at timestamptz NOT NULL,
              PRIMARY KEY (tenant_id, id),
              UNIQUE (tenant_id, binding_hash),
              CHECK (expires_at > created_at)
            );

            """;

        foreach (var table in Tables)
        {
            var policy = table.Trim('"');

            sql += $"""
                ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
                ALTER TABLE {table} FORCE ROW LEVEL SECURITY;

                CREATE POLICY {policy}_permissive ON {table}
                  AS PERMISSIVE FOR ALL
                  USING (true)
                  WITH CHECK (true);

                CREATE POLICY {policy}_tenant ON {table}
                  AS RESTRICTIVE FOR ALL
                  USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
                  WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);


                """;
        }

        sql +=
            """
            -- The Hosted request path: reads Users, and writes Sessions, transactions and
            -- OpenIddict's entities. Nothing deletes: pruning is a later job, not OpenIddict's.
            GRANT SELECT ON "user" TO gk_hosted;
            GRANT SELECT, INSERT, UPDATE ON user_session TO gk_hosted;
            GRANT SELECT, INSERT, UPDATE ON "authorization" TO gk_hosted;
            GRANT SELECT, INSERT, UPDATE ON token TO gk_hosted;
            GRANT SELECT, INSERT, UPDATE ON signin_transaction TO gk_hosted;
            """;

        migrationBuilder.Sql(sql);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
