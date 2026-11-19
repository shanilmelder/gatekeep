using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.7 (FR-17, FR-18, NFR-2): sign-up and email verification.
/// <list type="bullet">
/// <item><c>"user"</c> gains <c>email_verified_at</c>. <c>gk_hosted</c> inserts a User (its ID, email and creation time
/// only) and sets when its email was verified, and nothing else of it.</item>
/// <item>Identity's <c>password_credential</c>: a User's Argon2id password hash as a PHC string, <c>pending</c> until a
/// verification link activates it, then <c>active</c>; at most one <c>active</c> per User
/// (<c>password_credential_one_active</c>). It names the database Connection it was made under with no reference:
/// Directory is purged before Identity.</item>
/// <item>Identity's <c>one_time_token</c>: an email verification link's SHA-256 only, unique per Tenant, for the pending
/// credential it activates (deleted with it), with its expiry and when it was used. A link works once.</item>
/// <item><c>signin_transaction</c> gains <c>signup_user_id</c>, the User a sign-up in it registered, and
/// <c>signup_credential_id</c>, the pending credential it made, which has no reference: a credential another link's
/// verification deleted leaves the transaction naming none, so it can never sign in.</item>
/// <item><c>gk_hosted</c> reads, inserts and deletes credentials and tokens, and updates only a credential's status, hash and
/// <c>updated_at</c>, and a token's <c>used_at</c>. <c>gk_worker</c> reads only what its purges' WHEREs name and deletes
/// them: a Tenant's purge, and the expired-state purge of tokens an hour past their expiry, then of pending credentials
/// with no link left and unverified Users with no credential and no transaction naming them.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261128000000_SignUp")]
public sealed class Migration20261128000000SignUp : Migration
{
    private static readonly string[] Tables = ["password_credential", "one_time_token"];

    protected override void Up(MigrationBuilder migrationBuilder)
    {
        var sql =
            """
            ALTER TABLE "user" ADD COLUMN email_verified_at timestamptz NULL;

            -- No reference to connection: Directory's purge runs before Identity's.
            CREATE TABLE password_credential (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              user_id uuid NOT NULL,
              connection_id uuid NOT NULL,
              password_hash text NOT NULL CONSTRAINT password_credential_hash CHECK (char_length(password_hash) BETWEEN 1 AND 512),
              status text NOT NULL CONSTRAINT password_credential_status CHECK (status IN ('pending', 'active')),
              created_at timestamptz NOT NULL DEFAULT now(),
              updated_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, id),
              FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE RESTRICT
            );

            -- One active password per User.
            CREATE UNIQUE INDEX password_credential_one_active ON password_credential (tenant_id, user_id) WHERE status = 'active';
            CREATE INDEX password_credential_user ON password_credential (tenant_id, user_id);

            -- Story 4.11 adds the reset purpose.
            CREATE TABLE one_time_token (
              tenant_id uuid NOT NULL REFERENCES tenant (id) ON DELETE RESTRICT,
              id uuid NOT NULL,
              user_id uuid NOT NULL,
              credential_id uuid NOT NULL,
              purpose text NOT NULL CONSTRAINT one_time_token_purpose CHECK (purpose IN ('email_verification')),
              token_hash bytea NOT NULL CONSTRAINT one_time_token_hash CHECK (octet_length(token_hash) = 32),
              application_id uuid NULL,
              expires_at timestamptz NOT NULL,
              used_at timestamptz NULL,
              created_at timestamptz NOT NULL DEFAULT now(),
              PRIMARY KEY (tenant_id, id),
              FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE RESTRICT,
              FOREIGN KEY (tenant_id, credential_id) REFERENCES password_credential (tenant_id, id) ON DELETE CASCADE
            );

            CREATE UNIQUE INDEX one_time_token_hash_unique ON one_time_token (tenant_id, token_hash);
            CREATE INDEX one_time_token_credential ON one_time_token (tenant_id, credential_id);
            CREATE INDEX one_time_token_user ON one_time_token (tenant_id, user_id);
            CREATE INDEX one_time_token_expiry ON one_time_token (tenant_id, expires_at);

            -- Validating the new reference reads every Tenant's rows, which forced row-level security would refuse the
            -- owner, so it is lifted for the check only, inside this one transaction, and put back at once.
            ALTER TABLE signin_transaction NO FORCE ROW LEVEL SECURITY;
            ALTER TABLE "user" NO FORCE ROW LEVEL SECURITY;

            ALTER TABLE signin_transaction
              ADD COLUMN signup_user_id uuid NULL,
              ADD COLUMN signup_credential_id uuid NULL,
              ADD CONSTRAINT signin_transaction_signup_user_fkey
                FOREIGN KEY (tenant_id, signup_user_id) REFERENCES "user" (tenant_id, id) ON DELETE RESTRICT;

            ALTER TABLE signin_transaction FORCE ROW LEVEL SECURITY;
            ALTER TABLE "user" FORCE ROW LEVEL SECURITY;

            CREATE INDEX signin_transaction_signup_user ON signin_transaction (tenant_id, signup_user_id) WHERE signup_user_id IS NOT NULL;


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
            -- Host.Hosted: a sign-up creates its User, and a verification link marks the email verified.
            GRANT INSERT (tenant_id, id, email, created_at) ON "user" TO gk_hosted;
            GRANT UPDATE (email_verified_at) ON "user" TO gk_hosted;

            -- Host.Hosted keeps a User's password credentials and links; Host.Worker purges them, reading only the columns
            -- its WHEREs name, never a hash.
            GRANT SELECT, INSERT, DELETE ON password_credential TO gk_hosted;
            GRANT UPDATE (status, password_hash, updated_at) ON password_credential TO gk_hosted;
            GRANT SELECT (tenant_id, id, user_id, status), DELETE ON password_credential TO gk_worker;

            GRANT SELECT, INSERT, DELETE ON one_time_token TO gk_hosted;
            GRANT UPDATE (used_at) ON one_time_token TO gk_hosted;
            GRANT SELECT (tenant_id, credential_id, expires_at), DELETE ON one_time_token TO gk_worker;

            -- Host.Worker's expired-state purge also removes an abandoned sign-up: a pending credential with no link left,
            -- then an unverified User with no credential and no sign-in transaction naming it. It reads no hash or email value.
            GRANT SELECT (email_verified_at) ON "user" TO gk_worker;
            GRANT SELECT (signup_user_id) ON signin_transaction TO gk_worker;
            """;

        migrationBuilder.Sql(sql);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
