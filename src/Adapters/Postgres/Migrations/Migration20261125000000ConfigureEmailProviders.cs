using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.4 (FR-36, FR-46, AD-10): each Tenant's email provider.
/// <list type="bullet">
/// <item>Notifications' <c>email_provider</c>: one row per Tenant with its provider kind, the kind's non-secret settings as
/// a JSON object, the From address and name, and the provider's one secret as Transit ciphertext under the Tenant's
/// <c>email-</c> key, with the Tenant ID as associated data. An SMTP provider with no username has no secret, and every
/// other has one.</item>
/// <item><c>gk_admin</c> inserts, updates and deletes it, and reads every column but <c>secret_ciphertext</c>: it encrypts
/// under the email key and may never read or decrypt what it stored.</item>
/// <item><c>gk_worker</c> reads it, to send (Story 4.5), and deletes it in a Tenant's purge. <c>gk_hosted</c> has nothing.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261125000000_ConfigureEmailProviders")]
public sealed class Migration20261125000000ConfigureEmailProviders : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.Sql(
            """
            CREATE TABLE email_provider (
              tenant_id uuid PRIMARY KEY REFERENCES tenant (id) ON DELETE RESTRICT,
              kind text NOT NULL CONSTRAINT email_provider_kind
                CHECK (kind IN ('smtp', 'sendgrid', 'postmark', 'mailgun', 'ses', 'custom_http')),
              settings jsonb NOT NULL CONSTRAINT email_provider_settings
                CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 8192),
              from_address text NOT NULL CONSTRAINT email_provider_from_address
                CHECK (char_length(from_address) BETWEEN 3 AND 254),
              from_name text CONSTRAINT email_provider_from_name
                CHECK (char_length(from_name) BETWEEN 1 AND 128),
              -- Transit's own ciphertext form, so a plaintext secret can't be stored here by mistake.
              secret_ciphertext text CONSTRAINT email_provider_secret_ciphertext
                CHECK (secret_ciphertext ~ '^vault:v[0-9]+:[A-Za-z0-9+/=]+$' AND char_length(secret_ciphertext) <= 24576),
              updated_at timestamptz NOT NULL DEFAULT now(),
              -- Only SMTP with no username sends with no secret, so whether one is stored follows from what gk_admin reads.
              CONSTRAINT email_provider_secret_present
                CHECK ((secret_ciphertext IS NOT NULL) = (kind <> 'smtp' OR settings -> 'username' IS NOT NULL))
            );

            ALTER TABLE email_provider ENABLE ROW LEVEL SECURITY;
            ALTER TABLE email_provider FORCE ROW LEVEL SECURITY;

            CREATE POLICY email_provider_permissive ON email_provider
              AS PERMISSIVE FOR ALL
              USING (true)
              WITH CHECK (true);

            CREATE POLICY email_provider_tenant ON email_provider
              AS RESTRICTIVE FOR ALL
              USING (tenant_id = current_setting('gatekeep.tenant_id')::uuid)
              WITH CHECK (tenant_id = current_setting('gatekeep.tenant_id')::uuid);

            -- No row reaches a Tenant once its deletion has started (Story 1.29).
            CREATE TRIGGER tenant_row_guard BEFORE INSERT ON email_provider
              FOR EACH ROW EXECUTE FUNCTION tenant_row_guard('creating', 'active');

            -- Host.Admin: the Tenant Owner's save and removal, and every column but the ciphertext.
            GRANT INSERT, UPDATE, DELETE ON email_provider TO gk_admin;
            GRANT SELECT (tenant_id, kind, settings, from_address, from_name, updated_at) ON email_provider TO gk_admin;

            -- Host.Worker: sending (Story 4.5), and a Tenant's purge.
            GRANT SELECT, DELETE ON email_provider TO gk_worker;
            """);
    }

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
