using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Story 4.8 (FR-17): a sign-up's terms acceptance.
/// <list type="bullet">
/// <item><c>"user"</c> gains <c>terms_accepted_url</c>, the Tenant's terms URL exactly as the User accepted it (the terms
/// version), 1 to 2048 characters, and <c>terms_accepted_at</c>, when: both set, or neither
/// (<c>user_terms_accepted_together</c>). Both stay NULL where the Tenant set no terms URL.</item>
/// <item><c>gk_hosted</c> inserts both with a new User, and updates both when an unverified User signs up again, and
/// nothing else of them.</item>
/// </list>
/// It changes no earlier migration.
/// </summary>
[DbContext(typeof(MigrationsContext))]
[Migration("20261129000000_SignUpTerms")]
public sealed class Migration20261129000000SignUpTerms : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql(
            """
            ALTER TABLE "user"
              ADD COLUMN terms_accepted_url text NULL
                CONSTRAINT user_terms_accepted_url CHECK (char_length(terms_accepted_url) BETWEEN 1 AND 2048),
              ADD COLUMN terms_accepted_at timestamptz NULL,
              -- An acceptance is the URL and its time together, or neither.
              ADD CONSTRAINT user_terms_accepted_together CHECK ((terms_accepted_url IS NULL) = (terms_accepted_at IS NULL));

            -- Host.Hosted: a sign-up records the terms its User accepted, on the new User or on an unverified one's re-sign-up.
            GRANT INSERT (terms_accepted_url, terms_accepted_at) ON "user" TO gk_hosted;
            GRANT UPDATE (terms_accepted_url, terms_accepted_at) ON "user" TO gk_hosted;
            """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        throw new NotSupportedException("Migrations are forward-only.");
}
