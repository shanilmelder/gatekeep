using System.Text;
using Gatekeep.Modules.Operations.Contracts;

namespace Gatekeep.Modules.Operations.Core;

/// <summary>
/// Renders <c>job_guard_insert()</c> from a registry (AD-15). It quotes nothing it didn't
/// validate: type codes come from <see cref="Gatekeep.Kernel.Jobs.JobType"/> and role names
/// from <see cref="JobRole"/>, so neither can hold a quote.
/// </summary>
internal static class JobGuardRenderer
{
    private const string Head =
        """
        CREATE OR REPLACE FUNCTION job_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          -- The CHECK constraint refuses neither or both, so such a row isn't judged here.
          IF (NEW.tenant_id IS NULL) IS DISTINCT FROM NEW.deployment_wide THEN
            RETURN NEW;
          END IF;

          -- An unset Tenant raises, as the row-level security policies do.
          IF NEW.tenant_id IS NOT NULL AND NEW.tenant_id <> current_setting('gatekeep.tenant_id')::uuid THEN
            RAISE EXCEPTION 'a job can''t be enqueued for another Tenant';
          END IF;

          IF NEW.deployment_wide AND coalesce(current_setting('gatekeep.tenant_id', true), '') <> '' THEN
            RAISE EXCEPTION 'a Deployment-wide job can''t be enqueued in a Tenant scope';
          END IF;

          CASE NEW.type

        """;

    private const string Tail =
        """
            ELSE
              RAISE EXCEPTION 'job type % isn''t in the registry', NEW.type;
          END CASE;

          -- A job always starts unclaimed, whatever the enqueuer sent.
          NEW.status := 'pending';
          NEW.attempts := 0;
          NEW.locked_until := NULL;
          NEW.failure_code := NULL;
          NEW.finished_at := NULL;
          NEW.created_at := now();
          NEW.run_after := coalesce(NEW.run_after, now());

          RETURN NEW;
        END
        $$;
        """;

    public static string Render(JobRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        var sql = new StringBuilder(Head.ReplaceLineEndings("\n"));

        foreach (var definition in registry.Definitions.OrderBy(d => d.Type.Value, StringComparer.Ordinal))
        {
            var wrongScope = definition.Scope == JobScope.Tenant
                ? "NEW.deployment_wide"
                : "NOT NEW.deployment_wide";
            var scopeName = definition.Scope == JobScope.Tenant ? "for one Tenant" : "Deployment-wide";
            var roles = string.Join(", ", definition.EnqueuingRoles.Order(StringComparer.Ordinal).Select(r => $"'{r}'"));

            sql.Append(
                $"""
                    WHEN '{definition.Type.Value}' THEN
                      IF {wrongScope} THEN
                        RAISE EXCEPTION 'job type % is {scopeName}', NEW.type;
                      END IF;
                      IF NOT (current_user::text = ANY (ARRAY[{roles}])) THEN
                        RAISE EXCEPTION 'job type % can''t be enqueued by %', NEW.type, current_user;
                      END IF;

                """.ReplaceLineEndings("\n"));
        }

        sql.Append(Tail.ReplaceLineEndings("\n"));
        return sql.ToString();
    }
}
