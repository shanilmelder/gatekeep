#!/bin/sh
# Sets each login role's password from its Compose secret, so no password is in roles.sql,
# compose.yaml or an environment variable. Two callers:
#
#   - the postgres image's entrypoint, on the first start, after 10-roles.sql, against its
#     temporary init server on the unix socket (sourced or executed, either works);
#   - the postgres-passwords service, on every `up`, over the tools network as the
#     superuser, so a password file changed or restored later is applied before any host
#     starts and can't drift from the database.
#
# The password is read by psql itself (\set with backticks), so it never appears in a
# process's arguments, and statement logging is off by default. gk_cli has one since
# `gatekeep audit verify` logs in as it (Story 7.3). Any failure
# exits non-zero, which stops the init or the hosts.

roles="gk_migrator gk_hosted gk_admin gk_worker gk_dispatch gk_sealer gk_retention gk_cli"

# Over the network, the superuser's password goes in a pgpass file on the tmpfs, never in
# the environment or an argument.
if [ -n "${GATEKEEP_SUPERUSER_PASSWORD_FILE:-}" ]; then
    if [ ! -s "$GATEKEEP_SUPERUSER_PASSWORD_FILE" ]; then
        echo "role-passwords: no superuser password secret." >&2
        exit 1
    fi
    PGPASSFILE=/tmp/gatekeep.pgpass
    ( umask 0077 && printf '*:*:*:*:%s\n' "$(sed 's/[\:]/\&/g' "$GATEKEEP_SUPERUSER_PASSWORD_FILE")" > "$PGPASSFILE" )
    export PGPASSFILE
fi

for role in $roles; do
    file="/run/secrets/${role}_password"
    if [ ! -s "$file" ]; then
        echo "role-passwords: no password secret for $role." >&2
        exit 1
    fi

    if ! psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
        --username "${POSTGRES_USER:-${PGUSER:-postgres}}" --dbname "${POSTGRES_DB:-${PGDATABASE:-gatekeep}}" <<SQL
\set pw \`cat $file\`
ALTER ROLE $role PASSWORD :'pw';
SQL
    then
        echo "role-passwords: couldn't set the password for $role." >&2
        exit 1
    fi
done

if [ -n "${PGPASSFILE:-}" ]; then
    rm -f "$PGPASSFILE"
fi

echo "role-passwords: set the password of every login role."
