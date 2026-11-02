#!/bin/sh
# The caddy service's entrypoint: checks every setting the Caddyfile reads, then runs Caddy.
# A refusal names the setting and exits 2, so Compose shows Caddy restarting. The settings
# are substituted into the Caddyfile as text, so each is held to a strict shape first:
# nothing in it can be read by Caddy as a placeholder, a brace or another line.
#
# The Admin hostname must not be the Tenant zone or under it, nor the zone under the Admin
# hostname: no Tenant host may ever route to Host.Admin. In cloudflare mode the challenge
# domains must lie outside both sites and differ from each other (NFR-21).
set -eu

refuse() {
    echo "caddy: refusing to start: $1" >&2
    exit 2
}

# A lowercase DNS name: only a-z, 0-9, '.' and '-' (so no newline, brace or space), at most
# 253 characters, two labels or more of 1 to 63 characters that don't start or end with
# '-', and a last label that isn't all digits, so no IP address.
check_name() {
    setting="$1" value="$2"
    [ -n "$value" ] || refuse "$setting is not set."
    case "$value" in *[!a-z0-9.-]*) refuse "$setting holds a character other than a-z, 0-9, '.' and '-'." ;; esac
    [ "${#value}" -le 253 ] || refuse "$setting is longer than 253 characters."
    case "$value" in .* | *. | *..*) refuse "$setting has an empty label." ;; esac
    case "$value" in *.*) ;; *) refuse "$setting needs at least two labels." ;; esac
    labels="$(echo "$value" | tr '.' ' ')"
    for label in $labels; do
        [ "${#label}" -le 63 ] || refuse "$setting has a label longer than 63 characters."
        case "$label" in -* | *-) refuse "$setting has a label starting or ending with '-'." ;; esac
        last="$label"
    done
    case "$last" in *[!0-9]*) ;; *) refuse "$setting ends in an all-digit label, like an IP address." ;; esac
}

# True when $1 is $2 or a name under it.
at_or_under() {
    case "$1" in "$2" | *".$2") return 0 ;; esac
    return 1
}

zone="${GATEKEEP_TENANT_ZONE:-}"
admin="${GATEKEEP_ADMIN_HOST:-}"
check_name GATEKEEP_TENANT_ZONE "$zone"
check_name GATEKEEP_ADMIN_HOST "$admin"
at_or_under "$admin" "$zone" && refuse "GATEKEEP_ADMIN_HOST is under GATEKEEP_TENANT_ZONE; it must be outside the Tenant zone."
at_or_under "$zone" "$admin" && refuse "GATEKEEP_TENANT_ZONE is under GATEKEEP_ADMIN_HOST; they must be separate names."

case "${GATEKEEP_TLS_MODE:-}" in
    internal) ;;
    cloudflare)
        email="${GATEKEEP_ACME_EMAIL:-}"
        [ -n "$email" ] || refuse "GATEKEEP_ACME_EMAIL is not set."
        [ "${#email}" -le 254 ] || refuse "GATEKEEP_ACME_EMAIL is longer than 254 characters."
        local_part="${email%@*}" domain="${email#*@}"
        case "$email" in *@*@* | @* | *@) refuse "GATEKEEP_ACME_EMAIL is not an address." ;; *@*) ;; *) refuse "GATEKEEP_ACME_EMAIL is not an address." ;; esac
        case "$local_part" in *[!A-Za-z0-9._+-]*) refuse "GATEKEEP_ACME_EMAIL holds a character other than A-Z, a-z, 0-9, '.', '_', '+' and '-' before '@'." ;; esac
        [ "${#local_part}" -le 64 ] || refuse "GATEKEEP_ACME_EMAIL is longer than 64 characters before '@'."
        check_name GATEKEEP_ACME_EMAIL "$domain"

        zone_challenge="${GATEKEEP_ACME_CHALLENGE_DOMAIN:-}"
        admin_challenge="${GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN:-}"
        check_name GATEKEEP_ACME_CHALLENGE_DOMAIN "$zone_challenge"
        check_name GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN "$admin_challenge"
        for setting in GATEKEEP_ACME_CHALLENGE_DOMAIN GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN; do
            eval "value=\$$setting"
            at_or_under "$value" "$zone" && refuse "$setting is under GATEKEEP_TENANT_ZONE; it must be in the validation-only zone."
            at_or_under "$value" "$admin" && refuse "$setting is under GATEKEEP_ADMIN_HOST; it must be in the validation-only zone."
        done
        [ "$zone_challenge" != "$admin_challenge" ] \
            || refuse "GATEKEEP_ACME_CHALLENGE_DOMAIN and GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN are the same; each site needs its own."

        token=/run/secrets/cloudflare_dns_token
        [ -r "$token" ] || refuse "the cloudflare_dns_token secret is missing or unreadable."
        grep -q '[^[:space:]]' "$token" || refuse "the cloudflare_dns_token secret is empty."
        ;;
    *) refuse "GATEKEEP_TLS_MODE must be internal or cloudflare." ;;
esac

# "run" by default; "validate" or "adapt" to check the configuration without serving.
[ "$#" -gt 0 ] || set -- run
exec caddy "$@" --config /etc/caddy/Caddyfile --adapter caddyfile
