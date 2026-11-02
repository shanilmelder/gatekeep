#!/bin/sh
# First setup of a fresh OpenBao for Gatekeep (AD-10). Run once, as root, on the host,
# after openbao.service has started. docs/key-custody.md has the whole procedure.
#
# It initializes OpenBao with recovery shares written only to a root-only escrow file,
# enables Transit, writes one policy per host, creates one AppRole per host with
# short-lived tokens, writes each role's ID and secret ID to root-only files, creates
# the Deployment keys, and revokes the root token. It never prints a key, token or ID.
#
# Settings, all optional:
#   BAO_ADDR                   default unix:///run/openbao/openbao.sock
#   GATEKEEP_ESCROW_FILE       default /root/openbao-init.json   (move it offline, then destroy it)
#   GATEKEEP_APPROLE_DIR       default /etc/gatekeep/openbao     ({role}/role-id and {role}/secret-id)
#   GATEKEEP_POLICY_DIR        default the policies/ directory next to this script
#   GATEKEEP_RECOVERY_SHARES   default 5
#   GATEKEEP_RECOVERY_THRESHOLD default 3
#   GATEKEEP_TOKEN_TTL         default 15m
#   GATEKEEP_TOKEN_MAX_TTL     default 1h
set -eu
umask 0077

export BAO_ADDR="${BAO_ADDR:-unix:///run/openbao/openbao.sock}"
ESCROW_FILE="${GATEKEEP_ESCROW_FILE:-/root/openbao-init.json}"
APPROLE_DIR="${GATEKEEP_APPROLE_DIR:-/etc/gatekeep/openbao}"
POLICY_DIR="${GATEKEEP_POLICY_DIR:-$(cd "$(dirname "$0")" && pwd)/policies}"
RECOVERY_SHARES="${GATEKEEP_RECOVERY_SHARES:-5}"
RECOVERY_THRESHOLD="${GATEKEEP_RECOVERY_THRESHOLD:-3}"
TOKEN_TTL="${GATEKEEP_TOKEN_TTL:-15m}"
TOKEN_MAX_TTL="${GATEKEEP_TOKEN_MAX_TTL:-1h}"

ROLES="host-hosted host-admin host-worker cli"

say() { echo "setup: $*"; }
fail() { echo "setup: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root."
command -v bao > /dev/null || fail "bao isn't on PATH."
for role in $ROLES; do
    [ -f "$POLICY_DIR/$role.hcl" ] || fail "no policy $POLICY_DIR/$role.hcl."
done
[ ! -e "$ESCROW_FILE" ] || fail "$ESCROW_FILE already exists. Setup runs once, on a fresh server."

# Status exits 2 while sealed, which is expected before init.
STATUS="$(bao status -format=json 2> /dev/null || true)"
case "$STATUS" in
    *'"initialized": false'*) ;;
    *'"initialized": true'*) fail "OpenBao is already initialized." ;;
    *) fail "OpenBao isn't answering at $BAO_ADDR." ;;
esac

say "initializing; recovery shares go to $ESCROW_FILE only."
bao operator init \
    -recovery-shares="$RECOVERY_SHARES" \
    -recovery-threshold="$RECOVERY_THRESHOLD" \
    -format=json > "$ESCROW_FILE"
chmod 0400 "$ESCROW_FILE"

BAO_TOKEN="$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$ESCROW_FILE")"
[ -n "$BAO_TOKEN" ] || fail "init wrote no root token to $ESCROW_FILE."
export BAO_TOKEN

# From here on, any failure leaves a root token alive, so revoke it on the way out.
revoke_root() {
    if [ -n "${BAO_TOKEN:-}" ]; then
        bao token revoke -self > /dev/null 2>&1 || echo "setup: couldn't revoke the root token. Revoke it by hand." >&2
        unset BAO_TOKEN
    fi
}
trap revoke_root EXIT
# sh doesn't run the EXIT trap on a signal, so an interrupt revokes and exits itself.
trap 'revoke_root; exit 1' INT TERM HUP

# The static seal unseals on its own once initialized.
tries=0
until bao status > /dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || fail "OpenBao didn't unseal after init."
    sleep 1
done

# The audit device is declared in openbao.hcl. Without one, no request is recorded.
bao audit list -format=json 2> /dev/null | grep -q '"type"' || fail "no audit device is enabled. openbao.hcl must declare one."

say "enabling Transit and AppRole."
bao secrets enable -path=transit transit > /dev/null
bao auth enable -path=approle approle > /dev/null

for role in $ROLES; do
    say "writing policy and AppRole $role."
    bao policy write "$role" "$POLICY_DIR/$role.hcl" > /dev/null

    # Re-login on expiry instead of renewing, so the default policy isn't needed.
    bao write "auth/approle/role/$role" \
        token_policies="$role" \
        token_no_default_policy=true \
        token_type=service \
        token_ttl="$TOKEN_TTL" \
        token_max_ttl="$TOKEN_MAX_TTL" \
        secret_id_ttl=0 \
        secret_id_num_uses=0 > /dev/null

    mkdir -p "$APPROLE_DIR/$role"
    chmod 0700 "$APPROLE_DIR" "$APPROLE_DIR/$role"
    bao read -field=role_id "auth/approle/role/$role/role-id" > "$APPROLE_DIR/$role/role-id"
    bao write -f -field=secret_id "auth/approle/role/$role/secret-id" > "$APPROLE_DIR/$role/secret-id"
    chmod 0400 "$APPROLE_DIR/$role/role-id" "$APPROLE_DIR/$role/secret-id"
done

say "creating Deployment keys."
bao write transit/keys/dep-email type=aes256-gcm96 > /dev/null
bao write transit/keys/dep-payload type=aes256-gcm96 > /dev/null
bao write transit/keys/dep-hmac type=hmac key_size=32 > /dev/null
bao write transit/keys/dep-records type=rsa-3072 > /dev/null

say "revoking the root token."
bao token revoke -self > /dev/null
unset BAO_TOKEN
trap - EXIT INT TERM HUP

say "done. Move $ESCROW_FILE offline now, then destroy it: see docs/key-custody.md."
