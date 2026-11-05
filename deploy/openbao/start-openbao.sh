#!/bin/sh
# The openbao service's entrypoint (deploy/docker/openbao.Dockerfile). Renders the server
# config from /etc/openbao/openbao.hcl onto the /tmp tmpfs, then runs OpenBao on it.
#
# The rendered config holds only file:// references and key IDs, never key bytes. The key
# ID comes from master/master-key-id, which keygen and master-key-rotate write next to the
# Master Key, delivered as the Compose secret master_key_id. OpenBao refuses to start when
# it's missing or isn't gatekeep-master-<N>.
#
# Rotation mode (Story 12.7, docs/runbooks/master-key-rotation.md): only when
# deploy/compose.rotate.yaml adds both master_key_previous and master_key_previous_id does
# the seal also get the previous generation, so OpenBao unseals with it and re-wraps its
# root key under the new one, and only then does the socket listener allow the
# unauthenticated generate-root endpoints the root-key step needs. Base mode never does.
#
# Any further arguments go to bao server (the isolation tests add a test listener).
set -eu

TEMPLATE="${GATEKEEP_OPENBAO_TEMPLATE:-/etc/openbao/openbao.hcl}"
CONFIG="${GATEKEEP_OPENBAO_CONFIG:-/tmp/openbao.hcl}"
KEY_ID_FILE=/run/secrets/master_key_id
PREVIOUS_KEY_FILE=/run/secrets/master_key_previous
PREVIOUS_ID_FILE=/run/secrets/master_key_previous_id
PREVIOUS_KEY_URL="file://$PREVIOUS_KEY_FILE"

refuse() {
    echo "start-openbao: refusing to start: $*" >&2
    exit 1
}

# Prints N for a file holding exactly gatekeep-master-<N>: N from 1, no leading zero. Never
# prints what a malformed file holds, since a key could have been written there by mistake.
generation_of() {
    [ -f "$1" ] || refuse "$1 is missing or isn't a file. It must hold the Master Key's ID, gatekeep-master-<N> (docs/key-custody.md)."
    id="$(cat "$1")" || refuse "can't read $1."
    number="${id#gatekeep-master-}"
    case "$number" in
        "$id" | "" | 0* | *[!0-9]*) refuse "$1 doesn't hold a key ID of the form gatekeep-master-<N>, N from 1 with no leading zero." ;;
    esac
    [ "${#number}" -le 9 ] || refuse "$1 holds a generation number that's too long."
    echo "$number"
}

[ -f "$TEMPLATE" ] || refuse "no config template at $TEMPLATE."

current="$(generation_of "$KEY_ID_FILE")" || exit 1
previous=""
if [ -e "$PREVIOUS_KEY_FILE" ] || [ -e "$PREVIOUS_ID_FILE" ]; then
    # Compose makes an empty directory for a secret file that's missing, so a half-present
    # pair is refused rather than half-applied.
    [ -f "$PREVIOUS_KEY_FILE" ] || refuse "rotation mode needs $PREVIOUS_KEY_FILE as a file: run master-key-rotate prepare first."
    previous="$(generation_of "$PREVIOUS_ID_FILE")" || exit 1
    [ "$current" -eq $((previous + 1)) ] \
        || refuse "in rotation mode the current generation ($current) must be one above the previous ($previous)."
fi

umask 0077
rm -f "$CONFIG"
awk -v current="gatekeep-master-$current" \
    -v previous="${previous:+gatekeep-master-$previous}" \
    -v previous_url="$PREVIOUS_KEY_URL" '
    /^listener "unix"/ { unix = 1 }
    /^}/ { unix = 0 }
    { gsub(/@MASTER_KEY_ID@/, current) }
    previous != "" && unix && /^[ \t]*disable_unauthed_generate_root_endpoints[ \t]*=[ \t]*true[ \t]*$/ {
        sub(/true/, "false")
    }
    { print }
    previous != "" && /^[ \t]*current_key[ \t]*=/ {
        print "  previous_key_id = \"" previous "\""
        print "  previous_key    = \"" previous_url "\""
    }
' "$TEMPLATE" > "$CONFIG"

# The rendering is checked, not trusted: one key ID, and unauthenticated generate-root on the
# socket in rotation mode only.
grep -q "@MASTER_KEY_ID@" "$CONFIG" && refuse "the rendered config still holds a placeholder."
[ "$(grep -c "current_key_id = \"gatekeep-master-$current\"" "$CONFIG")" -eq 1 ] \
    || refuse "the template must hold current_key_id = \"@MASTER_KEY_ID@\" exactly once."
opened="$(grep -c "^[[:space:]]*disable_unauthed_generate_root_endpoints[[:space:]]*=[[:space:]]*false" "$CONFIG" || true)"
if [ -n "$previous" ]; then
    [ "$opened" -eq 1 ] || refuse "the template's socket listener must set disable_unauthed_generate_root_endpoints = true."
    echo "start-openbao: rotation mode: generation $current current, generation $previous previous."
else
    [ "$opened" -eq 0 ] || refuse "the template enables unauthenticated generate-root."
    echo "start-openbao: generation $current."
fi

exec bao server -config="$CONFIG" "$@"
