#!/bin/sh
# The two Master Key rotation steps that touch master/ (Story 12.7), run by the
# master-key-rotate service of deploy/compose.rotate.yaml with no network, mounting only
# master/ and OpenBao's socket. docs/runbooks/master-key-rotation.md has the whole rotation:
#
#   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm master-key-rotate prepare
#   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm master-key-rotate finish
#
# prepare moves generation N (master-key and master-key-id) to master/previous/, mode 0400
# and owned by OpenBao's user, then writes generation N+1 with generate-master-key.sh. It
# refuses while master/previous/ holds anything, so a rotation can't start over one that
# hasn't finished.
#
# finish, once OpenBao is unsealed on generation N+1 alone and the root-key step has left its
# marker on the socket volume (rotate-root-key.sh), shreds master/previous/: the last online
# copy of generation N. The escrowed copies stay. prepare removes any stale marker, so only a
# root-key step run after it lets finish go on.
#
# It prints only paths, generation numbers and the escrow label, never a key.
#
# Settings, all optional:
#   GATEKEEP_MASTER_DIR   default /secrets       (master/ in the secrets directory)
#   GATEKEEP_KEY_OWNER    default 100:1000       (OpenBao's user, as for generate-master-key.sh)
#   BAO_ADDR              default unix:///run/openbao/openbao.sock
#   GATEKEEP_ROOT_MARKER  default /run/openbao/.master-key-root-rotated
set -eu

DIR="${GATEKEEP_MASTER_DIR:-/secrets}"
KEY="$DIR/master-key"
ID="$DIR/master-key-id"
PREVIOUS="$DIR/previous"
KEY_OWNER="${GATEKEEP_KEY_OWNER:-100:1000}"
export BAO_ADDR="${BAO_ADDR:-unix:///run/openbao/openbao.sock}"
MARKER="${GATEKEEP_ROOT_MARKER:-/run/openbao/.master-key-root-rotated}"
GENERATE="$(cd "$(dirname "$0")" && pwd)/generate-master-key.sh"

say() { echo "master-key-rotate: $*"; }
fail() { echo "master-key-rotate: $*" >&2; exit 1; }

# N for a file holding exactly gatekeep-master-<N>, as start-openbao.sh reads it. Never
# prints what a malformed file holds.
generation_of() {
    [ -f "$1" ] || fail "$1 is missing or isn't a file."
    id="$(cat "$1")" || fail "can't read $1."
    number="${id#gatekeep-master-}"
    case "$number" in
        "$id" | "" | 0* | *[!0-9]*) fail "$1 doesn't hold a key ID of the form gatekeep-master-<N>." ;;
    esac
    [ "${#number}" -le 9 ] || fail "$1 holds a generation number that's too long."
    echo "$number"
}

# True when master/previous/ holds anything but the empty directories Compose leaves for
# secret files that were missing when the overlay started.
previous_holds_something() {
    [ -d "$PREVIOUS" ] || return 1
    for name in master-key master-key-id; do
        [ -d "$PREVIOUS/$name" ] && rmdir "$PREVIOUS/$name" 2> /dev/null || true
    done
    [ -n "$(ls -A "$PREVIOUS")" ]
}

check_mount() {
    [ "$(id -u)" -eq 0 ] || fail "run as root."
    { [ -d "$DIR" ] && mountpoint -q "$DIR"; } || fail "$DIR isn't the mounted master/ directory."
}

prepare() {
    check_mount
    if previous_holds_something; then
        fail "$PREVIOUS already holds a key, so a rotation is under way. Finish it (or recover it, as the runbook says) first. Nothing was moved."
    fi
    [ -f "$KEY" ] || fail "$KEY is missing or isn't a file. Nothing was moved."
    [ "$(wc -c < "$KEY" | tr -d ' ')" -eq 32 ] || fail "$KEY isn't 32 bytes. Nothing was moved."
    current="$(generation_of "$ID")" || exit 1
    next=$((current + 1))
    # A marker from an earlier rotation would let finish go on without this one's root-key step.
    rm -f "$MARKER" || fail "couldn't remove the stale $MARKER. Nothing was moved."

    mkdir -p "$PREVIOUS"
    chmod 0700 "$PREVIOUS"
    # ln refuses an existing name, so nothing already in previous/ is ever replaced.
    ln "$KEY" "$PREVIOUS/master-key" 2> /dev/null || fail "couldn't move $KEY to $PREVIOUS. Nothing was moved."
    if ! ln "$ID" "$PREVIOUS/master-key-id" 2> /dev/null; then
        rm -f "$PREVIOUS/master-key"
        fail "couldn't move $ID to $PREVIOUS. Nothing was moved."
    fi
    chown "$KEY_OWNER" "$PREVIOUS/master-key" "$PREVIOUS/master-key-id"
    chmod 0400 "$PREVIOUS/master-key" "$PREVIOUS/master-key-id"
    rm -f "$KEY" "$ID"

    if ! sh "$GENERATE" "$KEY" "gatekeep-master-$next"; then
        # Put generation N back where it was, so OpenBao still starts on it.
        rm -f "$KEY" "$ID"
        ln "$PREVIOUS/master-key" "$KEY" && ln "$PREVIOUS/master-key-id" "$ID" \
            && rm -f "$PREVIOUS/master-key" "$PREVIOUS/master-key-id" \
            || fail "couldn't write generation $next or put generation $current back. Generation $current is in $PREVIOUS: see the runbook's recovery steps."
        chmod 0444 "$ID"
        fail "couldn't write generation $next. Generation $current is back at $KEY, and nothing else changed."
    fi

    for file in "$PREVIOUS/master-key" "$PREVIOUS/master-key-id"; do
        if [ "$(stat -c '%u:%g %a' "$file")" != "$KEY_OWNER 400" ]; then
            echo "master-key-rotate: WARNING: $file isn't $KEY_OWNER 0400 after setting it. This file system ignores ownership and modes, so the guarantees in docs/key-custody.md hold only on a Linux host file system." >&2
        fi
    done

    say "moved generation $current to $PREVIOUS/master-key and $PREVIOUS/master-key-id."
    say "wrote generation $next to $KEY and $ID."
    say "escrow the new key (master/master-key in the secrets directory) on both offline drives as master-key-gen$next-$(date -u +%Y-%m-%d) before going on."
}

finish() {
    check_mount
    [ -f "$PREVIOUS/master-key" ] || fail "$PREVIOUS holds no key, so there's nothing to finish."
    [ -f "$MARKER" ] \
        || fail "the root-key step hasn't run since prepare: run it in rotation mode, then restart OpenBao in base mode. The previous generation stays in $PREVIOUS."
    # Exit 0 only when OpenBao answers, initialized and unsealed: on the new generation, since
    # base mode gives it no other.
    bao status > /dev/null 2>&1 \
        || fail "OpenBao isn't unsealed at $BAO_ADDR. The previous generation stays in $PREVIOUS."
    # The legacy generate-root endpoint answers without a token only in rotation mode. In base
    # mode it's refused as an unsupported operation (405); any other error proves nothing.
    if attempt="$(bao read sys/generate-root/attempt 2>&1)"; then
        fail "OpenBao is still in rotation mode. Restart it without deploy/compose.rotate.yaml first. The previous generation stays in $PREVIOUS."
    fi
    case "$attempt" in
        *"Code: 405"*"unsupported operation"*) ;;
        *) fail "couldn't tell whether OpenBao is out of rotation mode. The previous generation stays in $PREVIOUS." ;;
    esac

    for file in "$PREVIOUS"/* "$PREVIOUS"/.[!.]*; do
        if [ -f "$file" ]; then
            # Writable first: shred overwrites in place, and some bind mounts refuse a 0400 file even to root.
            chmod u+w "$file" && shred -u "$file" || fail "couldn't shred $file."
        elif [ -d "$file" ]; then
            rmdir "$file" 2> /dev/null || fail "$file is a directory that isn't empty."
        fi
    done

    rm -f "$MARKER" || echo "master-key-rotate: WARNING: couldn't remove $MARKER." >&2

    say "shredded the online copy of the previous generation in $PREVIOUS."
    say "keep that generation escrowed until the last backup taken before this rotation has expired: only it opens those backups."
}

case "${1:-}" in
    prepare) prepare ;;
    finish) finish ;;
    *) fail "usage: rotate-master-key.sh prepare | finish" ;;
esac
