#!/bin/sh
# The root-key step of a Master Key rotation (Story 12.7), run by the master-key-rotate-root
# service of deploy/compose.rotate.yaml with no network, mounting only OpenBao's socket, while
# OpenBao runs in rotation mode. docs/runbooks/master-key-rotation.md has the whole rotation.
# The recovery shares are typed at its prompt, which doesn't echo them:
#
#   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm master-key-rotate-root
#
# or, with no terminal (-T), come on standard input as the escrowed openbao-init.json or one
# share per line, as the stack check's rehearsal passes them:
#
#   docker compose -f deploy/compose.yaml -f deploy/compose.rotate.yaml run --rm -T master-key-rotate-root < openbao-init.json
#
# A seal rotation only re-wraps OpenBao's root key. This rotates the root key itself
# (sys/rotate/root) and starts a new barrier keyring term (sys/rotate/keyring), so the
# previous generation and a snapshot taken under it can't open anything written after.
#
# It refuses, before reading any share, unless OpenBao is unsealed and in rotation mode: only
# then does the legacy sys/generate-root/attempt endpoint answer without a token. It takes a
# short-lived root token through that endpoint and sys/generate-root/update, with the OTP the
# attempt returns, decoded here. With it, it first revokes every other root token, such as one a
# failed earlier run couldn't revoke. Its own is revoked on success, failure or interrupt, and an
# unfinished attempt is cancelled. It fails unless the keyring term rose. On success it writes
# the new term, not a secret, to $MARKER on the socket volume, which master-key-rotate finish
# requires. It prints the new key term only: never a share, OTP or token.
#
# Settings, all optional:
#   BAO_ADDR              default unix:///run/openbao/openbao.sock
#   GATEKEEP_ROOT_MARKER  default /run/openbao/.master-key-root-rotated
set -eu
set -f
umask 0077

export BAO_ADDR="${BAO_ADDR:-unix:///run/openbao/openbao.sock}"
export HOME="${HOME:-/tmp}"
unset BAO_TOKEN VAULT_TOKEN
MARKER="${GATEKEEP_ROOT_MARKER:-/run/openbao/.master-key-root-rotated}"

say() { echo "master-key-rotate-root: $*"; }
fail() { echo "master-key-rotate-root: $*" >&2; exit 1; }

# The value of "field": "..." in bao's JSON output on stdin, or nothing.
field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -n 1; }
number() { sed -n "s/.*\"$1\": *\([0-9][0-9]*\).*/\1/p" | head -n 1; }

command -v bao > /dev/null || fail "bao isn't on PATH."

# 1. Rotation mode, before any share is read.
bao status > /dev/null 2>&1 || fail "OpenBao isn't unsealed at $BAO_ADDR. No share was read."
STATUS="$(bao read -format=json sys/generate-root/attempt 2> /dev/null)" \
    || fail "OpenBao isn't in rotation mode: start it with deploy/compose.rotate.yaml first. No share was read."
REQUIRED="$(printf '%s\n' "$STATUS" | number required)"
[ -n "$REQUIRED" ] && [ "$REQUIRED" -gt 0 ] || fail "OpenBao didn't say how many recovery shares it needs. No share was read."

# 2. The shares, kept in memory only. The escrow file's other values (the revoked root token,
# the hex form of each share) are never used.
if [ -t 0 ]; then
    # At a terminal: one prompt per share, with echo off, restored however this ends.
    trap 'stty echo 2> /dev/null || true' EXIT
    trap 'stty echo 2> /dev/null || true; exit 1' INT TERM HUP
    stty -echo 2> /dev/null || fail "couldn't turn the terminal's echo off. No share was read."
    INPUT=""
    i=1
    while [ "$i" -le "$REQUIRED" ]; do
        printf 'Recovery share %s of %s: ' "$i" "$REQUIRED" >&2
        IFS= read -r line || break
        printf '\n' >&2
        INPUT="$INPUT$line
"
        i=$((i + 1))
    done
    unset line
    stty echo 2> /dev/null || true
    trap - EXIT INT TERM HUP
else
    INPUT="$(cat)"
fi
case "$INPUT" in
    *'"recovery_keys_b64"'*)
        SHARES="$(printf '%s\n' "$INPUT" | tr ',[]{}' '\n\n\n\n\n' | awk '
            /"recovery_keys_b64"/ { on = 1; next }
            on && /:/ { on = 0 }
            on { gsub(/[" \t\r]/, ""); if (length($0) > 0) print }')"
        ;;
    *) SHARES="$(printf '%s\n' "$INPUT" | tr -d ' \t\r' | grep -v '^$' || true)" ;;
esac
unset INPUT
count=0
for share in $SHARES; do
    case "$share" in *[!A-Za-z0-9+/=]*) fail "standard input holds a line that isn't a recovery share. Nothing was started." ;; esac
    count=$((count + 1))
done
[ "$count" -ge "$REQUIRED" ] || fail "OpenBao needs $REQUIRED recovery shares and standard input held $count. Nothing was started."

# 3. From here on an attempt or a root token may exist: cancel and revoke on the way out.
ATTEMPT_OPEN=0
cleanup() {
    if [ -n "${BAO_TOKEN:-}" ]; then
        bao token revoke -self > /dev/null 2>&1 || echo "master-key-rotate-root: couldn't revoke the root token. Run this step again: it revokes every other root token it finds." >&2
        unset BAO_TOKEN
    fi
    if [ "$ATTEMPT_OPEN" = 1 ]; then
        bao delete sys/generate-root/attempt > /dev/null 2>&1 || echo "master-key-rotate-root: couldn't cancel the root generation attempt." >&2
        ATTEMPT_OPEN=0
    fi
}
trap cleanup EXIT
# sh doesn't run the EXIT trap on a signal, so an interrupt cleans up and exits itself.
trap 'cleanup; exit 1' INT TERM HUP

case "$STATUS" in
    *'"started": true'*)
        echo "master-key-rotate-root: WARNING: a root generation attempt was already in progress, and this didn't start it. It's cancelled now. If no one you know started it, treat the socket's users as suspect." >&2
        bao delete sys/generate-root/attempt > /dev/null 2>&1 || fail "couldn't cancel the attempt already in progress."
        ;;
esac

ATTEMPT_OPEN=1
ATTEMPT="$(bao write -format=json -f sys/generate-root/attempt 2> /dev/null)" || fail "couldn't start a root generation attempt."
OTP="$(printf '%s\n' "$ATTEMPT" | field otp)"
NONCE="$(printf '%s\n' "$ATTEMPT" | field nonce)"
unset ATTEMPT
[ -n "$OTP" ] && [ -n "$NONCE" ] || fail "the attempt returned no OTP or nonce. Nothing was rotated."

submitted=0
ENCODED=""
for share in $SHARES; do
    [ "$submitted" -lt "$REQUIRED" ] || break
    # The share goes on bao's standard input, never in an argument.
    PROGRESS="$(printf '%s' "$share" | bao write -format=json sys/generate-root/update key=- nonce="$NONCE" 2> /dev/null)" \
        || fail "OpenBao refused a recovery share, or the attempt was cancelled by another user of the socket. The attempt is cancelled, and nothing was rotated."
    submitted=$((submitted + 1))
    case "$PROGRESS" in
        *'"complete": true'*)
            ENCODED="$(printf '%s\n' "$PROGRESS" | field encoded_token)"
            break
            ;;
    esac
done
unset SHARES PROGRESS share
[ -n "$ENCODED" ] || fail "$submitted recovery shares didn't complete root generation. The attempt is cancelled, and nothing was rotated."
ATTEMPT_OPEN=0

# The encoded token is base64 without padding; the token is it XOR the OTP, byte by byte.
while [ $((${#ENCODED} % 4)) -ne 0 ]; do ENCODED="$ENCODED="; done
TOKEN="$( {
    printf '%s' "$ENCODED" | base64 -d | od -An -tu1 -v
    echo X
    printf '%s' "$OTP" | od -An -tu1 -v
} | awk '
    $1 == "X" { second = 1; next }
    { for (i = 1; i <= NF; i++) if (second) b[nb++] = $i; else a[na++] = $i }
    END {
        if (na == 0 || na != nb) exit 1
        for (i = 0; i < na; i++) printf "%c", xor(a[i], b[i])
    }')" || fail "couldn't decode the root token. Nothing was rotated."
unset ENCODED OTP
[ -n "$TOKEN" ] || fail "couldn't decode the root token. Nothing was rotated."
export BAO_TOKEN="$TOKEN"
unset TOKEN

# Every other root token goes: none should exist, but a run that couldn't revoke its own leaves one.
OWN="$(bao token lookup -format=json 2> /dev/null | field accessor)"
[ -n "$OWN" ] || fail "couldn't look up the root token. Nothing was rotated."
others=0
ACCESSORS="$(bao list -format=json auth/token/accessors 2> /dev/null)" \
    || fail "couldn't list the tokens, so other root tokens can't be revoked. Nothing was rotated."
for accessor in $(printf '%s\n' "$ACCESSORS" | grep -o '"[A-Za-z0-9.]*"' | tr -d '"'); do
    [ "$accessor" = "$OWN" ] && continue
    if bao token lookup -format=json -accessor "$accessor" 2> /dev/null | tr -d ' \n' | grep -q '"policies":\["root"\]'; then
        bao token revoke -accessor "$accessor" > /dev/null 2>&1 || fail "couldn't revoke another root token. Nothing was rotated."
        others=$((others + 1))
    fi
done
unset OWN accessor ACCESSORS
[ "$others" -eq 0 ] || echo "master-key-rotate-root: WARNING: revoked $others other root token(s). One may be left by an earlier run that failed; if not, treat the recovery shares as exposed." >&2

TERM_BEFORE="$(bao read -field=term sys/key-status 2> /dev/null)" || fail "couldn't read the keyring term. Nothing was rotated."
case "$TERM_BEFORE" in "" | *[!0-9]*) fail "OpenBao gave no keyring term. Nothing was rotated." ;; esac
bao write -f sys/rotate/root > /dev/null 2>&1 || fail "OpenBao refused to rotate the root key. Nothing was rotated."
bao write -f sys/rotate/keyring > /dev/null 2>&1 \
    || fail "the root key rotated, but OpenBao refused to rotate the barrier keyring. Run this step again."
TERM_NOW="$(bao read -field=term sys/key-status 2> /dev/null)" \
    || fail "the root key rotated, but the keyring term can't be read back. Run this step again."
case "$TERM_NOW" in "" | *[!0-9]*) fail "the root key rotated, but OpenBao gave no keyring term. Run this step again." ;; esac
[ "$TERM_NOW" -gt "$TERM_BEFORE" ] \
    || fail "the keyring term didn't rise (still $TERM_NOW). Run this step again."

bao token revoke -self > /dev/null 2>&1 || fail "rotated, but couldn't revoke the root token. Run this step again: it revokes every other root token it finds."
unset BAO_TOKEN
trap - EXIT INT TERM HUP

# For finish: proof this step ran against the OpenBao now on the socket. Not a secret.
printf '%s\n' "$TERM_NOW" > "$MARKER" 2> /dev/null && chmod 0644 "$MARKER" \
    || fail "rotated, but couldn't write $MARKER, which finish needs. Run this step again."

say "rotated OpenBao's root key and barrier keyring; the key term is now $TERM_NOW. The root token is revoked."
