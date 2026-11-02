#!/bin/sh
# Writes a new Master Key (the OpenBao static seal key): 32 CSPRNG bytes in a
# root:root 0400 file on the key volume. Run as root, once per generation. It prints
# nothing about the key, and it refuses to overwrite an existing key file.
#
# Usage: generate-master-key.sh [key-file]    (default /srv/gatekeep/keys/master-key)
#
# After it runs, follow docs/key-custody.md: escrow the file offline, apart from
# backups, and keep every generation until no backup needs it.
set -eu

KEY_FILE="${1:-/srv/gatekeep/keys/master-key}"
KEY_DIR="$(dirname "$KEY_FILE")"

if [ "$(id -u)" -ne 0 ]; then
    echo "generate-master-key: run as root." >&2
    exit 1
fi

if [ ! -d "$KEY_DIR" ] || ! mountpoint -q "$KEY_DIR"; then
    echo "generate-master-key: $KEY_DIR isn't a mounted volume. Mount the key volume first." >&2
    exit 1
fi

if [ -e "$KEY_FILE" ]; then
    echo "generate-master-key: $KEY_FILE already exists. A new generation needs a new file name." >&2
    exit 1
fi

umask 0277
TMP_FILE="$(mktemp "$KEY_DIR/.master-key.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

head -c 32 /dev/urandom > "$TMP_FILE"

if [ "$(wc -c < "$TMP_FILE" | tr -d ' ')" -ne 32 ]; then
    echo "generate-master-key: couldn't read 32 random bytes." >&2
    exit 1
fi

chown root:root "$TMP_FILE"
chmod 0400 "$TMP_FILE"
# ln refuses an existing name, so a key that appeared since the check above survives.
if ! ln "$TMP_FILE" "$KEY_FILE" 2> /dev/null; then
    echo "generate-master-key: $KEY_FILE already exists. A new generation needs a new file name." >&2
    exit 1
fi
rm -f "$TMP_FILE"
trap - EXIT

echo "generate-master-key: wrote $KEY_FILE (root:root 0400)."
