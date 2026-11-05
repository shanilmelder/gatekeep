#!/bin/sh
# Writes a new Master Key (the OpenBao static seal key): 32 CSPRNG bytes, mode 0400,
# owned by the openbao user of the OpenBao image, in the secrets directory, and next to it
# its key ID, gatekeep-master-<N>, in <key-file>-id (mode 0444: an ID, not a secret). Run
# by the keygen Compose service for generation 1:
#
#   docker compose -f deploy/compose.yaml run --rm keygen
#
# and by master-key-rotate prepare for each later generation (Story 12.7).
#
# The secrets directory is a bind mount of a directory on the Docker host, never a
# Docker volume, so the key is in no data volume and no backup of one. Compose hands it
# to the openbao service as the read-only secret master_key, and the ID as master_key_id.
# This prints nothing about the key, and it refuses to overwrite an existing key or ID file.
#
# Usage: generate-master-key.sh [key-file [key-id]]    (default /secrets/master-key gatekeep-master-1)
#
# After it runs, follow docs/key-custody.md: escrow the file offline, apart from
# backups, and keep every generation until no backup needs it.
set -eu

KEY_FILE="${1:-/secrets/master-key}"
KEY_ID="${2:-gatekeep-master-1}"
ID_FILE="$KEY_FILE-id"
KEY_DIR="$(dirname "$KEY_FILE")"
# The openbao user and group of openbao/openbao:2.7.2, which reads the secret.
KEY_OWNER="${GATEKEEP_KEY_OWNER:-100:1000}"

if [ "$(id -u)" -ne 0 ]; then
    echo "generate-master-key: run as root." >&2
    exit 1
fi

case "${KEY_ID#gatekeep-master-}" in
    "$KEY_ID" | "" | 0* | *[!0-9]*)
        echo "generate-master-key: the key ID must be gatekeep-master-<N>, N from 1 with no leading zero." >&2
        exit 1
        ;;
esac

# A bind mount, so the key lands on the host's secrets directory, not in this container.
if [ ! -d "$KEY_DIR" ] || ! mountpoint -q "$KEY_DIR"; then
    echo "generate-master-key: $KEY_DIR isn't a mounted secrets directory." >&2
    exit 1
fi

# Compose makes an empty directory for a secret file that's missing at start. That isn't a key.
for file in "$KEY_FILE" "$ID_FILE"; do
    if [ -d "$file" ]; then
        rmdir "$file" 2> /dev/null || { echo "generate-master-key: $file is a directory that isn't empty." >&2; exit 1; }
    fi
done

for file in "$KEY_FILE" "$ID_FILE"; do
    if [ -e "$file" ]; then
        echo "generate-master-key: $file already exists. A new generation needs a new file name." >&2
        exit 1
    fi
done

chmod 0700 "$KEY_DIR"
umask 0077
TMP_FILE="$(mktemp "$KEY_DIR/.master-key.XXXXXX")"
TMP_ID="$(mktemp "$KEY_DIR/.master-key-id.XXXXXX")"
trap 'rm -f "$TMP_FILE" "$TMP_ID"' EXIT

head -c 32 /dev/urandom > "$TMP_FILE"

if [ "$(wc -c < "$TMP_FILE" | tr -d ' ')" -ne 32 ]; then
    echo "generate-master-key: couldn't read 32 random bytes." >&2
    exit 1
fi

printf '%s\n' "$KEY_ID" > "$TMP_ID"

chown "$KEY_OWNER" "$TMP_FILE" "$TMP_ID"
chmod 0400 "$TMP_FILE"
chmod 0444 "$TMP_ID"
# ln refuses an existing name, so a key that appeared since the check above survives.
if ! ln "$TMP_FILE" "$KEY_FILE" 2> /dev/null; then
    echo "generate-master-key: $KEY_FILE already exists. A new generation needs a new file name." >&2
    exit 1
fi
# The key just written has sealed nothing yet, so without its ID it's removed again.
if ! ln "$TMP_ID" "$ID_FILE" 2> /dev/null; then
    rm -f "$KEY_FILE"
    echo "generate-master-key: $ID_FILE already exists. A new generation needs a new file name." >&2
    exit 1
fi
rm -f "$TMP_FILE" "$TMP_ID"
trap - EXIT

# A Docker Desktop bind mount from Windows or macOS takes the calls above and ignores them.
if [ "$(stat -c '%u:%g %a' "$KEY_FILE")" != "$KEY_OWNER 400" ]; then
    echo "generate-master-key: WARNING: $KEY_FILE isn't $KEY_OWNER 0400 after setting it. This file system ignores ownership and modes, so the guarantees in docs/key-custody.md hold only on a Linux host file system." >&2
fi

echo "generate-master-key: wrote $KEY_FILE ($KEY_OWNER 0400) and its ID, $KEY_ID, to $ID_FILE."
