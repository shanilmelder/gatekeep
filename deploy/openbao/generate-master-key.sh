#!/bin/sh
# Writes a new Master Key (the OpenBao static seal key): 32 CSPRNG bytes, mode 0400,
# owned by the openbao user of the OpenBao image, in the secrets directory. Run by the
# keygen Compose service, once per generation:
#
#   docker compose -f deploy/compose.yaml run --rm keygen
#
# The secrets directory is a bind mount of a directory on the Docker host, never a
# Docker volume, so the key is in no data volume and no backup of one. Compose hands it
# to the openbao service as the read-only secret master_key. This prints nothing about
# the key, and it refuses to overwrite an existing key file.
#
# Usage: generate-master-key.sh [key-file]    (default /secrets/master-key)
#
# After it runs, follow docs/key-custody.md: escrow the file offline, apart from
# backups, and keep every generation until no backup needs it.
set -eu

KEY_FILE="${1:-/secrets/master-key}"
KEY_DIR="$(dirname "$KEY_FILE")"
# The openbao user and group of openbao/openbao:2.7.2, which reads the secret.
KEY_OWNER="${GATEKEEP_KEY_OWNER:-100:1000}"

if [ "$(id -u)" -ne 0 ]; then
    echo "generate-master-key: run as root." >&2
    exit 1
fi

# A bind mount, so the key lands on the host's secrets directory, not in this container.
if [ ! -d "$KEY_DIR" ] || ! mountpoint -q "$KEY_DIR"; then
    echo "generate-master-key: $KEY_DIR isn't a mounted secrets directory." >&2
    exit 1
fi

# Compose makes an empty directory for a secret file that's missing at start. That isn't a key.
if [ -d "$KEY_FILE" ]; then
    rmdir "$KEY_FILE" 2> /dev/null || { echo "generate-master-key: $KEY_FILE is a directory that isn't empty." >&2; exit 1; }
fi

if [ -e "$KEY_FILE" ]; then
    echo "generate-master-key: $KEY_FILE already exists. A new generation needs a new file name." >&2
    exit 1
fi

chmod 0700 "$KEY_DIR"
umask 0077
TMP_FILE="$(mktemp "$KEY_DIR/.master-key.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

head -c 32 /dev/urandom > "$TMP_FILE"

if [ "$(wc -c < "$TMP_FILE" | tr -d ' ')" -ne 32 ]; then
    echo "generate-master-key: couldn't read 32 random bytes." >&2
    exit 1
fi

chown "$KEY_OWNER" "$TMP_FILE"
chmod 0400 "$TMP_FILE"
# ln refuses an existing name, so a key that appeared since the check above survives.
if ! ln "$TMP_FILE" "$KEY_FILE" 2> /dev/null; then
    echo "generate-master-key: $KEY_FILE already exists. A new generation needs a new file name." >&2
    exit 1
fi
rm -f "$TMP_FILE"
trap - EXIT

# A Docker Desktop bind mount from Windows or macOS takes the calls above and ignores them.
if [ "$(stat -c '%u:%g %a' "$KEY_FILE")" != "$KEY_OWNER 400" ]; then
    echo "generate-master-key: WARNING: $KEY_FILE isn't $KEY_OWNER 0400 after setting it. This file system ignores ownership and modes, so the guarantees in docs/key-custody.md hold only on a Linux host file system." >&2
fi

echo "generate-master-key: wrote $KEY_FILE ($KEY_OWNER 0400)."
