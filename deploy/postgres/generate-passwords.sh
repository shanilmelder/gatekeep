#!/bin/sh
# Writes a random password for the PostgreSQL superuser and each login role into postgres/
# in the secrets directory, keeping any that exists. Run by the passwords Compose service:
#
#   docker compose -f deploy/compose.yaml run --rm passwords
#
# Each file is a Compose secret. Mode 0444 lets both PostgreSQL and the one host that uses
# a role read it inside their containers, where only mounted files are visible; on the
# Docker host the 0700 directory keeps everyone but root out. Those modes hold only on a
# Linux host file system: a Docker Desktop bind mount from Windows or macOS ignores them,
# and this says so. It prints no value.
set -eu

DIR="${1:-/secrets/postgres}"

if [ "$(id -u)" -ne 0 ]; then
    echo "generate-passwords: run as root." >&2
    exit 1
fi

if ! mountpoint -q "$DIR"; then
    echo "generate-passwords: $DIR isn't a mounted secrets directory." >&2
    exit 1
fi

chmod 0700 "$DIR"
umask 0333

for name in postgres gk_migrator gk_hosted gk_admin gk_worker gk_dispatch gk_sealer gk_retention gk_cli; do
    file="$DIR/${name}_password"

    # Compose makes an empty directory for a secret file that's missing at start, and an
    # empty file is no password. Neither counts as one that exists.
    if [ -d "$file" ]; then
        rmdir "$file" 2> /dev/null || { echo "generate-passwords: $file is a directory that isn't empty." >&2; exit 1; }
    fi
    if [ -f "$file" ] && [ ! -s "$file" ]; then
        rm -f "$file"
    fi

    if [ -e "$file" ]; then
        echo "generate-passwords: kept $file."
        continue
    fi

    # 32 characters from 24 random bytes, base64 with no symbols that need quoting.
    head -c 24 /dev/urandom | base64 | tr -d '\n' | tr '+/' 'xy' > "$file"
    chmod 0444 "$file"
    if [ "$(stat -c %a "$file")" != 444 ]; then
        echo "generate-passwords: WARNING: $file isn't mode 0444. This file system ignores modes (a Docker Desktop bind mount from Windows or macOS does), so the guarantees in docs/key-custody.md hold only on a Linux host file system." >&2
    fi
    echo "generate-passwords: wrote $file."
done

if [ "$(stat -c %a "$DIR")" != 700 ]; then
    echo "generate-passwords: WARNING: $DIR isn't mode 0700. Only a Linux host file system keeps it so." >&2
fi
