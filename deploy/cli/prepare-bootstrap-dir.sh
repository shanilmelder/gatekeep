#!/bin/sh
# Makes bootstrap/ in the secrets directory ready for `gatekeep init` (Story 1.19). Run by the
# bootstrap-dir Compose service, as often as you like:
#
#   docker compose -f deploy/compose.yaml run --rm bootstrap-dir
#
# The cli service bind-mounts this directory read-write and writes the one-time bootstrap
# token into it as bootstrap-token, mode 0600. Here the directory gets mode 0700 and the cli
# uid as owner, so on the Docker host only root, or whoever holds that uid, can read the
# token. bootstrap/ must be a real directory, not a symbolic link. Those modes hold only on a
# Linux host file system: a Docker Desktop bind mount from Windows or macOS ignores them, and
# this says so. It reads and writes no file in it.
set -eu

DIR="${1:-/secrets/bootstrap}"
# The cli service's user, deploy/compose.yaml and deploy/docker/cli.Dockerfile.
CLI_UID=10004

if [ "$(id -u)" -ne 0 ]; then
    echo "prepare-bootstrap-dir: run as root." >&2
    exit 1
fi

if [ -L "$DIR" ]; then
    echo "prepare-bootstrap-dir: $DIR is a symbolic link. Make bootstrap/ a real directory." >&2
    exit 1
fi

if ! mountpoint -q "$DIR"; then
    echo "prepare-bootstrap-dir: $DIR isn't a mounted secrets directory." >&2
    exit 1
fi

# A file system that ignores owners and modes refuses these too: the check below explains it.
chown "$CLI_UID:$CLI_UID" "$DIR" 2> /dev/null || true
chmod 0700 "$DIR" 2> /dev/null || true

if [ "$(stat -c %a "$DIR")" != 700 ] || [ "$(stat -c %u "$DIR")" != "$CLI_UID" ]; then
    echo "prepare-bootstrap-dir: WARNING: $DIR isn't mode 0700 owned by uid $CLI_UID. This file system ignores modes (a Docker Desktop bind mount from Windows or macOS does), so only a Linux host file system keeps the bootstrap token root-only." >&2
fi

echo "prepare-bootstrap-dir: $DIR is ready for gatekeep init."
