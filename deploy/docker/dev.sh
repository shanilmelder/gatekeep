#!/bin/sh
# Runs inside the long-lived dev container (deploy/compose.dev.yaml, profile dev):
#
#   sh /host/deploy/docker/dev.sh [checkout] [command...]
#
# checkout is a path under the repository mounted at /host: . (the default) for the main
# checkout, or .claude/worktrees/<name>. Its files are synced into /work/<checkout>, leaving
# out what the tests image leaves out, so build output and node_modules there carry over
# from run to run. Restore and the workspace install then catch up from the lockfiles, and
# the command runs there: with none, the same steps as the tests image (run-tests.sh).
set -eu

checkout="${1:-.}"
[ "$#" -gt 0 ] && shift

case "$checkout" in
  /* | *..*) echo "dev.sh: checkout must be a path under the repository, not $checkout" >&2; exit 2 ;;
esac

source="/host/$checkout"
if [ ! -f "$source/Gatekeep.slnx" ]; then
  echo "dev.sh: no Gatekeep checkout at $checkout" >&2
  exit 2
fi

name="$(printf '%s' "$checkout" | sed 's#^\./*##; s#/*$##; s#/#__#g')"
target="/work/checkouts/${name:-main}"
mkdir -p "$target"

echo "== sync $checkout to $target"
# --delete removes files gone from the checkout, but never the excluded ones, so build output
# and node_modules stay. Mirrors deploy/docker/tests.Dockerfile.dockerignore.
rsync -a --delete \
  --exclude '/.git' --exclude '/.claude/' --exclude '/graft/' --exclude '.vs/' \
  --exclude 'bin/' --exclude 'obj/' --exclude 'node_modules/' --exclude 'dist/' \
  --exclude 'TestResults/' --exclude 'test-results/' --exclude 'playwright-report/' \
  --exclude '/deploy/secrets/' --exclude '/deploy/secrets-*/' --exclude '/deploy/trust/' \
  --exclude '/deploy/release.env' --exclude '.env*' --exclude '*.pem' --exclude '*.pfx' \
  "$source/" "$target/"

cd "$target"

echo "== restore"
dotnet restore Gatekeep.slnx --locked-mode
pnpm install --frozen-lockfile --ignore-scripts

if [ "$#" -eq 0 ]; then
  exec sh deploy/docker/run-tests.sh
fi
exec "$@"
