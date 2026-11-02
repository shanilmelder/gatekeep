#!/bin/sh
# Runs inside the tests container (deploy/compose.test.yaml): the same steps CI used to
# run on the runner. Restore already ran, from lockfiles, when the image was built.
set -eu

echo "== pnpm audit"
pnpm audit --audit-level critical

echo "== build .NET solution"
dotnet build Gatekeep.slnx --no-restore

echo "== build workspaces"
pnpm -r build

echo "== architecture tests"
dotnet test tests/Architecture --no-build

echo "== isolation tests"
dotnet test tests/Isolation --no-build
