#!/bin/sh
# Release build (Story 12.5, docs/release-signing.md). Runs in the release-tools image, in
# the secret-free CI build job and in the rehearsal, from the repository root:
#
#   sh /opt/gatekeep/release/build.sh
#
# For each release image: builds it with a docker-container buildx builder into an OCI
# archive, dist/<svc>.tar; writes its SPDX SBOM, dist/<svc>.spdx.json; and records the
# archive's manifest digest in dist/digests.txt as "<svc> sha256:<hex>". It holds no
# secret, logs in to nothing and pushes nothing: its output is only files. The signing job
# pushes these exact archives and refuses any digest that differs from digests.txt.
#
# GATEKEEP_RELEASE_SERVICES  space-separated services (default: every release image)
# GATEKEEP_RELEASE_DIST      output directory (default: dist)
set -eu

# Every service deploy/compose.yaml builds, plus release-tools, the verifier
# compose.release.yaml runs. ReleaseConfigTests holds this list to the Compose file.
DEFAULT_SERVICES="hosted admin worker caddy cli openbao release-tools"
SERVICES="${GATEKEEP_RELEASE_SERVICES:-$DEFAULT_SERVICES}"
DIST="${GATEKEEP_RELEASE_DIST:-dist}"
PLATFORM=linux/amd64
BUILDKIT=moby/buildkit:v0.34.1@sha256:99368f3e46177c6405b9740e4461d91cee004128daeecca78d4ceac50ec1da5c
BUILDER="gatekeep-release-$$"

say() { echo "release-build: $*"; }
fail() { echo "release-build: FAIL $*" >&2; exit 1; }

[ -f deploy/compose.yaml ] || fail "run from the repository root."
for svc in $SERVICES; do
    echo "$svc" | grep -Eq '^[a-z][a-z0-9-]*$' || fail "bad service name '$svc'."
    [ -f "deploy/docker/$svc.Dockerfile" ] || fail "no deploy/docker/$svc.Dockerfile for '$svc'."
done

cleanup() { docker buildx rm --force "$BUILDER" > /dev/null 2>&1 || true; }
trap cleanup EXIT

mkdir -p "$DIST"
: > "$DIST/digests.txt"

docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "image=$BUILDKIT" --bootstrap > /dev/null

for svc in $SERVICES; do
    say "building $svc."
    docker buildx build --builder "$BUILDER" \
        --platform "$PLATFORM" \
        --provenance=false --sbom=false \
        --file "deploy/docker/$svc.Dockerfile" \
        --output "type=oci,dest=$DIST/$svc.tar" \
        --quiet \
        . > /dev/null

    # The archive's index names exactly one image manifest: its digest is the release digest.
    index="$(tar -xOf "$DIST/$svc.tar" index.json)"
    count="$(echo "$index" | grep -o '"digest":"sha256:[0-9a-f]\{64\}"' | wc -l)"
    [ "$count" -eq 1 ] || fail "$svc archive index names $count manifests, not 1."
    echo "$index" | grep -q '"mediaType":"application/vnd.oci.image.manifest.v1+json"' \
        || fail "$svc archive index doesn't name an OCI image manifest."
    digest="$(echo "$index" | grep -o 'sha256:[0-9a-f]\{64\}')"

    say "SBOM for $svc."
    syft scan "oci-archive:$DIST/$svc.tar" --quiet --output "spdx-json=$DIST/$svc.spdx.json"
    [ -s "$DIST/$svc.spdx.json" ] || fail "no SBOM for $svc."

    echo "$svc $digest" >> "$DIST/digests.txt"
    say "$svc $digest"
done

say "done: $DIST/digests.txt"
