#!/bin/sh
# Release verification (Story 12.5, docs/install.md "Install a signed release"). The
# release-verify service of deploy/compose.release.yaml runs it before the Operator
# deploys a release:
#
#   docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml \
#     --env-file deploy/release.env --profile release run --rm release-verify
#
# It checks every GATEKEEP_<SVC>_IMAGE in its environment. Each must name its image by
# digest, carry a signature by the public key pinned on the Docker host, and carry a
# signed SPDX SBOM attestation. Each signature must be for the service of its variable
# (GATEKEEP_RELEASE_TOOLS_IMAGE is release-tools, in a repository ending /gatekeep-release-tools),
# and every image must be from the same release (the org.gatekeep.service and
# org.gatekeep.release annotations publish.sh signs). The pinned key is the only root of
# trust: no transparency log is consulted. Any failure refuses the whole release, exit 1.
#
# GATEKEEP_TRUST_KEY  the pinned public key (default /trust/release-signing.pub, the
#                     read-only bind of ${GATEKEEP_TRUST_DIR}/release-signing.pub)
# COSIGN              the command to run (default: cosign)
# GATEKEEP_REGISTRY_INSECURE=1  plain-HTTP registry, rehearsal only
set -eu

KEY="${GATEKEEP_TRUST_KEY:-/trust/release-signing.pub}"
COSIGN="${COSIGN:-cosign}"
COSIGN_REGISTRY=""
if [ "${GATEKEEP_REGISTRY_INSECURE:-0}" = 1 ]; then
    [ "${GATEKEEP_RELEASE_REHEARSAL:-0}" = 1 ] || { echo "release-verify: REFUSED GATEKEEP_REGISTRY_INSECURE is for the rehearsal only." >&2; exit 1; }
    COSIGN_REGISTRY="--allow-insecure-registry --allow-http-registry"
fi

refuse() { echo "release-verify: REFUSED $*" >&2; exit 1; }
# GATEKEEP_RELEASE_TOOLS_IMAGE -> release-tools
service() { echo "$1" | sed 's/^GATEKEEP_//; s/_IMAGE$//' | tr 'A-Z_' 'a-z-'; }

IMAGES="$(env | grep -E '^GATEKEEP_[A-Z0-9_]+_IMAGE=' | sort || true)"
[ -n "$IMAGES" ] || refuse "no GATEKEEP_<SVC>_IMAGE is set. Pass --env-file deploy/release.env."

# Every check that needs no network, first: each reference pinned by digest, and the key.
for line in $IMAGES; do
    name="${line%%=*}"
    ref="${line#*=}"
    echo "$ref" | grep -Eq '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$' \
        || refuse "$name=$ref is not pinned by digest (<repository>@sha256:<64 hex>)."
    svc="$(service "$name")"
    case "${ref%@*}" in
        */gatekeep-"$svc") ;;
        *) refuse "$name=$ref isn't the gatekeep-$svc repository." ;;
    esac
done
[ -f "$KEY" ] && [ -s "$KEY" ] \
    || refuse "no pinned public key at $KEY. Put the release key at \${GATEKEEP_TRUST_DIR:-deploy/trust}/release-signing.pub."

failed=0
first=1
common=""
for line in $IMAGES; do
    name="${line%%=*}"
    ref="${line#*=}"
    svc="$(service "$name")"
    # shellcheck disable=SC2086
    if ! out="$($COSIGN verify --key "$KEY" --insecure-ignore-tlog=true $COSIGN_REGISTRY \
        -a "org.gatekeep.service=$svc" "$ref" 2>&1)"; then
        echo "release-verify: REFUSED $name $ref: no valid signature by the pinned key for gatekeep-$svc." >&2
        echo "$out" | tail -n 3 >&2
        failed=1
        continue
    fi
    # The releases this digest is signed for (re-signing the same release adds no new value).
    releases="$(echo "$out" | grep -o '"org.gatekeep.release": *"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/' | sort -u)"
    if [ "$first" = 1 ]; then
        common="$releases"
        first=0
    else
        keep=""
        for r in $common; do
            echo "$releases" | grep -Fxq -- "$r" && keep="$keep $r"
        done
        common="$keep"
    fi
    # shellcheck disable=SC2086
    if ! out="$($COSIGN verify-attestation --key "$KEY" --insecure-ignore-tlog=true --type spdxjson $COSIGN_REGISTRY "$ref" 2>&1 > /dev/null)"; then
        echo "release-verify: REFUSED $name $ref: no SBOM attestation signed by the pinned key." >&2
        echo "$out" | tail -n 3 >&2
        failed=1
        continue
    fi
    echo "release-verify: verified $name $ref"
done

[ "$failed" = 0 ] || refuse "at least one image failed. Don't deploy this release."
# shellcheck disable=SC2086
set -- $common
[ "$#" -eq 1 ] || refuse "the images aren't all signed for one release (common: ${*:-none}). Don't deploy this release."
echo "release-verify: release $1"
echo "release-verify: every image is signed by the pinned key and carries a signed SBOM."
