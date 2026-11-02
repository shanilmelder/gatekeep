#!/bin/sh
# Release publish (Story 12.5, docs/release-signing.md). Runs only in the CI sign job, on
# the self-hosted signing runner that holds the hardware key, and in the rehearsal. It is
# the only step that touches the signing key. It never builds anything: it pushes the OCI
# archives the build job made, checks each pushed digest against the one the build job
# recorded, signs each digest, attests its SBOM and writes release.env.
#
#   GATEKEEP_REGISTRY=ghcr.io/<owner> GATEKEEP_RELEASE_TAG=v1.2.3 \
#   GATEKEEP_SIGNING_KEY=sk sh deploy/release/publish.sh
#
# GATEKEEP_SIGNING_KEY  the hardware key: "sk" (cosign --sk, a PIV token such as a
#                       YubiKey), "sk:<slot>" for another PIV slot, or a "pkcs11:" URI.
#                       Anything else (a key file) is refused unless
#                       GATEKEEP_RELEASE_REHEARSAL=1. It is a reference, never key material.
# GATEKEEP_RELEASE_DIST the build job's output (default: dist)
# COSIGN, CRANE         the commands to run (default: cosign, crane)
# GATEKEEP_REGISTRY_INSECURE=1  plain-HTTP registry, rehearsal only
#
# Each signature carries org.gatekeep.service=<svc> and org.gatekeep.release=<tag>, so
# verify.sh can refuse a signed image in another service's slot, or images from two
# releases. Outside the rehearsal, digests.txt must name exactly RELEASE_SERVICES, and the
# signing machine must run the pinned cosign and crane.
#
# Signatures and attestations are not uploaded to a transparency log: the key pinned on
# the Docker host is the only root of trust, so verification needs no Sigstore service.
set -eu

DIST="${GATEKEEP_RELEASE_DIST:-dist}"
COSIGN="${COSIGN:-cosign}"
CRANE="${CRANE:-crane}"
REHEARSAL="${GATEKEEP_RELEASE_REHEARSAL:-0}"
KEY="${GATEKEEP_SIGNING_KEY:-}"
REGISTRY="${GATEKEEP_REGISTRY:-}"
TAG="${GATEKEEP_RELEASE_TAG:-}"
# Must equal DEFAULT_SERVICES in build.sh (ReleaseConfigTests holds them together).
RELEASE_SERVICES="hosted admin worker caddy cli openbao release-tools"
COSIGN_VERSION=v2.6.5
CRANE_VERSION=v0.22.1
CRANE_COMMIT=8a72a424fdecb4caa14f2d525e5d2503331442b5

say() { echo "release-publish: $*"; }
fail() { echo "release-publish: FAIL $*" >&2; exit 1; }

# The hardware-key rule comes first, before anything is read or pushed.
case "$KEY" in
    "") fail "set GATEKEEP_SIGNING_KEY to the hardware key (sk, sk:<slot> or a pkcs11: URI)." ;;
    pkcs11:*) set -- --key "$KEY" ;;
    sk) set -- --sk ;;
    sk:) fail "GATEKEEP_SIGNING_KEY 'sk:' names no slot." ;;
    sk:*) set -- --sk --slot "${KEY#sk:}" ;;
    *)
        [ "$REHEARSAL" = 1 ] || fail "GATEKEEP_SIGNING_KEY isn't a hardware key (sk, sk:<slot> or pkcs11:). A key file is for the rehearsal only."
        [ -f "$KEY" ] || fail "no key file '$KEY'."
        say "REHEARSAL: signing with the software key $KEY."
        set -- --key "$KEY"
        ;;
esac

# The signing machine's tools, before anything is read or pushed. The rehearsal runs the
# release-tools image, whose tools are pinned by digest.
if [ "$REHEARSAL" != 1 ]; then
    $COSIGN version 2>&1 | grep -Eq "^GitVersion:[[:space:]]+$COSIGN_VERSION\$" \
        || fail "cosign isn't $COSIGN_VERSION (docs/release-signing.md, The signing machine)."
    # A release binary prints its version; a build from the tag (as in the pinned crane
    # image) prints the tag's commit instead.
    case "$($CRANE version 2>/dev/null)" in
        "$CRANE_VERSION" | "${CRANE_VERSION#v}" | "$CRANE_COMMIT") ;;
        *) fail "crane isn't $CRANE_VERSION (docs/release-signing.md, The signing machine)." ;;
    esac
fi

COSIGN_REGISTRY=""
if [ "${GATEKEEP_REGISTRY_INSECURE:-0}" = 1 ]; then
    [ "$REHEARSAL" = 1 ] || fail "GATEKEEP_REGISTRY_INSECURE is for the rehearsal only."
    CRANE="$CRANE --insecure"
    COSIGN_REGISTRY="--allow-insecure-registry --allow-http-registry"
fi

echo "$REGISTRY" | grep -Eq '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)*$' \
    || fail "GATEKEEP_REGISTRY '$REGISTRY' isn't a lower-case registry path, such as ghcr.io/<owner>."
echo "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' \
    || fail "GATEKEEP_RELEASE_TAG '$TAG' isn't a release tag such as v1.2.3."
[ -s "$DIST/digests.txt" ] || fail "no $DIST/digests.txt from the build job."

# Read and check every line before pushing anything.
SERVICES=""
while read -r svc digest extra; do
    [ -z "$svc" ] && continue
    [ -z "${extra:-}" ] || fail "digests.txt line for '$svc' has extra fields."
    echo "$svc" | grep -Eq '^[a-z][a-z0-9-]*$' || fail "bad service name '$svc' in digests.txt."
    echo "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || fail "bad digest for $svc in digests.txt."
    [ -s "$DIST/$svc.tar" ] || fail "no archive $DIST/$svc.tar."
    [ -s "$DIST/$svc.spdx.json" ] || fail "no SBOM $DIST/$svc.spdx.json."
    SERVICES="$SERVICES $svc"
done < "$DIST/digests.txt"
[ -n "$SERVICES" ] || fail "digests.txt names no image."
if [ "$REHEARSAL" != 1 ]; then
    # shellcheck disable=SC2086
    [ "$(printf '%s\n' $SERVICES | sort)" = "$(printf '%s\n' $RELEASE_SERVICES | sort)" ] \
        || fail "digests.txt names '$(echo $SERVICES)', not every release image: $RELEASE_SERVICES."
fi

recorded() { awk -v s="$1" '$1 == s { print $2 }' "$DIST/digests.txt"; }
repository() { echo "$REGISTRY/gatekeep-$1"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. Push every archive, and stop at the first digest that differs from the build's.
for svc in $SERVICES; do
    mkdir "$WORK/$svc"
    tar -xf "$DIST/$svc.tar" -C "$WORK/$svc"
    pushed="$($CRANE push "$WORK/$svc" "$(repository "$svc"):$TAG")"
    pushed="${pushed##*@}"
    expected="$(recorded "$svc")"
    [ "$pushed" = "$expected" ] \
        || fail "$svc pushed as $pushed, but the build recorded $expected. Nothing is signed."
    say "pushed $(repository "$svc")@$pushed"
done

# 2. Sign each digest, bound to its service and this release, and attest its SBOM. Never
# a tag. (cosign attest takes no annotations: the signature carries them.)
for svc in $SERVICES; do
    ref="$(repository "$svc")@$(recorded "$svc")"
    # shellcheck disable=SC2086
    $COSIGN sign "$@" $COSIGN_REGISTRY --tlog-upload=false --yes \
        -a "org.gatekeep.service=$svc" -a "org.gatekeep.release=$TAG" "$ref"
    # shellcheck disable=SC2086
    $COSIGN attest "$@" $COSIGN_REGISTRY --tlog-upload=false --yes \
        --type spdxjson --predicate "$DIST/$svc.spdx.json" "$ref"
    say "signed and attested $ref"
done

# 3. release.env: every image by digest, and nothing else.
: > "$WORK/release.env"
for svc in $SERVICES; do
    name="GATEKEEP_$(echo "$svc" | tr 'a-z-' 'A-Z_')_IMAGE"
    echo "$name=$(repository "$svc")@$(recorded "$svc")" >> "$WORK/release.env"
done
cp "$WORK/release.env" "$DIST/release.env"
say "wrote $DIST/release.env"
