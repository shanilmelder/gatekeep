#!/bin/sh
# Release rehearsal (Story 12.5). Runs inside the release container of
# deploy/compose.dev.yaml, never on the machine itself:
#
#   docker compose -f deploy/compose.dev.yaml run --rm --build release
#
# It runs the real release scripts end to end, with a throwaway software key in place of
# the hardware key and a local registry in place of GHCR: build.sh for openbao and
# release-tools, then publish.sh (GATEKEEP_RELEASE_REHEARSAL=1), then verify.sh, which must
# pass, both directly and as release-verify runs it (non-root, read-only, the pinned key
# mounted read-only, no GATEKEEP_TRUST_KEY). Then each refusal of the release path must
# fail closed: an unsigned digest, a signed digest with no SBOM attestation, a different
# key, a tag reference, a missing pinned key, another service's repository in a slot, a
# signed image copied into another service's repository, images from two releases, a
# software key outside the rehearsal, and a pushed digest that differs from the build's.
#
# After the build, the registry and this container share one internal network and this
# container leaves every other network, so publishing and verifying are shown to need no
# Sigstore service or any other egress. It always cleans up.
set -eu

RELEASE=/opt/gatekeep/release
REGISTRY_IMAGE=registry:3.1.2@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3
NET="gatekeep-release-check-$$"
REG="gatekeep-release-registry-$$"
SELF="$(hostname)"
VOL="gatekeep-release-trust-$$"
WORK="$(mktemp -d)"
TAG=v0.0.0-rehearsal
TOOLS=gatekeep/release-tools:local

say() { echo "release-check: $*"; }
pass() { echo "release-check: PASS $*"; }
fail() { echo "release-check: FAIL $*" >&2; exit 1; }

[ -f deploy/compose.yaml ] || fail "run from the repository root."

cleanup() {
    docker rm -f "$REG" > /dev/null 2>&1 || true
    docker volume rm -f "$VOL" > /dev/null 2>&1 || true
    docker network disconnect -f "$NET" "$SELF" > /dev/null 2>&1 || true
    docker network rm "$NET" > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

say "local registry on an internal network."
docker network create --internal "$NET" > /dev/null
docker run -d --name "$REG" --network "$NET" --network-alias registry \
    --read-only --tmpfs /var/lib/registry --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 "$REGISTRY_IMAGE" > /dev/null
docker network connect "$NET" "$SELF"

say "throwaway key pairs A (release) and B (another key)."
for pair in a b; do
    mkdir -p "$WORK/keys-$pair"
    (cd "$WORK/keys-$pair" && COSIGN_PASSWORD="" cosign generate-key-pair > /dev/null 2>&1)
    [ -s "$WORK/keys-$pair/cosign.pub" ] || fail "no key pair $pair."
done

# publish.sh as the rehearsal runs it: $1 the build output, $2 the registry path, then
# extra variables.
publish() {
    dist="$1"
    registry="$2"
    shift 2
    env GATEKEEP_RELEASE_DIST="$dist" GATEKEEP_REGISTRY="$registry" GATEKEEP_RELEASE_TAG="$TAG" \
        GATEKEEP_REGISTRY_INSECURE=1 COSIGN_PASSWORD="" "$@" sh "$RELEASE/publish.sh"
}

# verify.sh with only the variables a release-verify container would have: $1 is an env
# file of GATEKEEP_<SVC>_IMAGE lines, $2 the pinned key.
verify() {
    # shellcheck disable=SC2046
    env -i PATH="$PATH" HOME="$HOME" GATEKEEP_TRUST_KEY="$2" \
        GATEKEEP_REGISTRY_INSECURE=1 GATEKEEP_RELEASE_REHEARSAL=1 \
        $(cat "$1") sh "$RELEASE/verify.sh"
}

# Runs "$@" and requires it to fail with output holding $expect.
expect_refusal() {
    what="$1"
    expect="$2"
    shift 2
    if out="$("$@" 2>&1)"; then
        echo "$out" >&2
        fail "$what was accepted."
    fi
    echo "$out" | grep -qF -- "$expect" || { echo "$out" >&2; fail "$what failed without '$expect'."; }
    pass "$what is refused."
}

# release-tools has a hyphen, so publish.sh's GATEKEEP_RELEASE_TOOLS_IMAGE naming runs too.
say "build.sh for openbao and release-tools."
GATEKEEP_RELEASE_SERVICES="openbao release-tools" GATEKEEP_RELEASE_DIST="$WORK/dist" sh "$RELEASE/build.sh"
for svc in openbao release-tools; do
    [ -s "$WORK/dist/$svc.tar" ] && [ -s "$WORK/dist/$svc.spdx.json" ] || fail "build.sh wrote no archive or SBOM for $svc."
    grep -q '"spdxVersion"' "$WORK/dist/$svc.spdx.json" || fail "the $svc SBOM isn't SPDX JSON."
    grep -Eq "^$svc sha256:[0-9a-f]{64}\$" "$WORK/dist/digests.txt" || fail "digests.txt has no line for $svc."
done
[ "$(wc -l < "$WORK/dist/digests.txt")" -eq 2 ] || fail "digests.txt doesn't hold exactly two lines."
cp -r "$WORK/dist" "$WORK/dist-drift"
cp -r "$WORK/dist" "$WORK/dist-second"

# The build needs egress (buildx fetches registry tokens for the base images). Nothing
# after it does: leave every network but the registry's.
for network in $(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$SELF"); do
    [ "$network" = "$NET" ] || docker network disconnect "$network" "$SELF"
done
waited=0
until crane --insecure catalog registry:5000 > /dev/null 2>&1; do
    waited=$((waited + 2))
    [ "$waited" -le 60 ] || fail "the registry never answered."
    sleep 2
done
if wget -q -T 5 -O /dev/null http://1.1.1.1/ 2> /dev/null; then
    fail "this container still has egress."
fi
say "registry up; this container has no egress from here on."

say "publish.sh with the software key, as a rehearsal."
publish "$WORK/dist" registry:5000/signed GATEKEEP_RELEASE_REHEARSAL=1 GATEKEEP_SIGNING_KEY="$WORK/keys-a/cosign.key"
ENV_FILE="$WORK/dist/release.env"
[ "$(cut -d= -f1 "$ENV_FILE" | sort | tr '\n' ' ')" = "GATEKEEP_OPENBAO_IMAGE GATEKEEP_RELEASE_TOOLS_IMAGE " ] \
    || fail "release.env doesn't hold exactly GATEKEEP_OPENBAO_IMAGE and GATEKEEP_RELEASE_TOOLS_IMAGE: $(cat "$ENV_FILE")"
for svc in openbao release-tools; do
    name="GATEKEEP_$(echo "$svc" | tr 'a-z-' 'A-Z_')_IMAGE"
    line="$(grep "^$name=" "$ENV_FILE")"
    echo "$line" | grep -Eq "^$name=registry:5000/signed/gatekeep-$svc@sha256:[0-9a-f]{64}\$" \
        || fail "release.env doesn't name $svc by digest: $line"
    [ "${line##*@}" = "$(awk -v s="$svc" '$1 == s { print $2 }' "$WORK/dist/digests.txt")" ] \
        || fail "release.env names another $svc digest than the build recorded."
done
SIGNED="$(grep '^GATEKEEP_OPENBAO_IMAGE=' "$ENV_FILE" | cut -d= -f2)"
SIGNED_TOOLS="$(grep '^GATEKEEP_RELEASE_TOOLS_IMAGE=' "$ENV_FILE" | cut -d= -f2)"

mkdir -p "$WORK/trust-a" "$WORK/trust-b"
cp "$WORK/keys-a/cosign.pub" "$WORK/trust-a/release-signing.pub"
cp "$WORK/keys-b/cosign.pub" "$WORK/trust-b/release-signing.pub"

say "verify.sh on the signed release."
out="$(verify "$ENV_FILE" "$WORK/trust-a/release-signing.pub")" || { echo "$out" >&2; fail "the signed release didn't verify."; }
echo "$out"
echo "$out" | grep -qF "verified GATEKEEP_OPENBAO_IMAGE $SIGNED" || fail "verify.sh didn't name the verified image."
echo "$out" | grep -qF "verified GATEKEEP_RELEASE_TOOLS_IMAGE $SIGNED_TOOLS" || fail "verify.sh didn't name the verified release-tools image."
echo "$out" | grep -qxF "release-verify: release $TAG" || fail "verify.sh didn't name the release."
pass "the signed release verifies against the pinned key."

# As compose.release.yaml runs release-verify: the image's own entrypoint, non-root, a
# read-only root, the pinned key read-only at /trust, and no GATEKEEP_TRUST_KEY. The key goes
# into a throwaway volume through a helper, as this container's files aren't the host's.
say "release-verify as deployed."
docker volume create "$VOL" > /dev/null
docker run --rm -i --network none --user 0:0 --volume "$VOL:/trust" --entrypoint sh "$TOOLS" \
    -c 'cat > /trust/release-signing.pub && chmod 444 /trust/release-signing.pub' < "$WORK/trust-a/release-signing.pub"
out="$(docker run --rm --network "$NET" --user 10010:10010 --read-only --tmpfs /tmp:size=64m,mode=1777 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --volume "$VOL:/trust:ro" --env-file "$ENV_FILE" \
    --env GATEKEEP_REGISTRY_INSECURE=1 --env GATEKEEP_RELEASE_REHEARSAL=1 \
    "$TOOLS" 2>&1)" || { echo "$out" >&2; fail "release-verify as deployed refused the signed release."; }
echo "$out"
echo "$out" | grep -qF "every image is signed by the pinned key" || fail "release-verify as deployed didn't pass."
pass "release-verify as deployed passes the signed release."

say "refusals."
UNSIGNED="$(crane --insecure mutate "$SIGNED" --label org.gatekeep.rehearsal=unsigned \
    --tag "registry:5000/signed/gatekeep-openbao:unsigned")"
echo "$UNSIGNED" | grep -Eq '@sha256:[0-9a-f]{64}$' || fail "no unsigned image to test with: $UNSIGNED"
echo "GATEKEEP_OPENBAO_IMAGE=$UNSIGNED" > "$WORK/unsigned.env"
expect_refusal "an unsigned digest" "REFUSED GATEKEEP_OPENBAO_IMAGE $UNSIGNED" \
    verify "$WORK/unsigned.env" "$WORK/trust-a/release-signing.pub"

# The same digest, now signed by key A for openbao and this release, but never attested.
COSIGN_PASSWORD="" cosign sign --key "$WORK/keys-a/cosign.key" --allow-insecure-registry --allow-http-registry \
    --tlog-upload=false --yes -a org.gatekeep.service=openbao -a "org.gatekeep.release=$TAG" "$UNSIGNED" > /dev/null 2>&1 \
    || fail "couldn't sign the test image."
expect_refusal "a signed image with no SBOM attestation" "REFUSED GATEKEEP_OPENBAO_IMAGE $UNSIGNED: no SBOM attestation" \
    verify "$WORK/unsigned.env" "$WORK/trust-a/release-signing.pub"

echo "GATEKEEP_OPENBAO_IMAGE=$SIGNED_TOOLS" > "$WORK/slot.env"
expect_refusal "another service's repository in a slot" "isn't the gatekeep-openbao repository" \
    verify "$WORK/slot.env" "$WORK/trust-a/release-signing.pub"

# The signed release-tools image, with its signature and attestation, copied into the
# openbao repository: the digest is signed, but for release-tools.
TOOLS_HEX="${SIGNED_TOOLS##*sha256:}"
crane --insecure copy "$SIGNED_TOOLS" registry:5000/signed/gatekeep-openbao:swapped > /dev/null 2>&1 \
    || fail "couldn't copy release-tools into the openbao repository."
for suffix in sig att; do
    crane --insecure copy "registry:5000/signed/gatekeep-release-tools:sha256-$TOOLS_HEX.$suffix" \
        "registry:5000/signed/gatekeep-openbao:sha256-$TOOLS_HEX.$suffix" > /dev/null 2>&1 \
        || fail "couldn't copy the release-tools .$suffix."
done
SWAPPED="registry:5000/signed/gatekeep-openbao@sha256:$TOOLS_HEX"
printf 'GATEKEEP_OPENBAO_IMAGE=%s\nGATEKEEP_RELEASE_TOOLS_IMAGE=%s\n' "$SWAPPED" "$SIGNED_TOOLS" > "$WORK/swapped.env"
expect_refusal "a signed image in another service's slot" \
    "REFUSED GATEKEEP_OPENBAO_IMAGE $SWAPPED: no valid signature by the pinned key for gatekeep-openbao" \
    verify "$WORK/swapped.env" "$WORK/trust-a/release-signing.pub"

# The same archives, published again as another release.
publish "$WORK/dist-second" registry:5000/second GATEKEEP_RELEASE_TAG=v0.0.1-rehearsal \
    GATEKEEP_RELEASE_REHEARSAL=1 GATEKEEP_SIGNING_KEY="$WORK/keys-a/cosign.key" > /dev/null
printf 'GATEKEEP_OPENBAO_IMAGE=%s\n%s\n' "$SIGNED" "$(grep '^GATEKEEP_RELEASE_TOOLS_IMAGE=' "$WORK/dist-second/release.env")" > "$WORK/mixed.env"
grep -q "registry:5000/second/gatekeep-release-tools@" "$WORK/mixed.env" || fail "no second release to mix in."
expect_refusal "images from two releases" "aren't all signed for one release" \
    verify "$WORK/mixed.env" "$WORK/trust-a/release-signing.pub"

expect_refusal "a release signed by another key" "REFUSED GATEKEEP_OPENBAO_IMAGE $SIGNED" \
    verify "$ENV_FILE" "$WORK/trust-b/release-signing.pub"

echo "GATEKEEP_OPENBAO_IMAGE=registry:5000/signed/gatekeep-openbao:$TAG" > "$WORK/tag.env"
expect_refusal "a tag reference" "not pinned by digest" \
    verify "$WORK/tag.env" "$WORK/trust-a/release-signing.pub"

expect_refusal "a missing pinned key" "$WORK/missing/release-signing.pub" \
    verify "$ENV_FILE" "$WORK/missing/release-signing.pub"

expect_refusal "a software key outside the rehearsal" "isn't a hardware key" \
    publish "$WORK/dist" registry:5000/soft GATEKEEP_SIGNING_KEY="$WORK/keys-a/cosign.key"
if crane --insecure ls registry:5000/soft/gatekeep-openbao > /dev/null 2>&1; then
    fail "the refused software-key run pushed an image."
fi
pass "the refused software-key run pushed nothing."

sed -i "s/sha256:[0-9a-f]\{64\}/sha256:$(printf '0%.0s' $(seq 64))/" "$WORK/dist-drift/digests.txt"
expect_refusal "a pushed digest that differs from the build's" "Nothing is signed" \
    publish "$WORK/dist-drift" registry:5000/drift GATEKEEP_RELEASE_REHEARSAL=1 GATEKEEP_SIGNING_KEY="$WORK/keys-a/cosign.key"
if crane --insecure ls registry:5000/drift/gatekeep-openbao | grep -q '^sha256-'; then
    fail "the drifted release has a signature or attestation."
fi
[ ! -e "$WORK/dist-drift/release.env" ] || fail "the drifted release wrote release.env."
pass "the drifted release has no signature, attestation or release.env."

say "passed."
