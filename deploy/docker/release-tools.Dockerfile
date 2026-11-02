# Release tools (Story 12.5, docs/release-signing.md): cosign, crane and syft, plus the
# Docker CLI with buildx, and the scripts in deploy/release. One image for three jobs:
#
#   - build.sh, in the secret-free CI build job: builds each release image to an OCI
#     archive, writes its SPDX SBOM and records its digest.
#   - verify.sh, as the release-verify service of deploy/compose.release.yaml: checks every
#     image digest in release.env against the public key pinned on the Docker host.
#   - the CI rehearsal (deploy/ci/release-check.sh), which runs all three scripts.
#
# The signing job doesn't use this image: it never runs anything the build job made.
# Every base and every tool image is pinned by digest. No key is ever in this image: the
# pinned public key is bind-mounted read-only at /trust at runtime.

FROM ghcr.io/sigstore/cosign/cosign:v2.6.5@sha256:ad281047f85c5e1fc6ffbc30c2b55be3b07b4032bef715a12122ce5829619aca AS cosign
FROM gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1 AS crane
FROM anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a AS syft
FROM docker:29.8.1-cli@sha256:018edbc908e08fcc9dbf029c812c34251e9b4719e6f71ca0e5eae2a987d014ca AS docker

FROM busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec

COPY --from=docker /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=crane /ko-app/crane /usr/local/bin/crane
COPY --from=syft /syft /usr/local/bin/syft
COPY deploy/release/ /opt/gatekeep/release/

# Tools keep their state under /tmp, which is a tmpfs in release-verify. No update checks.
ENV HOME=/tmp \
    SYFT_CHECK_FOR_APP_UPDATE=false

# A uid of its own, distinct from every Gatekeep service.
USER 10010:10010

ENTRYPOINT ["sh", "/opt/gatekeep/release/verify.sh"]
