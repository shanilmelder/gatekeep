#!/bin/sh
# Test only. Stands in for Compose running the openbao service in deploy/compose.yaml:
# the gatekeep-custody group (gid 4500) and socket directory that deploy/docker/openbao.Dockerfile
# makes, the keygen service writing the Master Key and its ID into the bind-mounted secrets
# directory, and Compose mounting them read-only at /run/secrets/master_key and
# /run/secrets/master_key_id. Then it runs the image's own entrypoint, start-openbao.sh.
#
# Rotation mode (Story 12.7): while /opt/gatekeep/test/rotation-mode exists, or with
# GATEKEEP_TEST_ROTATION_MODE=1 from the first start, it also mounts
# previous/ as deploy/compose.rotate.yaml does, at master_key_previous and master_key_previous_id.
set -eu

KEY_DIR=/secrets

addgroup -S -g 4500 gatekeep-custody 2> /dev/null || true
addgroup openbao gatekeep-custody 2> /dev/null || true
# Story 1.30: the openbao-audit group (gid 4501) and the audit log directory, as the image makes them.
addgroup -S -g 4501 openbao-audit 2> /dev/null || true
addgroup openbao openbao-audit 2> /dev/null || true
mkdir -p /var/lib/openbao/data /run/openbao /var/log/openbao
chown openbao:openbao /var/lib/openbao /var/lib/openbao/data
chown openbao:openbao-audit /var/log/openbao
chmod 2750 /var/log/openbao
chown openbao:gatekeep-custody /run/openbao
chmod 0750 /run/openbao

# Only on the first start, as the keygen step would, so a restart never makes a new key.
if [ "${GATEKEEP_TEST_GENERATE_KEY:-1}" = 1 ] && [ ! -e /var/lib/openbao/.first-start-done ]; then
    sh /opt/gatekeep/openbao/generate-master-key.sh "$KEY_DIR/master-key"
    touch /var/lib/openbao/.first-start-done
fi

# A Compose secret: the file, read-only, readable by openbao alone. Fresh on each start. A
# missing file is absent, and a directory stays an empty directory, as Compose leaves them.
secret() {
    if [ -f "$1" ]; then
        install -o openbao -g openbao -m 0400 "$1" "/run/secrets/$2"
    elif [ -d "$1" ]; then
        mkdir "/run/secrets/$2"
    fi
}

rm -rf /run/secrets
mkdir -p /run/secrets
secret "$KEY_DIR/master-key" master_key
secret "$KEY_DIR/master-key-id" master_key_id
if [ -e /opt/gatekeep/test/rotation-mode ] || [ "${GATEKEEP_TEST_ROTATION_MODE:-0}" = 1 ]; then
    secret "$KEY_DIR/previous/master-key" master_key_previous
    secret "$KEY_DIR/previous/master-key-id" master_key_previous_id
fi
[ -n "$(ls -A /run/secrets)" ] || rm -rf /run/secrets

exec su-exec openbao sh /opt/gatekeep/openbao/start-openbao.sh -config=/etc/openbao/test-listener.hcl
