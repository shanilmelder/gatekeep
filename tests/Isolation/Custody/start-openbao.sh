#!/bin/sh
# Test only. Stands in for Compose running the openbao service in deploy/compose.yaml:
# the gatekeep-custody group (gid 4500) and socket directory that deploy/docker/openbao.Dockerfile
# makes, the keygen service writing the Master Key into the bind-mounted secrets
# directory, and Compose mounting that file read-only at /run/secrets/master_key.
set -eu

KEY_FILE=/secrets/master-key
SECRET_FILE=/run/secrets/master_key

addgroup -S -g 4500 gatekeep-custody 2> /dev/null || true
addgroup openbao gatekeep-custody 2> /dev/null || true
mkdir -p /var/lib/openbao/data /run/openbao /var/log/openbao
chown openbao:openbao /var/lib/openbao /var/lib/openbao/data /var/log/openbao
chown openbao:gatekeep-custody /run/openbao
chmod 0750 /run/openbao

# Only on the first start, as the keygen step would, so a restart never makes a new key.
if [ "${GATEKEEP_TEST_GENERATE_KEY:-1}" = 1 ] && [ ! -e /var/lib/openbao/.first-start-done ]; then
    sh /opt/gatekeep/openbao/generate-master-key.sh "$KEY_FILE"
    touch /var/lib/openbao/.first-start-done
fi

# The Compose secret: the key file, read-only, readable by openbao alone. Fresh on each
# start, and absent when the key file is, as Compose would leave it.
rm -rf /run/secrets
if [ -e "$KEY_FILE" ]; then
    mkdir -p /run/secrets
    install -o openbao -g openbao -m 0400 "$KEY_FILE" "$SECRET_FILE"
fi

exec su-exec openbao bao server -config=/etc/openbao/openbao.hcl -config=/etc/openbao/test-listener.hcl
