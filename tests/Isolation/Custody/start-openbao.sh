#!/bin/sh
# Test only. Stands in for systemd running deploy/openbao/openbao.service in a container:
# the openbao user and socket group, the key volume, and LoadCredential= copying the
# root-only Master Key into the service's credential directory on every start.
set -eu

KEY_FILE=/srv/gatekeep/keys/master-key
CREDENTIALS_DIRECTORY=/run/credentials/openbao.service

addgroup -S gatekeep-custody 2> /dev/null || true
addgroup openbao gatekeep-custody 2> /dev/null || true
mkdir -p /srv/gatekeep/keys /var/lib/openbao/data /run/openbao /var/log/openbao
chmod 0700 /srv/gatekeep/keys
chown openbao:openbao /var/lib/openbao /var/lib/openbao/data /run/openbao /var/log/openbao

# Only on the first start, as an install step would, so a restart never makes a new key.
if [ "${GATEKEEP_TEST_GENERATE_KEY:-1}" = 1 ] && [ ! -e /var/lib/openbao/.first-start-done ]; then
    sh /opt/gatekeep/openbao/generate-master-key.sh "$KEY_FILE"
    touch /var/lib/openbao/.first-start-done
fi

# LoadCredential=master-key:/srv/gatekeep/keys/master-key, fresh on each start.
rm -rf "$CREDENTIALS_DIRECTORY"
if [ -e "$KEY_FILE" ]; then
    mkdir -p "$CREDENTIALS_DIRECTORY"
    install -o openbao -g openbao -m 0400 "$KEY_FILE" "$CREDENTIALS_DIRECTORY/master-key"
fi

exec su-exec openbao bao server -config=/etc/openbao/openbao.hcl -config=/etc/openbao/test-listener.hcl
