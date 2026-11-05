# OpenBao 2.7.2 for Gatekeep key custody (AD-10), as the openbao Compose service, and the
# image the openbao-setup, keygen and Master Key rotation services run their scripts from.
# Base image pinned by digest.
#
# It adds only what the stack needs: the gatekeep-custody group (gid 4500), which owns the
# socket, directories whose ownership the named volumes copy on first use, and the config
# template, scripts and policies. No key, token or ID is ever in this image: the Master Key
# and its ID arrive at runtime as the Compose secrets master_key and master_key_id, and
# start-openbao.sh renders the server config from them onto the /tmp tmpfs (Story 12.7).

FROM openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f

USER root
RUN addgroup -S -g 4500 gatekeep-custody \
    && addgroup openbao gatekeep-custody \
    && mkdir -p /var/lib/openbao/data /run/openbao /var/log/openbao /opt/gatekeep/openbao/policies \
    && chown openbao:openbao /var/lib/openbao /var/lib/openbao/data /var/log/openbao \
    && chmod 0700 /var/lib/openbao /var/lib/openbao/data /var/log/openbao \
    && chown openbao:gatekeep-custody /run/openbao \
    && chmod 0750 /run/openbao

COPY deploy/openbao/openbao.hcl /etc/openbao/openbao.hcl
COPY deploy/openbao/start-openbao.sh deploy/openbao/setup.sh deploy/openbao/generate-master-key.sh \
    deploy/openbao/rotate-master-key.sh deploy/openbao/rotate-root-key.sh /opt/gatekeep/openbao/
COPY deploy/openbao/policies/ /opt/gatekeep/openbao/policies/

USER openbao
ENTRYPOINT ["sh", "/opt/gatekeep/openbao/start-openbao.sh"]
