# Caddy 2.11.7 with the caddy-dns/cloudflare module, the only service that publishes ports:
# the Tenant zone and Admin sites (deploy/caddy/Caddyfile, AD-26). Both bases are pinned by
# digest and the module by exact version, whose Go module hashes the build checks against
# the Go checksum database.
#
# Caddy listens on 8080 and 8443 and needs no capability. The binary must carry no file
# capability: cap_net_bind_service can't be granted under cap_drop: [ALL], so it wouldn't
# even start. xcaddy is told not to set it, the final stage removes any that a builder
# carried over from the upstream binary it replaces, and the build fails if one is left.
# Caddy runs as a uid of its own, and the data and config directories, which the named
# volumes copy on first use, are its alone (0700): certificate private keys live only there.

FROM caddy:2.11.7-builder-alpine@sha256:95a5e7e2692b5eb9545aadc5b90a39f6f509bee59c9508a493f83ee902eaef63 AS build
RUN XCADDY_SETCAP=0 xcaddy build v2.11.7 --with github.com/caddy-dns/cloudflare@v0.2.4 --output /out/caddy

FROM caddy:2.11.7-alpine@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5

COPY --from=build /out/caddy /usr/bin/caddy
# getcap must exist and succeed, so an error can't pass for "no capability".
RUN command -v getcap > /dev/null \
    && caps="$(getcap /usr/bin/caddy)" \
    && { [ -z "$caps" ] || setcap -r /usr/bin/caddy; } \
    && caps="$(getcap /usr/bin/caddy)" \
    && [ -z "$caps" ] \
    && addgroup -S -g 10005 gatekeep-caddy \
    && adduser -S -D -H -u 10005 -G gatekeep-caddy gatekeep-caddy \
    && mkdir -p /data/caddy /config/caddy \
    && chown -R 10005:10005 /data /config \
    && chmod -R 0700 /data /config

COPY deploy/caddy/ /etc/caddy/

USER 10005:10005
# start.sh checks the settings, refusing an Admin hostname under the Tenant zone, then runs Caddy.
ENTRYPOINT ["sh", "/etc/caddy/start.sh"]
