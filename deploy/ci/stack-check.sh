#!/bin/sh
# Stack check (Stories 1.10, 1.11, 1.20, 12.7 and 1.30). Runs inside the stack container of deploy/compose.dev.yaml,
# never on the machine itself:
#
#   GATEKEEP_HOST_REPO=<this repository's path on the Docker host> \
#     docker compose -f deploy/compose.dev.yaml run --rm --build stack
#
# It installs the stack exactly as docs/install.md says, checks every service healthy,
# then checks what a unit test can't reach: the Master Key in no volume, image or
# environment; the hardening each container really runs with; no egress; the edge (Story
# 1.11): both of Caddy's sites over HTTPS through its published ports and every refusal,
# which container can reach which, Caddy's key files and its settings checks; PostgreSQL
# stopped; OpenBao stopped; the Master Key missing; and a rehearsal of the Master Key
# rotation in docs/runbooks/master-key-rotation.md, from prepare to rotate-transit-keys. Nothing here calls Cloudflare: Caddy
# uses its internal CA, and cloudflare mode is only validated, with no network. It always tears down, volumes and
# secrets included. Every wait polls for a defined state, with a deadline.
set -eu

[ -n "${GATEKEEP_HOST_REPO:-}" ] || { echo "stack-check: set GATEKEEP_HOST_REPO." >&2; exit 2; }
[ "$(pwd)" = "$GATEKEEP_HOST_REPO" ] && [ -f deploy/compose.yaml ] \
    || { echo "stack-check: run from the repository mounted at GATEKEEP_HOST_REPO." >&2; exit 2; }

ROOT="$GATEKEEP_HOST_REPO"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-gatekeep-stack-check}"
export GATEKEEP_SECRETS_DIR="${GATEKEEP_SECRETS_DIR:-./secrets-stack-check}"
# Compose resolves a relative secrets directory against deploy/, where compose.yaml is.
case "$GATEKEEP_SECRETS_DIR" in
    /*) SECRETS="$GATEKEEP_SECRETS_DIR" ;;
    *) SECRETS="$ROOT/deploy/${GATEKEEP_SECRETS_DIR#./}" ;;
esac

C="docker compose -f deploy/compose.yaml"
# The Master Key rotation overlay (Story 12.7), used only by the rehearsal.
R="$C -f deploy/compose.rotate.yaml"
BUSYBOX=busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
# This container's own image: it has Node, for HTTP checks and the key search.
TOOLS=gatekeep/tests:local
HOSTS="hosted admin worker"
BUILT="gatekeep/openbao:local gatekeep/hosted:local gatekeep/admin:local gatekeep/worker:local gatekeep/cli:local gatekeep/caddy:local"
# Caddy's two sites, as deploy/compose.yaml defaults them, and the host ports it publishes.
ZONE=gatekeep.localhost
ADMIN_HOST=admin.gatekeep-admin.localhost
HTTP_PORT="${GATEKEEP_HTTP_PORT:-80}"
HTTPS_PORT="${GATEKEEP_HTTPS_PORT:-443}"
unset GATEKEEP_TENANT_ZONE GATEKEEP_ADMIN_HOST

say() { echo "stack-check: $*"; }
fail() { echo "stack-check: FAIL $*" >&2; $C ps -a >&2 || true; $C logs --tail 40 >&2 || true; exit 1; }

cleanup() {
    $R --profile tools --profile setup --profile rotate down --volumes --remove-orphans > /dev/null 2>&1 || true
    # The secrets directory holds root-owned files, so a container removes it, through
    # its parent, which works whether the directory is relative or absolute.
    docker run --rm -v "$(dirname "$SECRETS"):/parent" "$BUSYBOX" rm -rf "/parent/$(basename "$SECRETS")" > /dev/null 2>&1 || true
}
trap cleanup EXIT

container() { $C ps -aq "$1"; }

# Polls "$@" every 2 seconds until it succeeds, for at most $1 seconds.
until_true() {
    limit="$1"
    shift
    waited=0
    until "$@"; do
        waited=$((waited + 2))
        [ "$waited" -le "$limit" ] || return 1
        sleep 2
    done
}

health_of() { docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1" 2> /dev/null; }

# "<status> <body>" of a host's /healthz, asked from inside that container's network namespace.
healthz() {
    docker run --rm --network "container:$(container "$1")" "$TOOLS" node -e '
        fetch("http://127.0.0.1:8081/healthz", { signal: AbortSignal.timeout(8000) })
            .then(async r => console.log(r.status, await r.text()))
            .catch(() => console.log("none"))'
}

healthz_is() { [ "$(healthz "$1")" = "$2" ]; }
host_health_is() { [ "$(health_of "$(container "$1")")" = "$2" ]; }

wait_healthz() {
    for host in $HOSTS; do
        until_true 90 healthz_is "$host" "$1" || fail "$host /healthz never answered '$1' (last: '$(healthz "$host")')."
        say "$host /healthz $1."
    done
}

wait_host_health() {
    for host in $HOSTS; do
        until_true 120 host_health_is "$host" "$1" || fail "$host never became $1."
        say "$host is $1."
    done
}

# Searches stdin, or a volume, for the Master Key. The key file is mounted read-only into
# the searching container only.
find_key() {
    docker run --rm -i -v "$SECRETS/master:/key:ro" -v "$ROOT/deploy/ci:/ci:ro" "$@"
}

cleanup

say "building images."
# One service at a time: built together, the .NET publishes run side by side and exhaust the
# memory of a small self-hosted runner, whose OOM killer then kills the whole check.
for service in $($C --profile tools --profile setup config --services); do
    $C --profile tools --profile setup build --quiet "$service"
done

say "install, as docs/install.md has it."
# The alert channel and the bucket (Story 1.30): placeholders under .invalid, which never resolve,
# so Host.Worker starts and nothing leaves. The secrets are random, so none is a known default.
export GATEKEEP_ALERT_URL=https://alerts.invalid/gatekeep/stack-check
export GATEKEEP_RECORDS_ENDPOINT=https://objects.invalid
export GATEKEEP_RECORDS_REGION=us-east-1
export GATEKEEP_RECORDS_BUCKET=gatekeep-stack-check
docker run --rm -v "$(dirname "$SECRETS"):/parent" "$BUSYBOX" sh -c '
    set -eu
    dir="/parent/$1"
    mkdir -p "$dir/alerts" "$dir/records"
    chmod 0700 "$dir/alerts" "$dir/records"
    for file in alerts/token records/access-key-id records/secret-access-key; do
        head -c 24 /dev/urandom | base64 | tr -d "\n" | tr "+/" "xy" > "$dir/$file"
        chmod 0444 "$dir/$file"
    done' sh "$(basename "$SECRETS")" || fail "couldn't write the placeholder alert and bucket secrets."
$C run --rm keygen
$C run --rm passwords
$C run --rm bootstrap-dir
$C up -d openbao
$C run --rm openbao-setup
$C run --rm cli migrate
$C up -d --wait || fail "the stack didn't come up healthy."

for service in postgres openbao $HOSTS; do
    state="$(health_of "$(container "$service")")"
    [ "$state" = healthy ] || fail "$service is '$state'."
done
[ "$(docker inspect --format '{{.State.ExitCode}} {{.State.Status}}' "$(container postgres-passwords)")" = "0 exited" ] \
    || fail "postgres-passwords didn't finish cleanly."
say "every service healthy."
wait_healthz "200 healthy"

say "audit verify, as gk_cli, finds every chain intact."
$C run --rm cli audit verify || fail "cli audit verify didn't exit 0."

say "init ensures the Deployment keys and writes a root-only bootstrap token, then reissues it."
# bootstrap-dir again: running it twice changes nothing.
$C run --rm bootstrap-dir > /dev/null || fail "bootstrap-dir didn't run a second time."
for run in issue reissue; do
    init_output="$($C run --rm cli init)" || fail "cli init ($run) didn't exit 0."
    echo "$init_output" | grep -q "bootstrap/bootstrap-token" || fail "cli init ($run) didn't name the token file."
    modes="$(docker run --rm -v "$SECRETS/bootstrap:/b:ro" "$BUSYBOX" stat -c '%a %u' /b /b/bootstrap-token | tr '\n' ' ')"
    [ "$modes" = "700 10004 600 10004 " ] \
        || fail "after $run the bootstrap token isn't 0600 in a 0700 directory owned by the cli uid ($modes)."
    # Checked inside the container, so the token itself is never printed here: its form, and
    # that init's captured output doesn't hold it.
    printf '%s\n' "$init_output" | docker run --rm -i -v "$SECRETS/bootstrap:/b:ro" "$BUSYBOX" sh -c \
        '[ "$(wc -c < /b/bootstrap-token)" -eq 65 ] && grep -qxE "[0-9a-f]{64}" /b/bootstrap-token && ! grep -qF -f /b/bootstrap-token' \
        || fail "after $run the bootstrap token isn't 64 lower-case hex characters and a newline, or init printed it."
done
[ "$(docker run --rm -v "$SECRETS/bootstrap:/b:ro" "$BUSYBOX" sh -c 'ls -A /b')" = bootstrap-token ] \
    || fail "init left files beside the bootstrap token."

# Fails unless the key at $1, a path under master/ in the secrets directory, is in no volume,
# built image or container environment of this project.
search_key() {
    key="/key/$1"
    for volume in $(docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
        find_key -v "$volume:/scan:ro" "$TOOLS" node /ci/find-key.mjs "$key" /scan \
            || fail "volume $volume holds the Master Key ($1)."
    done
    for image in $BUILT; do
        id="$(docker create "$image")"
        docker export "$id" | find_key "$TOOLS" node /ci/find-key.mjs "$key" - || { docker rm "$id" > /dev/null; fail "image $image holds the Master Key ($1)."; }
        docker rm "$id" > /dev/null
        docker history --no-trunc --format '{{.CreatedBy}}' "$image" | find_key "$TOOLS" node /ci/find-key.mjs "$key" - \
            || fail "the history of $image holds the Master Key ($1)."
    done
    for id in $(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
        docker inspect --format '{{json .Config.Env}}{{json .Config.Labels}}{{json .Config.Cmd}}' "$id" \
            | find_key "$TOOLS" node /ci/find-key.mjs "$key" - \
            || fail "container $id has the Master Key ($1) in its environment or configuration."
    done
}

say "the Master Key is in no volume, built image or container environment."
search_key master-key

say "hardening of each running container."
for service in $HOSTS caddy openbao-audit-shipper; do
    id="$(container "$service")"
    user="$(docker inspect --format '{{.Config.User}}' "$id")"
    case "$user" in "" | 0 | 0:* | root | root:*) fail "$service runs as root." ;; esac
    [ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$id")" = true ] || fail "$service root filesystem is writable."
    [ "$(docker inspect --format '{{.HostConfig.CapDrop}}' "$id")" = "[ALL]" ] || fail "$service keeps capabilities."
    [ "$(docker inspect --format '{{len .HostConfig.CapAdd}}' "$id")" = 0 ] || fail "$service adds capabilities."
    docker inspect --format '{{.HostConfig.SecurityOpt}}' "$id" | grep -q 'no-new-privileges:true' || fail "$service allows new privileges."
    if docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$id" | grep -q 'docker.sock'; then
        fail "$service has the Docker socket."
    fi
done
for id in $(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
    [ "$id" = "$(container caddy)" ] && continue
    [ "$(docker inspect --format '{{len .HostConfig.PortBindings}}' "$id")" = 0 ] || fail "container $id publishes a port."
done
[ "$(docker inspect --format '{{range $p, $b := .HostConfig.PortBindings}}{{$p}}={{range $b}}{{.HostPort}}{{end}} {{end}}' "$(container caddy)")" \
    = "8080/tcp=$HTTP_PORT 8443/tcp=$HTTPS_PORT " ] || fail "caddy publishes other than $HTTP_PORT and $HTTPS_PORT."
[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$(container openbao)")" = none ] || fail "openbao is on a network."

say "no egress from Host.Hosted or Host.Admin."
for service in hosted admin; do
    reached="$(docker run --rm --network "container:$(container "$service")" "$TOOLS" node -e '
        fetch("http://1.1.1.1/", { signal: AbortSignal.timeout(5000) })
            .then(() => console.log("reached"))
            .catch(() => console.log("refused"))')"
    [ "$reached" = refused ] || fail "$service reached the internet."
done

# Story 1.30: application egress is Host.Worker's and the audit shipper's alone, on the egress
# network beside only their own, and every request they make goes through EgressHttp.
networks_of() { docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$(container "$1")"; }
P="$COMPOSE_PROJECT_NAME"
[ "$(networks_of worker)" = "${P}_egress ${P}_worker " ] || fail "worker joins '$(networks_of worker)', not only egress and worker."
[ "$(networks_of openbao-audit-shipper)" = "${P}_egress " ] \
    || fail "openbao-audit-shipper joins '$(networks_of openbao-audit-shipper)', not only egress."
for service in hosted admin; do
    case "$(networks_of "$service")" in *"${P}_egress "*) fail "$service joins the egress network." ;; esac
done

say "the audit shipper reads the audit log through its group, which only it and OpenBao have."
[ "$(docker exec "$(container openbao)" stat -c '%a %U %G' /var/log/openbao /var/log/openbao/audit.log | tr '\n' ' ')" \
    = "2750 openbao openbao-audit 640 openbao openbao-audit " ] \
    || fail "the audit log isn't 0640 in a setgid 0750 directory, both of group openbao-audit."
for id in $(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
    name="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$id")"
    case "$name" in openbao | openbao-audit-shipper) continue ;; esac
    if docker inspect --format '{{range .Mounts}}{{.Name}} {{end}}' "$id" | grep -q "${P}_openbao-audit "; then
        fail "$name mounts the OpenBao audit volume."
    fi
    if docker inspect --format '{{.HostConfig.GroupAdd}}' "$id" | grep -q 4501; then
        fail "$name has the openbao-audit group."
    fi
done

# Fails unless cli alerts test to $1 exits 1 printing exactly the line $2.
alerts_test_prints() {
    if output="$($C run --rm -e GATEKEEP_ALERT_URL="$1" cli alerts test 2>&1)"; then
        fail "cli alerts test to $1 exited 0: $output"
    fi
    echo "$output" | grep -qxF "$2" || fail "cli alerts test to $1 didn't print '$2': $output"
}

say "cli alerts test refuses a private address, sending nothing."
for url in https://10.0.0.1/hook https://127.0.0.1/hook "https://[fd00::1]/hook" "https://[::ffff:192.168.1.1]/hook"; do
    alerts_test_prints "$url" "Alert channel refused: private address."
done
# host.docker.internal is the Docker host's own address where the name exists (Docker Desktop);
# where it doesn't, there is nothing to refuse.
if docker run --rm --network "${P}_egress" "$BUSYBOX" nslookup host.docker.internal > /dev/null 2>&1; then
    alerts_test_prints https://host.docker.internal/hook "Alert channel refused: private address."
else
    say "host.docker.internal doesn't resolve on the egress network here, so it isn't tried."
fi

say "cli alerts test reads the token secret and tries a public name: alerts.invalid never resolves."
alerts_test_prints https://alerts.invalid/hook "Alert channel unavailable."

# Story 1.30: the shipper read the audit file, which init's Transit calls wrote to, and tried the
# bucket at objects.invalid, which never resolves: the unavailable line, said once, and no restart.
shipper_tried() {
    docker logs "$(container openbao-audit-shipper)" 2>&1 \
        | grep -qxF "Off-server store unavailable: the audit file wasn't shipped. It will be tried again."
}
say "the audit shipper runs, reads the audit file and tries the bucket."
until_true 30 shipper_tried || fail "the audit shipper never tried the bucket: $(docker logs --tail 20 "$(container openbao-audit-shipper)" 2>&1)"
[ "$(docker inspect --format '{{.State.Status}} {{.RestartCount}}' "$(container openbao-audit-shipper)")" = "running 0" ] \
    || fail "the audit shipper isn't running, or restarted."
if docker logs "$(container openbao-audit-shipper)" 2>&1 | grep -qF "Can't read the audit file"; then
    fail "the audit shipper can't read the audit file."
fi

# --- The edge (Story 1.11) ---

# Caddy's internal root certificate, which is public, so the client can verify both sites.
CA_PEM="$(docker exec "$(container caddy)" cat /data/caddy/pki/authorities/local/root.crt)" \
    || fail "caddy has no internal root certificate."

# One request from a client container through the host's published ports, with the TLS
# name and Caddy's address pinned by --resolve. Arguments: scheme, name (or @ip, to connect
# by address with no TLS name), then any curl options. Prints
# "<curl exit> <status> <body bytes> <Set-Cookie count> <HSTS count> <Location>".
edge() {
    docker run --rm --add-host host.docker.internal:host-gateway -e CA_PEM="$CA_PEM" \
        -e HTTP_PORT="$HTTP_PORT" -e HTTPS_PORT="$HTTPS_PORT" "$TOOLS" sh -c '
        scheme="$1" name="$2"
        shift 2
        printf "%s\n" "$CA_PEM" > /tmp/ca.pem
        ip="$(getent ahostsv4 host.docker.internal | awk "NR == 1 { print \$1 }")"
        [ -n "$ip" ] || { echo "no address for host.docker.internal"; exit 0; }
        if [ "$scheme" = https ]; then port="$HTTPS_PORT"; else port="$HTTP_PORT"; fi
        if [ "$name" = @ip ]; then
            url="$scheme://$ip:$port/"
        else
            url="$scheme://$name:$port/"
            set -- --resolve "$name:$port:$ip" "$@"
        fi
        status="$(curl -s --max-time 10 --cacert /tmp/ca.pem -o /tmp/body -D /tmp/head -w "%{http_code}" "$url" "$@")"
        code=$?
        touch /tmp/body /tmp/head
        echo "$code $status $(wc -c < /tmp/body) $(grep -ci "^set-cookie:" /tmp/head) $(grep -ci "^strict-transport-security: max-age=31536000.\$" /tmp/head) $(sed -n "s/^[Ll]ocation: *//p" /tmp/head | tr -d "\r")"' \
        sh "$@"
}

# Fails unless "edge ..." prints what the first argument, a case pattern, says.
expect_edge() {
    want="$1"
    shift
    got="$(edge "$@")"
    case "$got" in $want) ;; *) fail "edge $*: got '$got', want '$want'." ;; esac
}

# Each site reaches its host and only it, with HSTS: Host.Hosted answers 404 with no body for
# now, and Host.Admin the Admin Dashboard's index.html (Story 1.20), so stopping one proves
# which one answers.
ADMIN_OK="0 200 [1-9]* 0 1 "
say "the Tenant zone reaches Host.Hosted and the Admin hostname Host.Admin, over HTTPS."
expect_edge "0 404 0 0 1 " https "acme.$ZONE"
expect_edge "$ADMIN_OK" https "$ADMIN_HOST"
for stopped in hosted admin; do
    $C stop "$stopped" > /dev/null
    if [ "$stopped" = hosted ]; then
        expect_edge "0 502 0 0 ? " https "acme.$ZONE"
        expect_edge "$ADMIN_OK" https "$ADMIN_HOST"
    else
        expect_edge "0 404 0 0 1 " https "acme.$ZONE"
        expect_edge "0 502 0 0 ? " https "$ADMIN_HOST"
    fi
    $C start "$stopped" > /dev/null
    until_true 120 host_health_is "$stopped" healthy || fail "$stopped didn't come back."
done

say "a Host header with a port, or in another case, is still the TLS name's own site."
expect_edge "0 404 0 0 1 " https "acme.$ZONE" -H "Host: acme.$ZONE:443"
expect_edge "0 404 0 0 1 " https "acme.$ZONE" -H "Host: ACME.$(echo "$ZONE" | tr 'a-z' 'A-Z')"
expect_edge "$ADMIN_OK" https "$ADMIN_HOST" -H "Host: $ADMIN_HOST:443"

# The response headers of GET https://$ADMIN_HOST/ through Caddy, CRs removed.
admin_headers() {
    docker run --rm --add-host host.docker.internal:host-gateway -e CA_PEM="$CA_PEM" \
        -e HTTPS_PORT="$HTTPS_PORT" "$TOOLS" sh -c '
        printf "%s\n" "$CA_PEM" > /tmp/ca.pem
        ip="$(getent ahostsv4 host.docker.internal | awk "NR == 1 { print \$1 }")"
        curl -s --max-time 10 --cacert /tmp/ca.pem --resolve "$1:$HTTPS_PORT:$ip" -o /dev/null -D - "https://$1:$HTTPS_PORT/" | tr -d "\r"' \
        sh "$ADMIN_HOST"
}

say "the Admin Dashboard arrives through Caddy with the AD-21 CSP, no referrer and framing denied (Story 1.20)."
ADMIN_CSP="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
heads="$(admin_headers)"
echo "$heads" | head -n 1 | grep -q "^HTTP/[0-9.]* 200" || fail "GET https://$ADMIN_HOST/ isn't 200: $heads"
for expected in \
    "content-security-policy: $ADMIN_CSP" \
    "referrer-policy: no-referrer" \
    "x-frame-options: DENY" \
    "x-content-type-options: nosniff"; do
    name="${expected%%:*}"
    got="$(echo "$heads" | grep -i "^$name:" || true)"
    [ "$(echo "$got" | grep -c .)" = 1 ] || fail "GET https://$ADMIN_HOST/ sends $name other than once: $heads"
    [ "$(echo "$got" | sed 's/^[^:]*: *//')" = "${expected#*: }" ] \
        || fail "GET https://$ADMIN_HOST/ sends '$got', want '$expected'."
done

say "other names, the zone apex, nested names and no TLS name at all get no TLS."
# A failed handshake is curl exit 35, with no response, even when the certificate is ignored.
for name in evil.example "$ZONE" "a.b.$ZONE" "x.$ADMIN_HOST" @ip; do
    expect_edge "35 000 0 0 0 " https "$name"
    expect_edge "35 000 0 0 0 " https "$name" --insecure
done
expect_edge "35 000 0 0 0 " https @ip --insecure -H "Host: $ADMIN_HOST"

say "a Host header other than the TLS name gets an empty 421: one site never reaches the other."
for host in "$ADMIN_HOST" "$(echo "$ADMIN_HOST" | tr 'a-z' 'A-Z')" evil.example "$ZONE" "b.$ZONE"; do
    expect_edge "0 421 0 0 0 " https "acme.$ZONE" -H "Host: $host"
done
for host in "acme.$ZONE" evil.example; do
    expect_edge "0 421 0 0 0 " https "$ADMIN_HOST" -H "Host: $host"
done

say "plain HTTP: a bare redirect for the two sites, nothing for any other name."
expect_edge "0 308 0 0 0 https://acme.$ZONE/" http "acme.$ZONE"
expect_edge "0 308 0 0 0 https://$ADMIN_HOST/" http "$ADMIN_HOST"
# The connection closes with no response: curl exit 52.
for name in evil.example "$ZONE" "a.b.$ZONE" "x.$ADMIN_HOST" @ip; do
    expect_edge "52 000 0 0 0 " http "$name"
done

# A request from inside one host's container to Caddy on its edge network, for the other
# host's site, with that site's TLS name and Host header. Prints like edge.
bridge() {
    docker run --rm --network "container:$(container "$1")" -e CA_PEM="$CA_PEM" "$TOOLS" sh -c '
        printf "%s\n" "$CA_PEM" > /tmp/ca.pem
        ip="$(getent ahostsv4 caddy | awk "NR == 1 { print \$1 }")"
        [ -n "$ip" ] || { echo "no address for caddy"; exit 0; }
        status="$(curl -s --max-time 10 --cacert /tmp/ca.pem --resolve "$1:8443:$ip" \
            -o /tmp/body -D /tmp/head -w "%{http_code}" "https://$1:8443/")"
        code=$?
        touch /tmp/body /tmp/head
        echo "$code $status $(wc -c < /tmp/body) $(grep -ci "^set-cookie:" /tmp/head)"' sh "$2"
}

say "neither host reaches the other's site through Caddy."
got="$(bridge hosted "$ADMIN_HOST")"
case "$got" in [1-9]*" 000 0 0") ;; *) fail "hosted got an answer from the Admin site through Caddy: '$got'." ;; esac
got="$(bridge admin "acme.$ZONE")"
case "$got" in [1-9]*" 000 0 0") ;; *) fail "admin got an answer from the Tenant site through Caddy: '$got'." ;; esac
# Each host's own site, through the same path, answers: the refusal is the other host's subnet.
[ "$(bridge hosted "acme.$ZONE")" = "0 404 0 0" ] || fail "hosted can't reach its own site through Caddy: '$(bridge hosted "acme.$ZONE")'."

# "open" or "closed": a TCP connection to host:port, from a container on the given --network.
reach() {
    docker run --rm --network "$1" "$TOOLS" node -e '
        const s = require("net").connect({ host: process.argv[1], port: +process.argv[2], timeout: 3000 });
        s.on("connect", () => { console.log("open"); s.destroy(); });
        s.on("timeout", () => { console.log("closed"); s.destroy(); });
        s.on("error", () => console.log("closed"));' "$2" "$3"
}

addresses() { docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$(container "$1")"; }

# Each service:port target, by name and by every address it has on any network, must be
# closed from the given --network.
expect_closed() {
    from="$1"
    shift
    for target in "$@"; do
        service="${target%:*}" port="${target#*:}"
        for address in "$service" $(addresses "$service"); do
            [ "$(reach "$from" "$address" "$port")" = closed ] || fail "$from reaches $address:$port ($service)."
        done
    done
}

say "Host.Hosted can't reach Host.Admin."
expect_closed "container:$(container hosted)" admin:8080 admin:8081

say "Caddy reaches the two public ports and nothing else."
for target in hosted admin; do
    [ "$(reach "container:$(container caddy)" "$target" 8080)" = open ] || fail "caddy can't reach $target:8080."
done
expect_closed "container:$(container caddy)" hosted:8081 admin:8081 worker:8080 worker:8081 postgres:5432 openbao:8200

say "Caddy's keys and config are its own."
caddy_id="$(container caddy)"
[ -n "$(docker exec "$caddy_id" find /data -name '*.key')" ] || fail "caddy holds no private key."
loose="$(docker exec "$caddy_id" sh -c 'find /data /config ! -user 10005; find /data /config -type d -perm /077; find /data /config -type f -perm /077')"
[ -z "$loose" ] || fail "caddy-data or caddy-config isn't Caddy's alone: $loose"
for id in $(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
    [ "$id" = "$caddy_id" ] && continue
    if docker inspect --format '{{range .Mounts}}{{.Name}} {{end}}' "$id" | grep -q 'caddy-'; then
        fail "container $id mounts a Caddy volume."
    fi
done

# Caddy's image, run alone with no network: only its settings checks and configuration.
# Secrets go on a tmpfs at the real path, so the shipped files run unchanged.
caddy_alone() {
    docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --tmpfs /data:uid=10005 --tmpfs /config:uid=10005 --tmpfs /tmp --tmpfs /run/secrets:uid=10005 "$@"
}

NAMES="-e GATEKEEP_TENANT_ZONE=id.gatekeep.invalid -e GATEKEEP_ADMIN_HOST=admin.gatekeep.invalid"
CLOUDFLARE="-e GATEKEEP_TLS_MODE=cloudflare -e GATEKEEP_ACME_EMAIL=ops@gatekeep.invalid
    -e GATEKEEP_ACME_CHALLENGE_DOMAIN=zone.validation.invalid -e GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN=admin.validation.invalid"
# The provider checks only the token's shape: 40 letters and digits.
WITH_TOKEN='echo notarealtokennotarealtokennotarealtoken0 > /run/secrets/cloudflare_dns_token && exec sh /etc/caddy/start.sh "$@"'

# Fails unless start.sh refuses the settings that follow the setting's name, naming it.
expect_refused() {
    setting="$1"
    shift
    # $NAMES and $CLOUDFLARE are split on purpose; a later -e wins over an earlier one.
    # shellcheck disable=SC2086
    if output="$(caddy_alone $NAMES "$@" gatekeep/caddy:local validate 2>&1)"; then
        fail "caddy accepted $setting from: $* ($output)"
    fi
    case "$output" in *"refusing to start"*"$setting"*) ;; *) fail "caddy refused without naming $setting: $output" ;; esac
}

say "Caddy refuses a bad setting before it runs, naming it."
LABEL63="$(printf '%063d' 0 | tr 0 a)"
INTERNAL="-e GATEKEEP_TLS_MODE=internal"
# shellcheck disable=SC2086
{
    for admin in "admin.$ZONE" "$ZONE" "a.b.$ZONE"; do
        expect_refused GATEKEEP_ADMIN_HOST $INTERNAL -e GATEKEEP_TENANT_ZONE="$ZONE" -e GATEKEEP_ADMIN_HOST="$admin"
    done
    expect_refused GATEKEEP_ADMIN_HOST $INTERNAL -e GATEKEEP_ADMIN_HOST=admin.id.gatekeep.invalid
    for bad in Admin.gatekeep.invalid localhost "$(printf 'a.invalid\nb.invalid')" "{env.HOME}.invalid" 10.0.0.1 \
        "$LABEL63.$LABEL63.$LABEL63.$LABEL63.invalid" "a.-b.invalid" ""; do
        expect_refused GATEKEEP_ADMIN_HOST $INTERNAL -e GATEKEEP_ADMIN_HOST="$bad"
    done
    expect_refused GATEKEEP_TENANT_ZONE $INTERNAL -e GATEKEEP_TENANT_ZONE=x.admin.gatekeep.invalid
    expect_refused GATEKEEP_TENANT_ZONE $INTERNAL -e GATEKEEP_TENANT_ZONE="$(printf 'id.gatekeep.invalid\n}')"
    expect_refused GATEKEEP_TLS_MODE -e GATEKEEP_TLS_MODE=public
    expect_refused GATEKEEP_TLS_MODE -e GATEKEEP_TLS_MODE=
    for email in "" ops@ @gatekeep.invalid "ops@gatekeep" "a b@gatekeep.invalid" "a{b}@gatekeep.invalid" \
        "ops@gatekeep.invalid@x.invalid" "$(printf 'ops@gatekeep.invalid\nx')"; do
        expect_refused GATEKEEP_ACME_EMAIL $CLOUDFLARE -e GATEKEEP_ACME_EMAIL="$email"
    done
    expect_refused GATEKEEP_ACME_CHALLENGE_DOMAIN $CLOUDFLARE -e GATEKEEP_ACME_CHALLENGE_DOMAIN=
    expect_refused GATEKEEP_ACME_CHALLENGE_DOMAIN $CLOUDFLARE -e GATEKEEP_ACME_CHALLENGE_DOMAIN=x.id.gatekeep.invalid
    expect_refused GATEKEEP_ACME_CHALLENGE_DOMAIN $CLOUDFLARE -e GATEKEEP_ACME_CHALLENGE_DOMAIN=admin.gatekeep.invalid
    expect_refused GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN $CLOUDFLARE -e GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN=
    expect_refused GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN $CLOUDFLARE -e GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN=x.admin.gatekeep.invalid
    expect_refused GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN $CLOUDFLARE -e GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN=id.gatekeep.invalid
    expect_refused "are the same" $CLOUDFLARE -e GATEKEEP_ADMIN_ACME_CHALLENGE_DOMAIN=zone.validation.invalid
    # No token file at all, then one holding only whitespace.
    expect_refused cloudflare_dns_token $CLOUDFLARE
    if output="$(caddy_alone $NAMES $CLOUDFLARE --entrypoint sh gatekeep/caddy:local -c \
        'printf " \n\t\n" > /run/secrets/cloudflare_dns_token && exec sh /etc/caddy/start.sh validate' 2>&1)"; then
        fail "caddy accepted a DNS token of whitespace: $output"
    fi
    case "$output" in *"refusing to start"*cloudflare_dns_token*) ;; *) fail "caddy refused a whitespace token without naming it: $output" ;; esac
}

say "Caddy's cloudflare mode validates offline, with a placeholder token at the real path."
# shellcheck disable=SC2086
output="$(caddy_alone $NAMES $CLOUDFLARE --entrypoint sh gatekeep/caddy:local -c "$WITH_TOKEN" sh validate 2>&1)" \
    || fail "Caddy's cloudflare mode doesn't validate: $output"
# Each site's policy writes its challenge records under its own validation-only name.
# shellcheck disable=SC2086
config="$(caddy_alone $NAMES $CLOUDFLARE --entrypoint sh gatekeep/caddy:local -c "$WITH_TOKEN" sh adapt 2> /dev/null)" \
    || fail "Caddy's cloudflare mode doesn't adapt."
policies="$(echo "$config" | docker run --rm -i "$TOOLS" node -e '
    let input = "";
    process.stdin.on("data", d => input += d).on("end", () => {
        const policies = JSON.parse(input).apps.tls.automation.policies;
        for (const p of policies) {
            const domains = [...new Set(p.issuers.map(i => i.challenges.dns.override_domain))];
            const tokens = [...new Set(p.issuers.map(i => i.challenges.dns.provider.api_token))];
            console.log(`${p.subjects.join(",")}=${domains.join(",")}:${tokens.join(",")}`);
        }
    });')"
expected="*.id.gatekeep.invalid=zone.validation.invalid:{file./run/secrets/cloudflare_dns_token}
admin.gatekeep.invalid=admin.validation.invalid:{file./run/secrets/cloudflare_dns_token}"
[ "$(echo "$policies" | sort)" = "$(echo "$expected" | sort)" ] \
    || fail "cloudflare mode's TLS policies aren't one per site with its own challenge domain: $policies"

say "PostgreSQL stopped."
$C stop postgres > /dev/null
wait_healthz "503 unhealthy: database"
wait_host_health unhealthy
$C start postgres > /dev/null
wait_healthz "200 healthy"
wait_host_health healthy

say "OpenBao stopped."
$C stop openbao > /dev/null
wait_healthz "503 unhealthy: custody"

say "OpenBao without its Master Key."
docker run --rm -v "$SECRETS/master:/m" "$BUSYBOX" mv /m/master-key /m/master-key.aside
$C rm -fs openbao > /dev/null
# Two outcomes count as a refusal, and anything else fails: Compose refuses to create the
# container because the secret file is missing, or it creates one that refuses on the seal.
if output="$($C up -d --no-deps openbao 2>&1)"; then
    openbao="$(container openbao)"
    [ -n "$openbao" ] || fail "Compose reported success but no openbao container exists."
    refused() { docker logs "$openbao" 2>&1 | grep -q 'seal "static"'; }
    until_true 60 refused || fail "openbao didn't refuse on the seal."
    [ "$(health_of "$openbao")" != healthy ] || fail "openbao is healthy with no Master Key."
    say "openbao started and refused on the seal."
else
    echo "$output" | grep -q 'master-key\|master_key' || fail "Compose failed for another reason: $output"
    [ -z "$($C ps -q openbao)" ] || fail "openbao is running with no Master Key."
    say "Compose refused to create openbao without its Master Key file."
fi
$C rm -fs openbao > /dev/null
# Compose leaves an empty directory where the missing secret file was.
docker run --rm -v "$SECRETS/master:/m" "$BUSYBOX" sh -c 'rm -rf /m/master-key && mv /m/master-key.aside /m/master-key'
$C up -d --wait openbao || fail "openbao didn't come back with its Master Key."
wait_healthz "200 healthy"

# --- Master Key rotation rehearsal (Story 12.7), as docs/runbooks/master-key-rotation.md has it ---

say "rotation rehearsal: every chain intact before it."
$C run --rm cli audit verify > /dev/null || fail "audit verify failed before the rotation."

say "rotation rehearsal: prepare."
prepared="$($R run --rm master-key-rotate prepare)" || fail "master-key-rotate prepare didn't exit 0."
echo "$prepared" | grep -q "moved generation 1 to /secrets/previous/master-key" || fail "prepare didn't move generation 1: $prepared"
echo "$prepared" | grep -q "wrote generation 2 to /secrets/master-key" || fail "prepare didn't write generation 2: $prepared"
echo "$prepared" | grep -qE "master-key-gen2-[0-9]{4}-[0-9]{2}-[0-9]{2}" || fail "prepare printed no escrow label: $prepared"
if $R run --rm master-key-rotate prepare > /dev/null 2>&1; then
    fail "a second prepare ran while master/previous/ held a key."
fi
[ "$(docker run --rm -v "$SECRETS/master:/m:ro" "$BUSYBOX" sh -c 'cat /m/master-key-id /m/previous/master-key-id' | tr '\n' ' ')" \
    = "gatekeep-master-2 gatekeep-master-1 " ] || fail "the key IDs aren't generation 2 current and 1 previous."

say "rotation rehearsal: the root step refuses outside rotation mode, before reading a share."
if output="$(echo | $R run --rm -T master-key-rotate-root 2>&1)"; then
    fail "the root step ran outside rotation mode."
fi
case "$output" in *"isn't in rotation mode"*"No share was read"*) ;; *) fail "the root step refused for another reason: $output" ;; esac

say "rotation rehearsal: OpenBao in rotation mode."
$R up -d --wait openbao || fail "openbao didn't come up healthy in rotation mode."
wait_healthz "200 healthy"

say "rotation rehearsal: both generations are in no volume, image or container environment."
search_key master-key
search_key previous/master-key

say "rotation rehearsal: the root step, with the stack's own recovery shares."
rooted="$(docker run --rm -v "$SECRETS/recovery:/r:ro" "$BUSYBOX" cat /r/openbao-init.json \
    | $R run --rm -T master-key-rotate-root)" || fail "the root step didn't exit 0."
echo "$rooted" | grep -q "the key term is now 2" || fail "the root step didn't report key term 2: $rooted"
# Checked inside a container, so no share is printed here: none is in the step's output.
printf '%s\n' "$rooted" | docker run --rm -i -v "$SECRETS/recovery:/r:ro" "$BUSYBOX" sh -c '
    sed -n "/recovery_keys_b64/,/]/p" /r/openbao-init.json | grep -o "\"[A-Za-z0-9+/=]*\"" | tr -d "\"" > /tmp/shares
    [ "$(grep -c . /tmp/shares)" -eq 5 ] && ! grep -qF -f /tmp/shares' \
    || fail "the root step printed a recovery share, or the escrow file doesn't hold five."

say "rotation rehearsal: OpenBao back in base mode, on generation 2 alone, then finish."
$C up -d --wait openbao || fail "openbao didn't come up healthy on generation 2 alone."
# Kept aside for the check that generation 1 alone stays sealed, then shredded.
docker run --rm -v "$SECRETS/master:/m" "$BUSYBOX" cp -p /m/previous/master-key /m/.generation-1-check
finished="$($R run --rm master-key-rotate finish)" || fail "master-key-rotate finish didn't exit 0."
echo "$finished" | grep -q "keep that generation escrowed until the last backup" || fail "finish didn't print the retirement rule: $finished"
[ -z "$(docker run --rm -v "$SECRETS/master:/m:ro" "$BUSYBOX" ls -A /m/previous)" ] || fail "finish left files in master/previous/."

say "rotation rehearsal: rotate-transit-keys, twice."
for run in 1 2; do
    rotated="$($C run --rm cli rotate-transit-keys)" || fail "cli rotate-transit-keys (run $run) didn't exit 0."
    [ "$rotated" = "Rotated 2 Transit keys for the Deployment and 0 Tenants, and skipped 0 that don't exist." ] \
        || fail "rotate-transit-keys (run $run) printed '$rotated'."
done

say "rotation rehearsal: every service healthy, and every chain intact."
$C up -d --wait || fail "the stack isn't healthy after the rotation."
wait_healthz "200 healthy"
$C run --rm cli audit verify > /dev/null || fail "audit verify failed after the rotation."

say "rotation rehearsal: generation 1 alone, with its own ID, stays sealed."
$C stop openbao > /dev/null
docker run --rm -v "$SECRETS/master:/m" "$BUSYBOX" sh -c '
    mv /m/master-key /m/.generation-2 && mv /m/master-key-id /m/.generation-2-id
    mv /m/.generation-1-check /m/master-key && echo gatekeep-master-1 > /m/master-key-id'
$C rm -fs openbao > /dev/null
$C up -d --no-deps openbao > /dev/null 2>&1 || fail "Compose didn't create openbao with generation 1."
old_key_refused() { docker logs "$(container openbao)" 2>&1 | grep -q 'unknown key id'; }
until_true 60 old_key_refused || fail "openbao with generation 1 alone didn't refuse its data."
[ "$(health_of "$(container openbao)")" != healthy ] || fail "openbao is healthy on generation 1 alone."
$C rm -fs openbao > /dev/null
docker run --rm -v "$SECRETS/master:/m" "$BUSYBOX" sh -c '
    chmod u+w /m/master-key && shred -u /m/master-key && rm -f /m/master-key-id
    mv /m/.generation-2 /m/master-key && mv /m/.generation-2-id /m/master-key-id'
$C up -d --wait openbao || fail "openbao didn't come back on generation 2."
$C up -d --wait || fail "the stack isn't healthy after the old-key check."
wait_healthz "200 healthy"
say "rotation rehearsal passed."

say "passed."
