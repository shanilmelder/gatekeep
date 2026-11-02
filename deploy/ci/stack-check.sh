#!/bin/sh
# Stack check (Stories 1.10 and 1.11). Runs inside the stack container of deploy/compose.test.yaml,
# never on the machine itself:
#
#   GATEKEEP_HOST_REPO=<this repository's path on the Docker host> \
#     docker compose -f deploy/compose.test.yaml run --rm --build stack
#
# It installs the stack exactly as docs/install.md says, checks every service healthy,
# then checks what a unit test can't reach: the Master Key in no volume, image or
# environment; the hardening each container really runs with; no egress; the edge (Story
# 1.11): both of Caddy's sites over HTTPS through its published ports and every refusal,
# which container can reach which, Caddy's key files and its settings checks; PostgreSQL
# stopped; OpenBao stopped; the Master Key missing. Nothing here calls Cloudflare: Caddy
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
    $C --profile tools --profile setup down --volumes --remove-orphans > /dev/null 2>&1 || true
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
$C --profile tools --profile setup build --quiet

say "install, as docs/install.md has it."
$C run --rm keygen
$C run --rm passwords
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

say "the Master Key is in no volume, built image or container environment."
for volume in $(docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
    find_key -v "$volume:/scan:ro" "$TOOLS" node /ci/find-key.mjs /key/master-key /scan \
        || fail "volume $volume holds the Master Key."
done
for image in $BUILT; do
    id="$(docker create "$image")"
    docker export "$id" | find_key "$TOOLS" node /ci/find-key.mjs /key/master-key - || { docker rm "$id" > /dev/null; fail "image $image holds the Master Key."; }
    docker rm "$id" > /dev/null
    docker history --no-trunc --format '{{.CreatedBy}}' "$image" | find_key "$TOOLS" node /ci/find-key.mjs /key/master-key - \
        || fail "the history of $image holds the Master Key."
done
for id in $(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"); do
    docker inspect --format '{{json .Config.Env}}{{json .Config.Labels}}{{json .Config.Cmd}}' "$id" \
        | find_key "$TOOLS" node /ci/find-key.mjs /key/master-key - \
        || fail "container $id has the Master Key in its environment or configuration."
done

say "hardening of each running container."
for service in $HOSTS caddy; do
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

say "no egress from any host."
for service in $HOSTS; do
    reached="$(docker run --rm --network "container:$(container "$service")" "$TOOLS" node -e '
        fetch("http://1.1.1.1/", { signal: AbortSignal.timeout(5000) })
            .then(() => console.log("reached"))
            .catch(() => console.log("refused"))')"
    [ "$reached" = refused ] || fail "$service reached the internet."
done

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

# Each site reaches its host and only it, with HSTS: both hosts answer 404 with no body for
# now, so stopping one proves which one answers.
say "the Tenant zone reaches Host.Hosted and the Admin hostname Host.Admin, over HTTPS."
expect_edge "0 404 0 0 1 " https "acme.$ZONE"
expect_edge "0 404 0 0 1 " https "$ADMIN_HOST"
for stopped in hosted admin; do
    $C stop "$stopped" > /dev/null
    if [ "$stopped" = hosted ]; then
        expect_edge "0 502 0 0 ? " https "acme.$ZONE"
        expect_edge "0 404 0 0 1 " https "$ADMIN_HOST"
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
expect_edge "0 404 0 0 1 " https "$ADMIN_HOST" -H "Host: $ADMIN_HOST:443"

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

say "passed."
