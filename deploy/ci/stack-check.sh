#!/bin/sh
# Stack check (Story 1.10). Runs inside the stack container of deploy/compose.test.yaml,
# never on the machine itself:
#
#   GATEKEEP_HOST_REPO=<this repository's path on the Docker host> \
#     docker compose -f deploy/compose.test.yaml run --rm --build stack
#
# It installs the stack exactly as docs/install.md says, checks every service healthy,
# then checks what a unit test can't reach: the Master Key in no volume, image or
# environment; the hardening each container really runs with; no egress; PostgreSQL
# stopped; OpenBao stopped; the Master Key missing. It always tears down, volumes and
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
BUILT="gatekeep/openbao:local gatekeep/hosted:local gatekeep/admin:local gatekeep/worker:local gatekeep/cli:local"

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
for service in $HOSTS; do
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
    [ "$(docker inspect --format '{{len .NetworkSettings.Ports}}' "$id")" = 0 ] || fail "$service publishes a port."
done
[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$(container openbao)")" = none ] || fail "openbao is on a network."

say "no egress from any host."
for service in $HOSTS; do
    reached="$(docker run --rm --network "container:$(container "$service")" "$TOOLS" node -e '
        fetch("http://1.1.1.1/", { signal: AbortSignal.timeout(5000) })
            .then(() => console.log("reached"))
            .catch(() => console.log("refused"))')"
    [ "$reached" = refused ] || fail "$service reached the internet."
done

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
