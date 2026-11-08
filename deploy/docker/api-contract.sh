#!/bin/sh
# The Admin API contract (Story 1.21), from the repository root inside the tests container.
#
#   sh deploy/docker/api-contract.sh             Fails if docs/api/openapi-v1.json isn't the
#                                                 document the last `dotnet build` generated from
#                                                 Host.Admin's endpoints, or if
#                                                 packages/api-client/src/schema.generated.ts isn't
#                                                 what openapi-typescript generates from it.
#   sh deploy/docker/api-contract.sh --self-check Proves the check fails, with the regenerate hint,
#                                                 when either committed file differs by one byte.
#   sh deploy/docker/api-contract.sh --write DIR  Builds Host.Admin, then writes both files into
#                                                 the repository mounted at DIR.
#
# Regenerate both after changing an endpoint, in Docker only, with the repository mounted:
#   docker compose -f deploy/compose.dev.yaml run --rm --build -v "<repository>:/out" tests sh deploy/docker/api-contract.sh --write /out
set -eu

generated=src/Gatekeep.Host.Admin/obj/openapi/openapi.json
# The committed files. The self-check points these at altered copies.
document="${API_CONTRACT_DOCUMENT:-docs/api/openapi-v1.json}"
client="${API_CONTRACT_CLIENT:-packages/api-client/src/schema.generated.ts}"
regenerate='docker compose -f deploy/compose.dev.yaml run --rm --build -v "<repository>:/out" tests sh deploy/docker/api-contract.sh --write /out'
hint="Regenerate both in Docker:"

# openapi-typescript's output for a document, as the api-client package runs it.
generate_client() {
  pnpm --silent --filter @gatekeep/api-client exec openapi-typescript "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" --output "$2" >/dev/null
}

case "${1:-}" in
  --write)
    out="${2:?usage: api-contract.sh --write DIR}"
    # Absolute: openapi-typescript runs from packages/api-client, where a relative DIR means elsewhere.
    out="$(cd "$out" && pwd)"
    dotnet build src/Gatekeep.Host.Admin --no-restore -v q >/dev/null
    mkdir -p "$out/docs/api"
    cp "$generated" "$out/docs/api/openapi-v1.json"
    generate_client "$generated" "$out/packages/api-client/src/schema.generated.ts"
    echo "Wrote docs/api/openapi-v1.json and packages/api-client/src/schema.generated.ts."
    exit 0
    ;;
  --self-check)
    scratch="$(mktemp -d)"
    trap 'rm -rf "$scratch"' EXIT
    # Each committed file with its last byte changed must fail the check, naming the fix.
    for which in document client; do
      cp "$document" "$scratch/openapi-v1.json"
      cp "$client" "$scratch/schema.generated.ts"
      if [ "$which" = document ]; then altered="$scratch/openapi-v1.json"; else altered="$scratch/schema.generated.ts"; fi
      printf 'x' >> "$altered"
      if API_CONTRACT_DOCUMENT="$scratch/openapi-v1.json" API_CONTRACT_CLIENT="$scratch/schema.generated.ts" \
        sh "$0" > "$scratch/out" 2>&1; then
        echo "Self-check failed: a changed $which passed the API contract check." >&2
        exit 1
      fi
      if ! grep -qF "$hint $regenerate" "$scratch/out"; then
        echo "Self-check failed: a changed $which failed without the regenerate hint." >&2
        cat "$scratch/out" >&2
        exit 1
      fi
    done
    echo "A one-byte change to either committed file fails the check with the regenerate hint."
    exit 0
    ;;
esac

if [ ! -f "$generated" ]; then
  echo "$generated is missing: build the solution first (dotnet build Gatekeep.slnx)." >&2
  exit 1
fi

if ! cmp -s "$generated" "$document"; then
  echo "$document is stale: Host.Admin's endpoints changed. $hint $regenerate" >&2
  exit 1
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
generate_client "$document" "$scratch/schema.generated.ts"
if ! cmp -s "$scratch/schema.generated.ts" "$client"; then
  echo "$client is stale: it isn't generated from $document. $hint $regenerate" >&2
  exit 1
fi

echo "$document and $client match Host.Admin's endpoints."
