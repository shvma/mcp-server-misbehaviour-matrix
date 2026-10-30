#!/usr/bin/env bash
# One command: start the testbed, run every column x behaviour, rebuild the matrix, run the unit tests.
#   ./run.sh            full run
#   ./run.sh --down     stop and remove this testbed's containers
# Needs: Docker, Python 3.9+ with the packages in requirements.txt (`cryptography`, `grpcio`, `protobuf`),
#        opa and agentgateway on PATH (or OPA/AGW set).
# Optional: COMPOSE_PROJECT_NAME (default mcpcase) names the containers; PORT_OFFSET (default 0) is
#           added to every port, so a second copy can run next to the first.
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mcpcase}"
export PORT_OFFSET="${PORT_OFFSET:-0}"
export KC_PORT=$((8080 + PORT_OFFSET)) DB_PORT=$((5433 + PORT_OFFSET)) PGRST_PORT=$((3030 + PORT_OFFSET))
COMPOSE=(docker compose -p "$COMPOSE_PROJECT_NAME" -f infra/compose.yaml)
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
KC="http://localhost:$KC_PORT"

if [ "${1:-}" = "--down" ]; then "${COMPOSE[@]}" down -v; exit 0; fi

"${COMPOSE[@]}" up -d keycloak db
echo "waiting for Keycloak on $KC_PORT..."
for _ in $(seq 1 100); do
  curl -sf "$KC/realms/stand/.well-known/openid-configuration" >/dev/null && break
  sleep 2
done
# PostgREST verifies token signatures with the realm's JWKS.
KC_JWKS="$(curl -sf "$KC/realms/stand/protocol/openid-connect/certs")"
export KC_JWKS
"${COMPOSE[@]}" up -d postgrest
for _ in $(seq 1 60); do curl -sf "http://localhost:$PGRST_PORT/" >/dev/null && break; sleep 1; done

mkdir -p results
"$OPA" fmt --list --fail policy >/dev/null || { echo "policy is not formatted: $OPA fmt -w policy" >&2; exit 1; }
"$OPA" test policy -v > results/opa-test.txt 2>&1 || { cat results/opa-test.txt; exit 1; }
tail -1 results/opa-test.txt
python3 -m unittest discover -s tests -v > results/unit-tests.txt 2>&1 || { cat results/unit-tests.txt; exit 1; }
tail -1 results/unit-tests.txt

python3 harness/run_matrix.py
python3 harness/build_matrix.py
