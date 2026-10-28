#!/usr/bin/env bash
# One command: start the testbed, run every column x behaviour, rebuild the matrix, run the unit tests.
#   ./run.sh            full run
#   ./run.sh --down     stop and remove the testbed containers
# Needs: Docker, Python 3.9+ with `cryptography`, opa and agentgateway on PATH (or OPA/AGW set).
set -euo pipefail
cd "$(dirname "$0")"
COMPOSE=(docker compose -p mcpcase -f infra/compose.yaml)
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"

if [ "${1:-}" = "--down" ]; then "${COMPOSE[@]}" down -v; exit 0; fi

"${COMPOSE[@]}" up -d keycloak db
echo "waiting for Keycloak..."
for _ in $(seq 1 100); do
  curl -sf http://localhost:8080/realms/stand/.well-known/openid-configuration >/dev/null && break
  sleep 2
done
# PostgREST verifies token signatures with the realm's JWKS.
KC_JWKS="$(curl -sf http://localhost:8080/realms/stand/protocol/openid-connect/certs)"
export KC_JWKS
"${COMPOSE[@]}" up -d postgrest
for _ in $(seq 1 60); do curl -sf http://localhost:3030/ >/dev/null && break; sleep 1; done

mkdir -p results
"$OPA" fmt --list --fail policy >/dev/null || { echo "policy is not formatted: $OPA fmt -w policy" >&2; exit 1; }
"$OPA" test policy -v > results/opa-test.txt 2>&1 || { cat results/opa-test.txt; exit 1; }
tail -1 results/opa-test.txt
python3 -m unittest discover -s tests -v > results/unit-tests.txt 2>&1 || { cat results/unit-tests.txt; exit 1; }
tail -1 results/unit-tests.txt

python3 harness/run_matrix.py
python3 harness/build_matrix.py
