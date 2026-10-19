#!/usr/bin/env bash
# Замер добавочной задержки допуска: N вызовов на каждый путь, сырьё в results/latency/.
# Запуск: ./stand/run_latency.sh [N]   (по умолчанию N=200)
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:-200}"
OUT=results/latency
mkdir -p "$OUT"; rm -f "$OUT"/*
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
AGW="${AGW:-$(command -v agentgateway || echo "$HOME/.local/bin/agentgateway")}"
PIDS=()
cleanup(){ for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
wait_port(){ for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "порт $1 не поднялся" >&2; exit 1; }

rm -rf stand/idp; python3 stand/idp.py keygen stand/idp
"$OPA" run --server --addr 127.0.0.1:8181 policy/admission.rego stand/data.json > /dev/null 2>&1 & PIDS+=($!)
CALLS_LOG=/dev/null python3 stand/mcp_server.py > /dev/null 2>&1 & PIDS+=($!)
(cd adapter && exec env MCP_TARGETS=notes=http://127.0.0.1:3001/mcp PORT=9191 OPA_URL=http://127.0.0.1:8181/v1/data/admission python3 adapter.py) > "$OUT/adapter.log" 2>&1 & PIDS+=($!)
for p in 8181 3001 9191; do wait_port $p; done

{ echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "host: $(uname -sm)"; echo "agentgateway: $("$AGW" --version | grep '"version"')"; "$OPA" version | head -1; python3 --version; } > "$OUT/env.txt"
TOKEN="$(python3 stand/idp.py token stand/idp stand-agent 3600)"

# Два экземпляра agentgateway делят служебные порты (15000, 15020, 15021), поэтому по очереди.
"$AGW" -f stand/gateway-bare.yaml > "$OUT/gateway-bare.log" 2>&1 & BARE=$!; PIDS+=($BARE)
wait_port 3002
python3 stand/measure_latency.py "$OUT" "$N" "$TOKEN" direct bare_gateway
kill "$BARE"; wait "$BARE" 2>/dev/null || true
"$AGW" -f stand/gateway.yaml > "$OUT/gateway.log" 2>&1 & PIDS+=($!)
wait_port 3000
python3 stand/measure_latency.py "$OUT" "$N" "$TOKEN" full_chain live_definition_check
