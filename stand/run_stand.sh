#!/usr/bin/env bash
# Живой стенд: OPA + учебный MCP-сервер + адаптер + agentgateway, три сценария.
# Сырые логи и ответы: results/stand/.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=results/stand
mkdir -p "$OUT"; rm -f "$OUT"/*
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
AGW="${AGW:-$(command -v agentgateway || echo "$HOME/.local/bin/agentgateway")}"
PIDS=()
cleanup(){ for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

"$OPA" run --server --addr 127.0.0.1:8181 policy/admission.rego stand/data.json > "$OUT/opa.log" 2>&1 & PIDS+=($!)
CALLS_LOG="$OUT/server-calls.log" python3 stand/mcp_server.py > "$OUT/mcp.log" 2>&1 & PIDS+=($!)
(cd adapter && exec env ADAPTER_LOG_INPUT=1 PORT=9191 OPA_URL=http://127.0.0.1:8181/v1/data/admission python3 adapter.py) > "$OUT/adapter.log" 2>&1 &
ADAPTER=$!; PIDS+=($ADAPTER)
"$AGW" -f stand/gateway.yaml > "$OUT/gateway.log" 2>&1 & PIDS+=($!)

wait_port(){ for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "порт $1 не поднялся" >&2; exit 1; }
for p in 8181 3001 9191 3000; do wait_port $p; done

C="python3 stand/client.py http://127.0.0.1:3000/mcp read"
echo "1. путь внутри разрешённого префикса";  $C '{"path":"/public/a"}'  | tee "$OUT/1-allowed.json"
echo "2. путь вне префикса";                  $C '{"path":"/private/b"}' | tee "$OUT/2-denied-path.json"
kill "$ADAPTER"; sleep 0.5
echo "3. адаптер недоступен";                 $C '{"path":"/public/a"}'  | tee "$OUT/3-adapter-down.json"
echo "--- дошло до MCP-сервера:"; cat "$OUT/server-calls.log" 2>/dev/null || echo "(ничего)"

# --- проверки: стенд падает, если поведение не то ---
python3 - "$OUT" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1])
r = {n: json.loads((out / f).read_text()) for n, f in
     [(1, "1-allowed.json"), (2, "2-denied-path.json"), (3, "3-adapter-down.json")]}
calls = [json.loads(l) for l in (out / "server-calls.log").read_text().splitlines()] if (out / "server-calls.log").exists() else []
checks = [
    ("1: разрешённый вызов прошёл (200)", r[1]["http"] == 200),
    ("2: вызов вне префикса отклонён (403)", r[2]["http"] == 403),
    ("2: причины отказа не отданы агенту", "reasons" not in json.dumps(r[2]["response"])),
    ("3: при недоступном адаптере шлюз отказал (403)", r[3]["http"] == 403),
    ("до MCP-сервера дошёл ровно один вызов, разрешённый", [c["arguments"] for c in calls] == [{"path": "/public/a"}]),
]
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
sys.exit(0 if all(ok for _, ok in checks) else 1)
PY

