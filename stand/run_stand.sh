#!/usr/bin/env bash
# Живой стенд: издатель токенов + OPA + учебный MCP-сервер + адаптер + agentgateway.
# Девять сценариев, в конце автоматические проверки. Сырые логи и ответы: results/stand/.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=results/stand
mkdir -p "$OUT"; rm -f "$OUT"/*
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
AGW="${AGW:-$(command -v agentgateway || echo "$HOME/.local/bin/agentgateway")}"
PIDS=()
cleanup(){ for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
wait_port(){ for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; echo "порт $1 не поднялся" >&2; exit 1; }

# Ключи: настоящий издатель и «чужой» ключ для поддельной подписи. Только на стенде.
rm -rf stand/idp stand/idp-forged
python3 stand/idp.py keygen stand/idp
python3 stand/idp.py keygen stand/idp-forged
tok(){ python3 stand/idp.py token "$@"; }

"$OPA" run --server --addr 127.0.0.1:8181 policy/admission.rego stand/data.json > "$OUT/opa.log" 2>&1 & PIDS+=($!)
CALLS_LOG="$OUT/server-calls.log" python3 stand/mcp_server.py > "$OUT/mcp.log" 2>&1 & MCP=$!; PIDS+=($MCP)
(cd adapter && exec env ADAPTER_LOG_INPUT=1 MCP_TARGETS=notes=http://127.0.0.1:3001/mcp PORT=9191 OPA_URL=http://127.0.0.1:8181/v1/data/admission python3 adapter.py) > "$OUT/adapter.log" 2>&1 &
ADAPTER=$!; PIDS+=($ADAPTER)
"$AGW" -f stand/gateway.yaml > "$OUT/gateway.log" 2>&1 & PIDS+=($!)
for p in 8181 3001 9191 3000; do wait_port $p; done

run(){ local name="$1" token="$2" args="$3"; echo "$name"
       TOKEN="$token" python3 stand/client.py http://127.0.0.1:3000/mcp read "$args" | tee "$OUT/$name.json"; }

GOOD=$(tok stand/idp stand-agent)
run 1-allowed            "$GOOD"                                    '{"path":"/public/a"}'
run 2-denied-path        "$GOOD"                                    '{"path":"/private/b"}'
run 3-no-token           ""                                         '{"path":"/public/a"}'
run 4-other-agent        "$(tok stand/idp other-agent)"             '{"path":"/public/a"}'
run 5-expired-token      "$(tok stand/idp stand-agent -3600)"       '{"path":"/public/a"}'
run 6-forged-signature   "$(tok stand/idp-forged stand-agent)"      '{"path":"/public/a"}'
run 7-wrong-audience     "$(tok stand/idp stand-agent 300 other-gw)" '{"path":"/public/a"}'

kill "$MCP"; wait "$MCP" 2>/dev/null || true
CALLS_LOG="$OUT/server-calls.log" TOOL_DEF=stand/notes_read_changed.json python3 stand/mcp_server.py >> "$OUT/mcp.log" 2>&1 & PIDS+=($!)
wait_port 3001
run 8-definition-changed "$GOOD"                                    '{"path":"/public/a"}'
kill "$ADAPTER"; sleep 0.5
run 9-adapter-down       "$GOOD"                                    '{"path":"/public/a"}'

# --- проверки: стенд падает, если поведение не то ---
python3 - "$OUT" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1])
r = {int(f.name.split("-")[0]): json.loads(f.read_text()) for f in out.glob("[0-9]-*.json")}
log = [json.loads(l) for l in (out / "adapter.log").read_text().splitlines() if l.startswith("{")]
calls = [json.loads(l) for l in (out / "server-calls.log").read_text().splitlines()] if (out / "server-calls.log").exists() else []
checks = [
    ("1: свой агент, разрешённый путь — прошёл (200)", r[1]["http"] == 200),
    ("2: путь вне префикса — 403", r[2]["http"] == 403),
    ("2: причины отказа не отданы агенту", "reasons" not in json.dumps(r[2]["response"])),
    ("3: без токена — шлюз отказал (401)", r[3]["http"] == 401),
    ("4: чужой агент с валидным токеном — 403", r[4]["http"] == 403),
    ("5: просроченный токен — 401", r[5]["http"] == 401),
    ("6: подпись чужим ключом — 401", r[6]["http"] == 401),
    ("7: токен для другой аудитории — 401", r[7]["http"] == 401),
    ("8: подменённое определение — 403", r[8]["http"] == 403),
    ("9: адаптер недоступен — 403", r[9]["http"] == 403),
    ("в адаптер дошли только аутентифицированные вызовы 1, 2, 4, 8",
     [(e["agent"], e["reasons"]) for e in log] ==
     [("stand-agent", []), ("stand-agent", ["path_not_allowed"]),
      ("other-agent", ["agent_not_admitted"]), ("stand-agent", ["definition_changed"])]),
    ("до MCP-сервера дошёл ровно один вызов, разрешённый", [c["arguments"] for c in calls] == [{"path": "/public/a"}]),
]
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
sys.exit(0 if all(ok for _, ok in checks) else 1)
PY
