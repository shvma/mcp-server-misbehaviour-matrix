#!/usr/bin/env python3
"""Замер задержки одного tools/call: напрямую к серверу, через голый шлюз, через полную цепочку.
Плюс отдельно цена живой сверки определения (tools/list у сервера на каждый вызов).

  python3 stand/measure_latency.py OUT_DIR N TOKEN ПУТЬ...   (direct bare_gateway full_chain live_definition_check)

Сырьё: OUT_DIR/<путь>.csv, одна строка на вызов (мс, http-статус). Сводка дописывается в OUT_DIR/summary.json.
Пути меряются по выбору, потому что два экземпляра agentgateway не делят служебные порты и идут по очереди.
"""
import csv
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapter"))
import adapter  # noqa: E402

OUT, N, TOKEN, CHOSEN = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4:]
ARGS = {"path": "/public/a"}


def post(url, obj, session=None, token=None):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if session:
        h["Mcp-Session-Id"] = session
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
            return r.status, r.headers.get("Mcp-Session-Id")
    except urllib.error.HTTPError as e:
        return e.code, None


def calls(url, token=None):
    """Одна сессия MCP, затем N вызовов tools/call; время каждого вызова отдельно."""
    _, sid = post(url, {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "latency", "version": "0.1"}}}, token=token)
    post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, token)
    rows = []
    for i in range(N):
        t = time.perf_counter()
        st, _ = post(url, {"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
                           "params": {"name": "read", "arguments": ARGS}}, sid, token)
        rows.append(((time.perf_counter() - t) * 1000, st))
    return rows


def live_hash():
    rows = []
    for _ in range(N):
        t = time.perf_counter()
        adapter.live_definition_hash("http://127.0.0.1:3001/mcp", "read", 5)
        rows.append(((time.perf_counter() - t) * 1000, 200))
    return rows


paths = {
    "direct": lambda: calls("http://127.0.0.1:3001/mcp"),
    "bare_gateway": lambda: calls("http://127.0.0.1:3002/mcp"),
    "full_chain": lambda: calls("http://127.0.0.1:3000/mcp", TOKEN),
    "live_definition_check": live_hash,
}
OUT.mkdir(parents=True, exist_ok=True)
sp = OUT / "summary.json"
summary = json.loads(sp.read_text()) if sp.exists() else {}
summary["n"] = N
for name in CHOSEN:
    run = paths[name]
    run()  # прогрев: первые вызовы открывают соединения и не входят в замер
    rows = run()
    with open(OUT / f"{name}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ms", "http"])
        w.writerows((f"{ms:.3f}", st) for ms, st in rows)
    ms = sorted(r[0] for r in rows)
    summary[name] = {"median_ms": round(statistics.median(ms), 2),
                     "p95_ms": round(ms[int(0.95 * (len(ms) - 1))], 2),
                     "non_200": sum(1 for r in rows if r[1] != 200)}
sp.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({k: summary[k] for k in CHOSEN}, indent=2))
bad = [k for k in CHOSEN if summary[k]["non_200"]]
sys.exit(1 if bad else 0)
