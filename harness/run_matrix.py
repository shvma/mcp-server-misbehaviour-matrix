#!/usr/bin/env python3
"""Run every (column x behaviour) on the live testbed and record raw data.

For each run: reset the target, start the server with the behaviour and the column's credential mode,
start the column's gateway (and adapter), take a snapshot of the target, let the agent list tools and
call read_note(a1), take a second snapshot, store everything in results/raw.jsonl.
Then measure per-call latency per column. The matrix itself is built by build_matrix.py from raw data.

Requires the infrastructure from infra/compose.yaml (run.sh starts it).
"""
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
from defhash import definition_hash  # noqa: E402
import net  # noqa: E402

RESULTS, RUN = ROOT / "results", ROOT / ".run"
OPA = os.environ.get("OPA") or shutil.which("opa") or str(Path.home() / ".local/bin/opa")
AGW = os.environ.get("AGW") or shutil.which("agentgateway") or str(Path.home() / ".local/bin/agentgateway")
DB = os.environ.get("DB_CONTAINER", "mcpcase-db-1")
GATEWAY = "http://127.0.0.1:3000/mcp"
LATENCY_CALLS = int(os.environ.get("LATENCY_CALLS", "200"))

COLUMNS = {  # column -> (gateway config, server credential mode, needs decision service, needs adapter)
    "a": ("gateway/a.yaml", "own", True, False),
    "b": ("gateway/b.yaml", "forwarded", False, False),
    "ab": ("gateway/ab.yaml", "forwarded", True, False),
    "c": ("gateway/c.yaml", "none", False, True),
}
BEHAVIORS = ["C0", "C1", "C2", "C3", "C4", "C5", "C6"]
SEED = ("delete from api.notes; insert into api.notes values "
        "('a1','alice','alice: release plan for Thursday'),"
        "('b1','bob','CANARY-BOB-7f3a: bob private note');")


def psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "postgres", "-At", "-c", sql],
                         check=True, capture_output=True, text=True).stdout.strip()
    return out


def lines(path):
    p = Path(path)
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def snapshot():
    notes = json.loads(psql("select coalesce(json_agg(n order by id), '[]') from api.notes n"))
    return {"notes": notes, "ledger": lines(RUN / "ledger.jsonl"), "sink": lines(RUN / "sink.jsonl")}


def port_open(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_port(port, up=True, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port) == up:
            return
        time.sleep(0.05)
    raise RuntimeError(f"port {port} {'did not open' if up else 'stayed open'}")


class Procs:
    def __init__(self):
        self.items = []

    def start(self, name, cmd, env=None, port=None):
        log = open(RUN / f"{name}.log", "a")
        p = subprocess.Popen(cmd, cwd=ROOT, env={**os.environ, **(env or {})}, stdout=log, stderr=log)
        self.items.append((p, port))
        if port:
            wait_port(port)
        return p

    def stop_all(self):
        for p, port in reversed(self.items):
            p.terminate()
            p.wait(5)
            if port:
                wait_port(port, up=False)
        self.items = []


def agent_session(token, url=GATEWAY):
    client = net.McpClient(url, bearer=token, name="agent")
    st_list, tools = client.list_tools()
    st_call, resp = client.call("read_note", {"id": "a1"})
    return {"init_status": client.status, "tools_status": st_list, "tools": tools,
            "call": {"status": st_call, "response": resp}}


def versions():
    def cmd(*c):
        try:
            return subprocess.run(c, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception as e:
            return f"unavailable: {e}"
    images = {}
    for svc in ("keycloak", "db", "postgrest"):
        images[svc] = cmd("docker", "inspect", "--format", "{{.Config.Image}}", f"mcpcase-{svc}-1")
    try:
        import cryptography
        crypto = cryptography.__version__
    except ImportError:
        crypto = "missing"
    return {"agentgateway": json.loads(cmd(AGW, "--version") or "{}").get("version"),
            "opa": cmd(OPA, "version").splitlines()[0], "images": images,
            "python": platform.python_version(), "cryptography": crypto, "platform": platform.platform()}


def run_one(procs, column, behavior, agent_token):
    cfg, cred, needs_decision, needs_adapter = COLUMNS[column]
    psql(SEED)
    for f in ("ledger.jsonl", "sink.jsonl", "server-trace.jsonl", "decision-run.log"):
        (RUN / f).write_text("")
    per_run = Procs()
    per_run.start("server", [sys.executable, "server/notes_server.py"], port=3001,
                  env={"BEHAVIOR": behavior, "CREDENTIAL": cred, "TRACE": str(RUN / "server-trace.jsonl")})
    if needs_adapter:
        per_run.start("adapter", [sys.executable, "adapter/typed_adapter.py"], port=3002)
    per_run.start("gateway", [AGW, "-f", cfg], port=3000)
    try:
        decision_log_start = (RUN / "decision.log").stat().st_size if needs_decision else 0
        before = snapshot()
        agent = agent_session(agent_token)
        time.sleep(0.2)  # let side effects land in logs
        after = snapshot()
        decisions = []
        if needs_decision:
            with open(RUN / "decision.log") as f:
                f.seek(decision_log_start)
                decisions = [json.loads(x) for x in f.read().splitlines() if x.startswith("{")]
    finally:
        per_run.stop_all()
    return {"column": column, "behavior": behavior, "server_credential": cred,
            "agent": agent, "target": {"before": before, "after": after},
            "server_trace": lines(RUN / "server-trace.jsonl"), "decisions": decisions}


def latency(procs, column, agent_token):
    cfg, cred, _, needs_adapter = COLUMNS[column] if column != "direct" else (None, "own", False, False)
    psql(SEED)
    per_run = Procs()
    per_run.start("server", [sys.executable, "server/notes_server.py"], port=3001,
                  env={"BEHAVIOR": "C0", "CREDENTIAL": cred, "TRACE": str(RUN / "latency-trace.jsonl")})
    if needs_adapter:
        per_run.start("adapter", [sys.executable, "adapter/typed_adapter.py"], port=3002)
    url = "http://127.0.0.1:3001/mcp"
    if cfg:
        per_run.start("gateway", [AGW, "-f", cfg], port=3000)
        url = GATEWAY
    try:
        client = net.McpClient(url, bearer=agent_token, name="agent")
        client.list_tools()
        for _ in range(10):  # warm-up
            client.call("read_note", {"id": "a1"})
        samples, failures = [], 0
        for _ in range(LATENCY_CALLS):
            t = time.perf_counter()
            st, resp = client.call("read_note", {"id": "a1"})
            samples.append((time.perf_counter() - t) * 1000)
            failures += not (st == 200 and isinstance(resp, dict) and "result" in resp)
    finally:
        per_run.stop_all()
    samples.sort()
    return {"column": column, "calls": len(samples), "failures": failures,
            "median_ms": round(statistics.median(samples), 2),
            "p95_ms": round(samples[int(0.95 * len(samples)) - 1], 2), "samples_ms": [round(s, 3) for s in samples]}


def main():
    RESULTS.mkdir(exist_ok=True)
    RUN.mkdir(exist_ok=True)
    pinned = json.loads((ROOT / "policy/data.json").read_text())["tools"]["notes/read_note"]["definition_sha256"]
    served = definition_hash(json.loads((ROOT / "server/tool.json").read_text()))
    if pinned != served:
        sys.exit(f"policy/data.json pins {pinned[:12]}, server/tool.json hashes to {served[:12]}")
    (RUN / "jwks.json").write_text(json.dumps(net.http("GET", "http://localhost:8080/realms/stand/protocol/openid-connect/certs")[1]))
    (RUN / "decision.log").write_text("")

    base = Procs()
    base.start("billing", [sys.executable, "services/billing.py"], port=3101, env={"LEDGER": str(RUN / "ledger.jsonl")})
    base.start("sink", [sys.executable, "services/sink.py"], port=3102, env={"SINK_LOG": str(RUN / "sink.jsonl")})
    base.start("opa", [OPA, "run", "--server", "--addr", "127.0.0.1:8181", "policy/admission.rego", "policy/data.json"], port=8181)
    decision_log = open(RUN / "decision.log", "a")
    decision = subprocess.Popen([sys.executable, "decision/decision.py"], cwd=ROOT, stdout=decision_log, stderr=decision_log)
    base.items.append((decision, 9191))
    wait_port(9191)
    try:
        agent_token = net.user_token("agent", "agent-secret", "alice", "alice-pass")
        records = []
        for column in COLUMNS:
            for behavior in BEHAVIORS:
                rec = run_one(base, column, behavior, agent_token)
                records.append(rec)
                print(f"{column:>2} {behavior}: call {rec['agent']['call']['status']}", flush=True)
        (RESULTS / "raw.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
        lat = [latency(base, c, agent_token) for c in ("direct", *COLUMNS)]
        (RESULTS / "latency.json").write_text(json.dumps(lat, indent=1) + "\n")
        (RESULTS / "versions.json").write_text(json.dumps(versions(), indent=2) + "\n")
    finally:
        base.stop_all()


if __name__ == "__main__":
    main()
