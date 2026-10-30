#!/usr/bin/env python3
"""Run every (column x behaviour) on the live testbed and record raw data.

For each run: reset the target, start the server with the behaviour and the column's credential mode,
start the column's gateway (and adapter), take a snapshot of the target, let the agent list tools and
call read_note(a1), take a second snapshot, store everything in results/raw.jsonl.
Then measure per-call latency per column, several times. The matrix itself is built by build_matrix.py
from raw data.

Requires the infrastructure from infra/compose.yaml (run.sh starts it). Every port is the default from
the README plus PORT_OFFSET, so a second copy of the testbed can run next to the first; the compose
project (and so the database container's name) comes from COMPOSE_PROJECT_NAME.
"""
import importlib
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS, RUN = ROOT / "results", ROOT / ".run"

# Default port of every component (the README lists them) -> the port used in this run.
DEFAULT_PORTS = {"gateway": 3000, "server": 3001, "adapter": 3002, "postgrest": 3030, "billing": 3101,
                 "sink": 3102, "db": 5433, "keycloak": 8080, "opa": 8181, "decision": 9191, "guardrail": 9201}
OFFSET = int(os.environ.get("PORT_OFFSET", "0"))
PORT = {k: v + OFFSET for k, v in DEFAULT_PORTS.items()}
os.environ["KC_URL"] = f"http://localhost:{PORT['keycloak']}"  # read by lib/net.py and lib/jwtcheck.py

sys.path.insert(0, str(ROOT / "lib"))
from defhash import definition_hash  # noqa: E402
import net  # noqa: E402

OPA = os.environ.get("OPA") or shutil.which("opa") or str(Path.home() / ".local/bin/opa")
AGW = os.environ.get("AGW") or shutil.which("agentgateway") or str(Path.home() / ".local/bin/agentgateway")
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "mcpcase")
DB = os.environ.get("DB_CONTAINER", f"{PROJECT}-db-1")
GATEWAY = f"http://127.0.0.1:{PORT['gateway']}/mcp"
SERVER = f"http://127.0.0.1:{PORT['server']}/mcp"
DATA_URL = f"http://localhost:{PORT['postgrest']}"
LATENCY_CALLS = int(os.environ.get("LATENCY_CALLS", "200"))
LATENCY_RUNS = int(os.environ.get("LATENCY_RUNS", "5"))
AGENT_ARGS = {"id": "a1"}

# column -> what sits on the path. cfg None = no gateway (agent talks straight to the server: the
# baseline). `cred` is the credential the server uses toward the data API. Column a_ro is (a) with the
# server on a read-only account, so that (a) vs (b) can be read apart from the credential: none -> a
# adds the gateway checks, a -> a_ro narrows the static account, a_ro -> b swaps it for the exchanged
# per-user token (and drops the gateway checks; ab puts them back).
COLUMNS = {
    "none": {"cfg": None, "cred": "own", "decision": False, "adapter": False},
    "a": {"cfg": "gateway/a.yaml", "cred": "own", "decision": True, "adapter": False},
    "a_ro": {"cfg": "gateway/a.yaml", "cred": "readonly", "decision": True, "adapter": False},
    "b": {"cfg": "gateway/b.yaml", "cred": "forwarded", "decision": False, "adapter": False},
    "ab": {"cfg": "gateway/ab.yaml", "cred": "forwarded", "decision": True, "adapter": False},
    "c": {"cfg": "gateway/c.yaml", "cred": "none", "decision": False, "adapter": True},
}
BEHAVIORS = ["C0", "C1", "C2", "C3a", "C3b", "C4", "C5", "C6"]
SEED = ("delete from api.notes; insert into api.notes values "
        "('a1','alice','CANARY-ALICE-9d2e: alice release plan for Thursday'),"
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


def wait_port(port, up=True, timeout=15, proc=None):
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port) == up:
            return
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"process for port {port} exited with {proc.returncode} before listening")
        time.sleep(0.05)
    raise RuntimeError(f"port {port} {'did not open' if up else 'stayed open'}")


def gateway_config(cfg):
    """gateway/*.yaml with every default port replaced by this run's port; written to .run/."""
    by_default = {v: PORT[k] for k, v in DEFAULT_PORTS.items()}

    def sub(m):
        if int(m.group(2)) not in by_default:
            raise ValueError(f"{cfg}: port {m.group(2)} is not a testbed port")
        return m.group(1) + str(by_default[int(m.group(2))])
    out = RUN / ("gw-" + Path(cfg).name)
    out.write_text(re.sub(r"(localhost:|port: )(\d{4})\b", sub, (ROOT / cfg).read_text()))
    return str(out)


class Procs:
    def __init__(self):
        self.items = []

    def start(self, name, cmd, env=None, port=None):
        # The port must be FREE before we start: if something else already listens there, waiting
        # for "open" would succeed at once and the run would talk to that other process.
        if port and port_open(port):
            raise RuntimeError(f"port {port} ({name}) is already in use; stop that process or set PORT_OFFSET")
        log = open(RUN / f"{name}.log", "a")
        p = subprocess.Popen(cmd, cwd=ROOT, env={**os.environ, **(env or {})}, stdout=log, stderr=log)
        self.items.append((p, port))
        if port:
            wait_port(port, proc=p)
        return p

    def stop_all(self):
        for p, port in reversed(self.items):
            p.terminate()
            p.wait(5)
            if port:
                wait_port(port, up=False)
        self.items = []


def server_env(behavior, cred, trace):
    return {"PORT": str(PORT["server"]), "BEHAVIOR": behavior, "CREDENTIAL": cred, "TRACE": str(trace),
            "DATA_URL": DATA_URL, "SINK_URL": f"http://localhost:{PORT['sink']}/collect",
            "BILLING_URL": f"http://localhost:{PORT['billing']}/charge"}


def start_column(procs, column, behavior, trace):
    """Server (+ adapter) (+ gateway) for one column. Returns the URL the agent talks to."""
    c = COLUMNS[column]
    procs.start("server", [sys.executable, "server/notes_server.py"], port=PORT["server"],
                env=server_env(behavior, c["cred"], trace))
    if c["adapter"]:
        procs.start("adapter", [sys.executable, "adapter/typed_adapter.py"], port=PORT["adapter"],
                    env={"PORT": str(PORT["adapter"]), "DATA_URL": DATA_URL, "UPSTREAM": SERVER})
    if c["cfg"] is None:
        return SERVER
    procs.start("gateway", [AGW, "-f", gateway_config(c["cfg"])], port=PORT["gateway"])
    return GATEWAY


def agent_session(token, url):
    client = net.McpClient(url, bearer=token, name="agent")
    st_list, tools = client.list_tools()
    st_call, resp = client.call("read_note", AGENT_ARGS)
    return {"init_status": client.status, "tools_status": st_list, "tools": tools,
            "call": {"arguments": AGENT_ARGS, "status": st_call, "response": resp}}


def versions():
    def cmd(*c):
        try:
            return subprocess.run(c, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception as e:
            return f"unavailable: {e}"
    def pkg(module):
        try:
            return importlib.import_module(module).__version__
        except ImportError:
            return "missing"
    images = {}
    for svc in ("keycloak", "db", "postgrest"):
        images[svc] = cmd("docker", "inspect", "--format", "{{.Config.Image}}", f"{PROJECT}-{svc}-1")
    return {"agentgateway": json.loads(cmd(AGW, "--version") or "{}").get("version"),
            "opa": cmd(OPA, "version").splitlines()[0], "images": images,
            "python": platform.python_version(), "cryptography": pkg("cryptography"), "grpcio": pkg("grpc"),
            "protobuf": pkg("google.protobuf"), "platform": platform.platform()}


def run_one(column, behavior, agent_token):
    c = COLUMNS[column]
    psql(SEED)
    for f in ("ledger.jsonl", "sink.jsonl", "server-trace.jsonl", "decision-run.log"):
        (RUN / f).write_text("")
    per_run = Procs()
    try:
        url = start_column(per_run, column, behavior, RUN / "server-trace.jsonl")
        decision_log_start = (RUN / "decision.log").stat().st_size if c["decision"] else 0
        before = snapshot()
        agent = agent_session(agent_token, url)
        time.sleep(0.2)  # let side effects land in logs
        after = snapshot()
        decisions = []
        if c["decision"]:
            with open(RUN / "decision.log") as f:
                f.seek(decision_log_start)
                decisions = [json.loads(x) for x in f.read().splitlines() if x.startswith("{")]
    finally:
        per_run.stop_all()
    return {"column": column, "behavior": behavior, "server_credential": c["cred"],
            "agent": agent, "target": {"before": before, "after": after},
            "server_trace": lines(RUN / "server-trace.jsonl"), "decisions": decisions}


def latency(column, agent_token, run):
    """One latency run: LATENCY_CALLS sequential tools/call on an honest server after warm-up."""
    psql(SEED)
    per_run = Procs()
    try:
        url = start_column(per_run, column, "C0", RUN / "latency-trace.jsonl")
        client = net.McpClient(url, bearer=agent_token, name="agent")
        client.list_tools()
        for _ in range(10):  # warm-up
            client.call("read_note", AGENT_ARGS)
        samples, failures = [], 0
        for _ in range(LATENCY_CALLS):
            t = time.perf_counter()
            st, resp = client.call("read_note", AGENT_ARGS)
            samples.append((time.perf_counter() - t) * 1000)
            failures += not (st == 200 and isinstance(resp, dict) and "result" in resp)
    finally:
        per_run.stop_all()
    samples.sort()
    return {"column": column, "run": run, "calls": len(samples), "failures": failures,
            "median_ms": round(statistics.median(samples), 3),
            "p95_ms": round(samples[int(0.95 * len(samples)) - 1], 3), "samples_ms": [round(x, 3) for x in samples]}


def gateway_proofs(agent_token):
    """Show the gateway (jwtAuth: strict) rejects a call with no token and one with a forged
    signature, and accepts a valid one. These are the gateway-works proofs (#5)."""
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "agent", "version": "1.0"}}}
    accept = {"Accept": "application/json, text/event-stream"}
    forged = agent_token.rsplit(".", 1)[0] + ".Zm9yZ2VkLXNpZ25hdHVyZQ"  # valid header.payload, bad sig
    per = Procs()
    try:
        start_column(per, "a", "C0", RUN / "proofs-trace.jsonl")
        no_token = net.http("POST", GATEWAY, body=init, headers=accept)[0]
        wrong_sig = net.http("POST", GATEWAY, token=forged, body=init, headers=accept)[0]
        valid = net.http("POST", GATEWAY, token=agent_token, body=init, headers=accept)[0]
    finally:
        per.stop_all()
    return {"no_token_status": no_token, "forged_signature_status": wrong_sig,
            "valid_token_status": valid,
            "no_token_rejected": no_token in (401, 403), "forged_rejected": wrong_sig in (401, 403),
            "valid_accepted": valid == 200}


def main():
    RESULTS.mkdir(exist_ok=True)
    RUN.mkdir(exist_ok=True)
    pinned = json.loads((ROOT / "policy/data.json").read_text())["tools"]["notes/read_note"]["definition_sha256"]
    served = definition_hash(json.loads((ROOT / "server/tool.json").read_text()))
    if pinned != served:
        sys.exit(f"policy/data.json pins {pinned[:12]}, server/tool.json hashes to {served[:12]}")
    jwks = net.http("GET", f"{os.environ['KC_URL']}/realms/stand/protocol/openid-connect/certs")[1]
    (RUN / "jwks.json").write_text(json.dumps(jwks))
    (RUN / "decision.log").write_text("")

    base = Procs()
    try:
        base.start("billing", [sys.executable, "services/billing.py"], port=PORT["billing"],
                   env={"PORT": str(PORT["billing"]), "LEDGER": str(RUN / "ledger.jsonl")})
        base.start("sink", [sys.executable, "services/sink.py"], port=PORT["sink"],
                   env={"PORT": str(PORT["sink"]), "SINK_LOG": str(RUN / "sink.jsonl")})
        base.start("opa", [OPA, "run", "--server", "--addr", f"127.0.0.1:{PORT['opa']}",
                           "policy/admission.rego", "policy/data.json"], port=PORT["opa"])
        base.start("guardrail", [sys.executable, "guardrail/pin_processor.py"], port=PORT["guardrail"],
                   env={"PORT": str(PORT["guardrail"]), "DATA_JSON": str(ROOT / "policy/data.json")})
        decision_log = open(RUN / "decision.log", "a")
        if port_open(PORT["decision"]):
            raise RuntimeError(f"port {PORT['decision']} (decision) is already in use")
        decision = subprocess.Popen(
            [sys.executable, "decision/decision.py"], cwd=ROOT, stdout=decision_log, stderr=decision_log,
            env={**os.environ, "PORT": str(PORT["decision"]),
                 "OPA_URL": f"http://127.0.0.1:{PORT['opa']}/v1/data/mcp/admission"})
        base.items.append((decision, PORT["decision"]))
        wait_port(PORT["decision"], proc=decision)

        agent_token = net.user_token("agent", "agent-secret", "alice", "alice-pass")
        records = []
        for column in COLUMNS:
            for behavior in BEHAVIORS:
                rec = run_one(column, behavior, agent_token)
                records.append(rec)
                print(f"{column:>4} {behavior:<3}: call {rec['agent']['call']['status']}", flush=True)
        (RESULTS / "raw.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))
        (RESULTS / "gateway-proofs.json").write_text(json.dumps(gateway_proofs(agent_token), indent=1) + "\n")
        # Columns are interleaved and the order is rotated each run, so drift on the host (thermal,
        # background load) spreads over all columns instead of landing on whichever ran last.
        lat, cols = [], list(COLUMNS)
        for run in range(LATENCY_RUNS):
            for column in cols[run % len(cols):] + cols[:run % len(cols)]:
                lat.append(latency(column, agent_token, run))
            print(f"latency run {run + 1}/{LATENCY_RUNS} done", flush=True)
        (RESULTS / "latency.json").write_text(json.dumps(lat, indent=1) + "\n")
        (RESULTS / "versions.json").write_text(json.dumps(versions(), indent=2) + "\n")
    finally:
        base.stop_all()


if __name__ == "__main__":
    main()
