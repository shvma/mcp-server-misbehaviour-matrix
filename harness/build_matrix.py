#!/usr/bin/env python3
"""Build results/matrix.md and results/cost.md from raw data only (raw.jsonl, latency.json, versions.json)
and from the repository's own files (line counts), and copy both tables into README.md between markers,
so the README always shows what the raw data says. No testbed needed."""
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
from outcome import outcome  # noqa: E402

R = ROOT / "results"
COLUMNS = [("none", "(none) no gateway"),
           ("a", "(a) gateway: OPA + definition pin"),
           ("a_ro", "(a′) as (a), server on a read-only account"),
           ("b", "(b) token exchange, rights at the target"),
           ("ab", "(a+b) both"), ("c", "(c) typed adapter")]
# The server's credential toward the data API, shown as its own row: it is the second thing that
# changes between columns, next to the checks in the column header.
CREDENTIAL = {"none": "own account: read/write, all rows", "a": "own account: read/write, all rows",
              "a_ro": "own account: read-only, all rows",
              "b": "exchanged user token: read-only, caller's rows (RLS)",
              "ab": "exchanged user token: read-only, caller's rows (RLS)",
              "c": "none (the adapter holds a read-only account)"}
BEHAVIORS = [("C0", "control: honest call"),
             ("C1", "changes its pinned tool's description (rug pull)"),
             ("C2", "adds a new, unpinned tool with instructions in its description"),
             ("C3a", "sends what the call handed it (arguments + the caller's own note) out (postmark pattern)"),
             ("C3b", "reads another user's note and sends it out"),
             ("C4", "writes instead of reading"),
             ("C5", "replays the token it received against another service"),
             ("C6", "lies in its answer")]
LABEL = {"ok": "ok", "broken": "BROKEN", "stopped": "stopped", "not_stopped": "**not stopped**",
         "poison_delivered_call_blocked": "**call blocked, poison delivered**",
         "args_leaked": "**arguments leaked**",
         "closed_by_design": "closed by design", "did_not_run": "did not run", "call_failed": "call failed"}

# Components a tools/call crosses, per column, and which of them are this repository's code.
PATH = {
    "none": (["notes server"], []),
    "a": (["agentgateway", "decision service", "OPA", "pin guardrail", "notes server"],
          ["decision/decision.py", "guardrail/pin_processor.py", "policy/admission.rego"]),
    "a_ro": (["agentgateway", "decision service", "OPA", "pin guardrail", "notes server"],
             ["decision/decision.py", "guardrail/pin_processor.py", "policy/admission.rego", "infra/db/init.sql"]),
    "b": (["agentgateway", "Keycloak (token exchange)", "notes server", "PostgREST + PostgreSQL RLS"],
          ["infra/db/init.sql"]),
    "ab": (["agentgateway", "decision service", "OPA", "pin guardrail", "Keycloak (token exchange)",
            "notes server", "PostgREST + PostgreSQL RLS"],
           ["decision/decision.py", "guardrail/pin_processor.py", "policy/admission.rego", "infra/db/init.sql"]),
    "c": (["agentgateway", "typed adapter", "PostgREST + PostgreSQL"],
          ["adapter/typed_adapter.py", "lib/jwtcheck.py", "lib/net.py"]),
}
OWN_COMPONENTS = ("decision service", "pin guardrail", "typed adapter")
# Configuration each column depends on: its gateway file and the Keycloak clients it uses (realm.json).
# The realm's users and settings are shared by every column and not attributed to any of them.
CONFIG = {
    "none": (None, ["agent", "evil-svc"]),
    "a": ("gateway/a.yaml", ["agent", "mcp-gateway", "evil-svc"]),
    "a_ro": ("gateway/a.yaml", ["agent", "mcp-gateway", "notes-ro"]),
    "b": ("gateway/b.yaml", ["agent", "mcp-gateway", "gateway", "notes-api"]),
    "ab": ("gateway/ab.yaml", ["agent", "mcp-gateway", "gateway", "notes-api"]),
    "c": ("gateway/c.yaml", ["agent", "mcp-gateway", "typed-adapter", "notes-api"]),
}
NEEDS = {
    "none": "nothing — the agent reaches the server directly (shows the attacks landing)",
    "a": "the gateway, a definition-pin guardrail on tools/list, and a live per-call decision",
    "a_ro": "as (a), plus a read-only role and service account for the server",
    "b": "an IdP with RFC 8693 token exchange; a target that enforces per-user rights (here: RLS)",
    "ab": "both of the above",
    "c": "a data API the adapter can query with a read-only account; one adapter function per tool",
}


def code_lines(rel):
    """Non-blank lines that are not comments (#, --) or docstring-only lines."""
    n, in_doc = 0, False
    for line in (ROOT / rel).read_text().splitlines():
        s = line.strip()
        if in_doc or s.startswith('"""'):
            if s.count('"""') % 2:
                in_doc = not in_doc
            continue
        if not s or s.startswith("#") or s.startswith("--"):
            continue
        n += 1
    return n


def per_tool_adapter_lines():
    src = (ROOT / "adapter/typed_adapter.py").read_text().split("# --- per-tool code")[1].split("# ----")[0]
    body = [x for x in src.splitlines()[1:] if x.strip() and not x.strip().startswith("#")]
    return len(body) + 1  # + the OPERATIONS entry


def realm_client_lines(names):
    clients = {c["clientId"]: c for c in json.loads((ROOT / "infra/keycloak/realm.json").read_text())["clients"]}
    return sum(len(json.dumps(clients[n], indent=2).splitlines()) for n in names)


def yaml_lines(rel):
    if rel is None:
        return 0
    return sum(1 for x in (ROOT / rel).read_text().splitlines() if x.strip() and not x.strip().startswith("#"))


def spread(values, digits=2):
    """'median (min–max)' of a list of numbers."""
    return f"{round(statistics.median(values), digits)} ({round(min(values), digits)}–{round(max(values), digits)})"


def per_tool_policy_lines():
    entry = json.loads((ROOT / "policy/data.json").read_text())["tools"]["notes/read_note"]
    return len(json.dumps({"notes/read_note": entry}, indent=2).splitlines())


def inject(text, name, lines):
    start, end = f"<!-- {name}:START -->", f"<!-- {name}:END -->"
    head, rest = text.split(start, 1)
    return head + start + "\n" + "\n".join(lines).strip() + "\n" + end + rest.split(end, 1)[1]


def main():
    raw = [json.loads(x) for x in (R / "raw.jsonl").read_text().splitlines() if x.strip()]
    cells = {(r["column"], r["behavior"]): outcome(r) for r in raw}
    versions = json.loads((R / "versions.json").read_text())
    out = ["# Matrix: server behaviour x place of the check", "",
           "Generated by `harness/build_matrix.py` from `results/raw.jsonl`. "
           "The definition of each outcome is in `harness/outcome.py`.", "",
           "| Server behaviour | " + " | ".join(c for _, c in COLUMNS) + " |",
           "|---|" + "---|" * len(COLUMNS)]
    out.append("| _server credential → data API_ | " + " | ".join(CREDENTIAL[c] for c, _ in COLUMNS) + " |")
    for b, label in BEHAVIORS:
        out.append(f"| {b}. {label} | " + " | ".join(LABEL[cells[(c, b)]] for c, _ in COLUMNS) + " |")
    broken = [c for c, _ in COLUMNS if cells[(c, "C0")] != "ok"]
    out += ["", "**not stopped** = the behaviour had its effect (see `harness/outcome.py` for what is checked).",
            "Columns whose control row is not ok: " + (", ".join(broken) if broken else "none") + ".", "",
            "Versions: agentgateway " + str(versions["agentgateway"]) + ", OPA "
            + versions["opa"].replace("Version: ", "") + ", "
            + ", ".join(f"{k} `{v}`" for k, v in versions["images"].items())
            + f", Python {versions['python']}, cryptography {versions.get('cryptography')}, "
            f"grpcio {versions.get('grpcio')}, protobuf {versions.get('protobuf')}."]
    (R / "matrix.md").write_text("\n".join(out) + "\n")

    runs = json.loads((R / "latency.json").read_text())
    by_col = {c: sorted((x for x in runs if x["column"] == c), key=lambda x: x["run"]) for c, _ in COLUMNS}
    n_runs, n_calls = len(by_col["none"]), by_col["none"][0]["calls"]
    base = {x["run"]: x["median_ms"] for x in by_col["none"]}
    cost = ["# Cost per column", "", "Generated by `harness/build_matrix.py`. Latency: "
            f"{n_runs} runs per column, each {n_calls} sequential tools/call after warm-up; columns interleaved "
            "and their order rotated between runs. Shown: median over runs (min–max over runs). All processes "
            "on one host (localhost); absolute numbers do not transfer to a network deployment.", "",
            "| | " + " | ".join(c for _, c in COLUMNS) + " |", "|---|" + "---|" * len(COLUMNS)]
    cost.append("| components on the call path | " + " | ".join(str(len(PATH[c][0])) for c, _ in COLUMNS) + " |")
    cost.append("| of them this repository's code | " + " | ".join(
        str(sum(1 for x in PATH[c][0] if x in OWN_COMPONENTS)) for c, _ in COLUMNS) + " |")
    cost.append("| own lines on the trust path | " + " | ".join(
        str(sum(code_lines(f) for f in PATH[c][1])) for c, _ in COLUMNS) + " |")
    cost.append("| config lines: gateway YAML + IdP clients | " + " | ".join(
        f"{yaml_lines(CONFIG[c][0])} + {realm_client_lines(CONFIG[c][1])}" for c, _ in COLUMNS) + " |")
    cost.append("| lines to add one tool | " + " | ".join([
        "n/a (no gateway)", f"{per_tool_policy_lines()} (policy data)", f"{per_tool_policy_lines()} (policy data)",
        "0 (rights live in the target)", f"{per_tool_policy_lines()} (policy data)",
        f"{per_tool_adapter_lines()} (adapter code)"]) + " |")
    cost.append("| requires from the environment | " + " | ".join(NEEDS[c] for c, _ in COLUMNS) + " |")
    cost.append("| latency median, ms | " + " | ".join(
        spread([x["median_ms"] for x in by_col[c]]) for c, _ in COLUMNS) + " |")
    cost.append("| latency p95, ms | " + " | ".join(
        spread([x["p95_ms"] for x in by_col[c]]) for c, _ in COLUMNS) + " |")
    cost.append("| added median vs (none), same run, ms | " + " | ".join(
        "—" if c == "none" else spread([x["median_ms"] - base[x["run"]] for x in by_col[c]])
        for c, _ in COLUMNS) + " |")
    cost.append("| failed calls during measurement | " + " | ".join(
        str(sum(x["failures"] for x in by_col[c])) for c, _ in COLUMNS) + " |")
    cost += ["", "Own lines on the trust path: " + "; ".join(
                 f"{c}: " + (", ".join(f"`{f}` {code_lines(f)}" for f in PATH[c][1]) or "none")
                 for c, _ in COLUMNS) + ".",
             "", "Config lines: non-comment lines of the column's `gateway/*.yaml`, plus the Keycloak clients "
             "it uses from `infra/keycloak/realm.json` (as JSON, 2-space indent): " + "; ".join(
                 f"{c}: " + ", ".join(CONFIG[c][1]) for c, _ in COLUMNS)
             + ". Realm users and settings, shared by every column, are not attributed."]
    (R / "cost.md").write_text("\n".join(cost) + "\n")
    readme = (ROOT / "README.md").read_text()
    readme = inject(readme, "MATRIX", out[4:])
    readme = inject(readme, "COST", cost[2:])
    (ROOT / "README.md").write_text(readme)
    print("\n".join(out))
    print()
    print("\n".join(cost))


if __name__ == "__main__":
    main()
