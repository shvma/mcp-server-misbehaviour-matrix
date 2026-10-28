#!/usr/bin/env python3
"""Decision service behind the gateway's extAuthz (columns a and a+b).

For each tools/call the gateway posts {"agent", "tool": {"server", "name"}, "arguments"}. The service
asks the MCP server for its tool list itself, hashes the definition it gets back, and sends the call
with that live hash to OPA. Allow only if OPA says allow. Any error, timeout or malformed input denies
(fail closed). There is no cache on purpose: a cache of N seconds is N seconds in which a changed
definition still passes.

Standard library only.
"""
import json
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from defhash import definition_hash  # noqa: E402
from net import McpClient  # noqa: E402

CHECKER_NAME = "definition-check"


def live_definition_hash(url, tool_name, timeout):
    """Ask the MCP server for tools/list now and hash the named tool's definition."""
    client = McpClient(url, name=CHECKER_NAME, timeout=timeout)
    status, resp = client.list_tools()
    if status != 200:
        raise LookupError(f"tools/list status {status}")
    for tool in resp["result"]["tools"]:
        if tool.get("name") == tool_name:
            return definition_hash(tool)
    raise LookupError("tool not in tools/list")


def ask_opa(opa_url, payload, timeout):
    req = urllib.request.Request(opa_url, data=json.dumps({"input": payload}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())["result"]


def decide(call, opa_url, targets, timeout=2.0):
    """Return (allow, reasons). Every failure is a denial."""
    if not isinstance(call, dict) or not isinstance(call.get("tool"), dict):
        return False, ["bad_request"]
    url = targets.get(call["tool"].get("server"))
    try:
        if not url:
            raise LookupError("unknown target")
        live = live_definition_hash(url, call["tool"].get("name"), timeout)
    except Exception:
        return False, ["definition_unavailable"]
    payload = {**call, "tool": {**call["tool"], "definition_sha256": live}}
    try:
        result = ask_opa(opa_url, payload, timeout)
        allow = result["allow"] is True
        reasons = sorted(result.get("deny_reasons", []))
    except Exception:
        return False, ["pdp_unavailable"]
    return (True, []) if allow else (False, reasons or ["pdp_denied"])


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            call = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"null")
        except Exception:
            call = None
        allow, reasons = decide(call, self.server.opa_url, self.server.targets, self.server.timeout)
        # Reasons are not returned: the gateway relays this body to the agent, and the agent is
        # untrusted; reasons would map the policy for it. They go to the log below.
        body = json.dumps({"allow": allow}).encode()
        self.send_response(200 if allow else 403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        tool = call.get("tool", {}) if isinstance(call, dict) else {}
        print(json.dumps({"tool": f"{tool.get('server')}/{tool.get('name')}",
                          "agent": call.get("agent") if isinstance(call, dict) else None,
                          "allow": allow, "reasons": reasons}), flush=True)

    def log_message(self, *args):
        pass


def make_server(port, opa_url, targets, timeout=2.0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.opa_url, srv.targets, srv.timeout = opa_url, targets, timeout
    return srv


def parse_targets(spec):
    """'notes=http://127.0.0.1:3001/mcp,other=http://...' -> dict"""
    return dict(item.split("=", 1) for item in spec.split(",") if "=" in item)


if __name__ == "__main__":
    srv = make_server(int(os.environ.get("PORT", "9191")),
                      os.environ.get("OPA_URL", "http://127.0.0.1:8181/v1/data/mcp/admission"),
                      parse_targets(os.environ.get("MCP_TARGETS", "notes=http://127.0.0.1:3001/mcp")),
                      float(os.environ.get("CHECK_TIMEOUT", "2")))
    srv.serve_forever()
