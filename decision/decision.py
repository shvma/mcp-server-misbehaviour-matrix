#!/usr/bin/env python3
"""Decision service behind the gateway's extAuthz (columns a and a+b).

For each tools/call the gateway posts {"agent", "tool": {"server", "name"}, "arguments"}. The service
asks OPA whether this agent may call this tool with these arguments, and allows only if OPA says so.
Any error, timeout or malformed input denies (fail closed).

The tool DEFINITION is pinned elsewhere: by the gateway's mcpGuardrails on the tools/list response
(guardrail/pin_processor.py), checked on the bytes the agent receives. This service no longer fetches
or hashes the definition, so there is no separate "checker" a server could serve a clean copy to.

Standard library only.
"""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def ask_opa(opa_url, payload, timeout):
    req = urllib.request.Request(opa_url, data=json.dumps({"input": payload}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())["result"]


def decide(call, opa_url, timeout=2.0):
    """Return (allow, reasons). Every failure is a denial."""
    if not isinstance(call, dict) or not isinstance(call.get("tool"), dict):
        return False, ["bad_request"]
    try:
        result = ask_opa(opa_url, call, timeout)
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
        allow, reasons = decide(call, self.server.opa_url, self.server.timeout)
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


def make_server(port, opa_url, timeout=2.0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.opa_url, srv.timeout = opa_url, timeout
    return srv


if __name__ == "__main__":
    srv = make_server(int(os.environ.get("PORT", "9191")),
                      os.environ.get("OPA_URL", "http://127.0.0.1:8181/v1/data/mcp/admission"),
                      float(os.environ.get("CHECK_TIMEOUT", "2")))
    srv.serve_forever()
