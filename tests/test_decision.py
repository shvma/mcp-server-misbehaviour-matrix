"""Decision service against a real OPA server (subprocess) and a fake MCP server."""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "decision"))
import decision  # noqa: E402

OPA = os.environ.get("OPA") or shutil.which("opa") or str(Path.home() / ".local/bin/opa")
TOOL = json.loads((ROOT / "server/tool.json").read_text())


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(agent="agent", server="notes", name="read_note", args=None):
    return {"agent": agent, "tool": {"server": server, "name": name}, "arguments": args or {"id": "a1"}}


class FakeMCP(BaseHTTPRequestHandler):
    """Serves tools/list with FakeMCP.tool."""
    tool = None

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if msg.get("id") is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        result = {"tools": [FakeMCP.tool]} if msg.get("method") == "tools/list" else {"protocolVersion": "2025-06-18"}
        body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Mcp-Session-Id", "s1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class DecisionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        port = free_port()
        cls.opa = subprocess.Popen([OPA, "run", "--server", "--addr", f"127.0.0.1:{port}",
                                    str(ROOT / "policy/admission.rego"), str(ROOT / "policy/data.json")],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.opa_url = f"http://127.0.0.1:{port}/v1/data/mcp/admission"
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2)
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise RuntimeError("OPA did not start")
        cls.mcp = ThreadingHTTPServer(("127.0.0.1", 0), FakeMCP)
        threading.Thread(target=cls.mcp.serve_forever, daemon=True).start()
        cls.targets = {"notes": f"http://127.0.0.1:{cls.mcp.server_address[1]}/mcp"}

    @classmethod
    def tearDownClass(cls):
        cls.opa.terminate()
        cls.opa.wait(5)
        cls.mcp.shutdown()
        cls.mcp.server_close()

    def setUp(self):
        FakeMCP.tool = dict(TOOL)

    def decide(self, c, **kw):
        return decision.decide(c, kw.pop("opa_url", self.opa_url), kw.pop("targets", self.targets), **kw)

    def test_pinned_definition_allows(self):
        self.assertEqual(self.decide(call()), (True, []))

    def test_changed_definition_denies(self):
        FakeMCP.tool = dict(TOOL, description=TOOL["description"] + " changed")
        self.assertEqual(self.decide(call()), (False, ["definition_changed"]))

    def test_other_agent_denied(self):
        self.assertEqual(self.decide(call(agent="other")), (False, ["agent_not_admitted"]))

    def test_argument_outside_pattern_denied(self):
        self.assertEqual(self.decide(call(args={"id": "../b1"})), (False, ["argument_not_allowed"]))

    def test_tool_missing_from_list(self):
        self.assertEqual(self.decide(call(name="absent")), (False, ["definition_unavailable"]))

    def test_unknown_target(self):
        self.assertEqual(self.decide(call(server="nowhere")), (False, ["definition_unavailable"]))

    def test_mcp_down_fails_closed(self):
        dead = {"notes": f"http://127.0.0.1:{free_port()}/mcp"}
        self.assertEqual(self.decide(call(), targets=dead, timeout=0.5), (False, ["definition_unavailable"]))

    def test_pdp_down_fails_closed(self):
        dead = f"http://127.0.0.1:{free_port()}/v1/data/mcp/admission"
        self.assertEqual(self.decide(call(), opa_url=dead, timeout=0.5), (False, ["pdp_unavailable"]))

    def test_pdp_wrong_path_fails_closed(self):
        wrong = self.opa_url.replace("/mcp/admission", "/nothing_here")
        self.assertEqual(self.decide(call(), opa_url=wrong), (False, ["pdp_unavailable"]))

    def test_bad_request(self):
        for bad in (None, "x", {}, {"tool": "x"}):
            self.assertEqual(self.decide(bad), (False, ["bad_request"]))

    def test_http_status_and_no_reasons_in_body(self):
        srv = decision.make_server(0, self.opa_url, self.targets)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/check"

        def post(raw):
            req = urllib.request.Request(url, data=raw, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=2) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        try:
            self.assertEqual(post(json.dumps(call()).encode()), (200, {"allow": True}))
            self.assertEqual(post(json.dumps(call(agent="other")).encode()), (403, {"allow": False}))
            self.assertEqual(post(b"not json"), (403, {"allow": False}))
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
