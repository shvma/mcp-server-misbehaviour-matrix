"""Decision service against a real OPA server (subprocess). No MCP server: the definition pin
moved to the guardrail (see tests/test_pin_processor.py); this service only asks OPA about the
agent, tool and arguments."""
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "decision"))
import decision  # noqa: E402

OPA = os.environ.get("OPA") or shutil.which("opa") or str(Path.home() / ".local/bin/opa")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(agent="agent", server="notes", name="read_note", args=None):
    return {"agent": agent, "tool": {"server": server, "name": name}, "arguments": args or {"id": "a1"}}


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

    @classmethod
    def tearDownClass(cls):
        cls.opa.terminate()
        cls.opa.wait(5)

    def decide(self, c, **kw):
        return decision.decide(c, kw.pop("opa_url", self.opa_url), **kw)

    def test_allowed_call_allows(self):
        self.assertEqual(self.decide(call()), (True, []))

    def test_other_agent_denied(self):
        self.assertEqual(self.decide(call(agent="other")), (False, ["agent_not_admitted"]))

    def test_unlisted_tool_denied(self):
        self.assertEqual(self.decide(call(name="absent")), (False, ["tool_not_listed"]))

    def test_argument_outside_pattern_denied(self):
        self.assertEqual(self.decide(call(args={"id": "../b1"})), (False, ["argument_not_allowed"]))

    def test_unknown_argument_denied(self):
        self.assertEqual(self.decide(call(args={"id": "a1", "admin": False})), (False, ["unknown_argument"]))

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
        srv = decision.make_server(0, self.opa_url)
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
