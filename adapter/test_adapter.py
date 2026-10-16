"""Тесты адаптера на настоящем сервере OPA (подпроцесс) и поддельной проверке потока."""
import json
import os
import shutil
import socket
import subprocess
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import adapter

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OPA = os.environ.get("OPA") or shutil.which("opa") or str(Path.home() / ".local/bin/opa")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(agent="agent-a", server="demo", name="reader", sha="h1", args=None):
    return {"agent": agent, "tool": {"server": server, "name": name, "definition_sha256": sha},
            "arguments": args or {}}


class Flow(BaseHTTPRequestHandler):
    mode = "allow"
    calls = 0

    def do_POST(self):
        Flow.calls += 1
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if Flow.mode == "slow":
            time.sleep(1.5)
        if Flow.mode == "error":
            self.send_response(500)
            self.end_headers()
            return
        body = json.dumps({"allow": Flow.mode in ("allow", "slow")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class AdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        port = free_port()
        cls.opa = subprocess.Popen(
            [OPA, "run", "--server", "--addr", f"127.0.0.1:{port}",
             str(ROOT / "policy/admission.rego"), str(HERE / "fixtures/data.json")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.opa_url = f"http://127.0.0.1:{port}/v1/data/admission"
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.2)
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise RuntimeError("OPA не поднялся")
        cls.flow = ThreadingHTTPServer(("127.0.0.1", 0), Flow)
        threading.Thread(target=cls.flow.serve_forever, daemon=True).start()
        cls.flow_url = f"http://127.0.0.1:{cls.flow.server_address[1]}/check"

    @classmethod
    def tearDownClass(cls):
        cls.opa.terminate()
        cls.opa.wait(5)
        cls.flow.shutdown()
        cls.flow.server_close()

    def setUp(self):
        Flow.mode, Flow.calls = "allow", 0

    # --- конфигурация «только OPA» ---

    def test_opa_allows(self):
        self.assertEqual(adapter.decide(call(), self.opa_url), (True, []))

    def test_opa_denies_with_reason(self):
        self.assertEqual(adapter.decide(call(agent="agent-b"), self.opa_url), (False, ["agent_not_admitted"]))

    def test_unknown_tool(self):
        self.assertEqual(adapter.decide(call(name="other"), self.opa_url), (False, ["no_decision"]))

    def test_changed_definition(self):
        self.assertEqual(adapter.decide(call(sha="h-new"), self.opa_url), (False, ["definition_changed"]))

    def test_pdp_down_fails_closed(self):
        dead = f"http://127.0.0.1:{free_port()}/v1/data/admission"
        self.assertEqual(adapter.decide(call(), dead, timeout=0.5), (False, ["pdp_unavailable"]))

    def test_pdp_wrong_path_fails_closed(self):
        wrong = self.opa_url.replace("/admission", "/nothing_here")
        self.assertEqual(adapter.decide(call(), wrong), (False, ["pdp_unavailable"]))

    def test_bad_request(self):
        for bad in (None, "x", {}, {"tool": "x"}):
            self.assertEqual(adapter.decide(bad, self.opa_url), (False, ["bad_request"]))

    # --- конфигурация «OPA и проверка потока» ---

    def test_both_allow(self):
        self.assertEqual(adapter.decide(call(), self.opa_url, self.flow_url), (True, []))

    def test_flow_denies(self):
        Flow.mode = "deny"
        self.assertEqual(adapter.decide(call(), self.opa_url, self.flow_url), (False, ["flow_denied"]))

    def test_flow_error_fails_closed(self):
        Flow.mode = "error"
        self.assertEqual(adapter.decide(call(), self.opa_url, self.flow_url), (False, ["flow_unavailable"]))

    def test_flow_timeout_fails_closed(self):
        Flow.mode = "slow"
        self.assertEqual(adapter.decide(call(), self.opa_url, self.flow_url, timeout=0.5), (False, ["flow_unavailable"]))

    def test_flow_not_asked_when_pdp_denies(self):
        adapter.decide(call(agent="agent-b"), self.opa_url, self.flow_url)
        self.assertEqual(Flow.calls, 0)

    # --- HTTP целиком, как его увидит шлюз ---

    def test_http_status_codes(self):
        srv = adapter.make_server(0, self.opa_url)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/"
        try:
            def post(raw):
                req = urllib.request.Request(url, data=raw, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=2) as r:
                        return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read())
            self.assertEqual(post(json.dumps(call()).encode()), (200, {"allow": True}))
            self.assertEqual(post(json.dumps(call(agent="agent-b")).encode()), (403, {"allow": False}))
            self.assertEqual(post(b"not json"), (403, {"allow": False}))
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
