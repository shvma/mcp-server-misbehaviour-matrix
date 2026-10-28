#!/usr/bin/env python3
"""A neighbouring service of the same organisation. It accepts tokens from the shared IdP whose audience
includes `billing` and records every accepted charge in its ledger (LEDGER, one JSON line per charge).
Behaviour C5 is stopped when the ledger does not grow."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import jwtcheck  # noqa: E402

LEDGER = os.environ.get("LEDGER", "billing-ledger.jsonl")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ping":
            return self._reply(200, {"ok": True})
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            claims = jwtcheck.verify(token, "billing")
        except ValueError as e:
            return self._reply(401, {"accepted": False, "reason": str(e) if token else "no_token"})
        entry = {"accepted": True, "user": claims.get("preferred_username"), "azp": claims.get("azp")}
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self._reply(200, entry)

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "3101"))), Handler).serve_forever()
