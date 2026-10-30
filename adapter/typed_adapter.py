#!/usr/bin/env python3
"""Typed adapter (column c): trusted code that exposes a fixed set of operations to the agent.

The adapter is the MCP server the gateway talks to. It
  * publishes its own tool definitions; nothing the third-party server describes reaches the agent;
  * verifies the caller's token itself and takes the user from it;
  * performs the described operation against the data API with its own read-only account,
    selecting only the caller's rows;
  * still invokes the third-party server, without any credential, and drops its output.
    The server keeps running its own logic; it has no rights to act with and no channel to the agent.
    It does receive the call's ARGUMENTS, and nothing here limits where it sends them (behaviour C3a:
    in postmark-mcp the leaked data was exactly the arguments, the mail being sent). For read_note
    the argument is a note id; for a tool whose arguments are the payload, this is the whole leak.

Adding a tool means adding one entry to OPERATIONS and one function. Standard library + lib/.
"""
import json
import os
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import jwtcheck  # noqa: E402
import net  # noqa: E402
from net import McpClient  # noqa: E402

DATA_URL = os.environ.get("DATA_URL", "http://localhost:3030")
UPSTREAM = os.environ.get("UPSTREAM", "http://127.0.0.1:3001/mcp")
AUDIENCE = os.environ.get("AUDIENCE", "mcp-gateway")
_svc_token = None


def data_token():
    global _svc_token
    if _svc_token is None:
        _svc_token = net.service_token("typed-adapter", "adapter-secret")
    return _svc_token


# --- per-tool code: this block is what a new tool costs -------------------------------------
READ_NOTE = {"name": "read_note", "description": "Read one note by its id and return its text.",
             "inputSchema": {"type": "object", "required": ["id"], "additionalProperties": False,
                             "properties": {"id": {"type": "string", "pattern": "^[a-z][0-9]+$"}}}}


def read_note(user, args):
    note_id = args.get("id")
    if set(args) != {"id"} or not isinstance(note_id, str) or not re.fullmatch(r"[a-z][0-9]+", note_id):
        raise ValueError("bad arguments")
    status, rows = net.http("GET", f"{DATA_URL}/notes?id=eq.{note_id}&owner=eq.{user}", data_token())
    if status != 200 or not isinstance(rows, list):
        raise RuntimeError("data api error")
    return rows[0]["body"] if rows else ""
# ---------------------------------------------------------------------------------------------


OPERATIONS = {"read_note": (READ_NOTE, read_note)}


def consult_upstream(name, args):
    """Invoke the third-party server with no credential; its answer is discarded. The arguments are
    passed as they came: the server sees them (see the module docstring)."""
    try:
        McpClient(UPSTREAM, name="typed-adapter").call(name, args)
    except Exception:
        pass


def handle_call(bearer, params):
    claims = jwtcheck.verify(bearer or "", AUDIENCE)  # ValueError -> refused
    name, args = params.get("name"), params.get("arguments") or {}
    if name not in OPERATIONS:
        raise ValueError("unknown tool")
    consult_upstream(name, args)
    return OPERATIONS[name][1](claims["preferred_username"], args)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj=None, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode() if obj is not None else b""
        self.send_response(code)
        if obj is not None:
            self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:
            return self._send(202)
        auth = self.headers.get("Authorization", "")
        headers = {}
        if method == "initialize":
            headers["Mcp-Session-Id"] = uuid.uuid4().hex
            result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "notes-adapter", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": [spec for spec, _ in OPERATIONS.values()]}
        elif method == "tools/call":
            try:
                text = handle_call(auth[7:] if auth.startswith("Bearer ") else None, msg.get("params", {}))
            except Exception:
                return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                        "error": {"code": -32602, "message": "call refused"}})
            result = {"content": [{"type": "text", "text": text}]}
        else:
            return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                    "error": {"code": -32601, "message": "method not found"}})
        self._send(200, {"jsonrpc": "2.0", "id": mid, "result": result}, headers)

    def do_GET(self):
        self._send(405)

    def do_DELETE(self):
        self._send(200)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "3002"))), Handler).serve_forever()
