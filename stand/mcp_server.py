#!/usr/bin/env python3
"""Учебный MCP-сервер «notes» (streamable HTTP, ответы JSON). Один инструмент read(path).
Каждый дошедший до сервера tools/call пишется строкой в файл CALLS_LOG: так видно,
какие вызовы шлюз пропустил, а какие остановил до сервера."""
import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL = {"name": "read", "description": "Прочитать заметку по пути",
        "inputSchema": {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}}}
LOG = os.environ.get("CALLS_LOG", "calls.log")


class H(BaseHTTPRequestHandler):
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
        headers = {}
        if method == "initialize":
            result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "notes", "version": "0.1"}}
            headers["Mcp-Session-Id"] = uuid.uuid4().hex
        elif method == "tools/list":
            result = {"tools": [TOOL]}
        elif method == "tools/call":
            p = msg.get("params", {})
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
            result = {"content": [{"type": "text", "text": f"заметка {p.get('arguments', {}).get('path')}"}]}
        else:
            return self._send(200, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no method"}})
        self._send(200, {"jsonrpc": "2.0", "id": mid, "result": result}, headers)

    def do_GET(self):
        self._send(405)

    def do_DELETE(self):
        self._send(200)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "3001"))), H).serve_forever()
