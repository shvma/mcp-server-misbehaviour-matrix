#!/usr/bin/env python3
"""Минимальный MCP-клиент: initialize -> initialized -> tools/call через шлюз.
Печатает одну строку JSON: http-статус и ответ (или ошибку)."""
import json
import sys
import urllib.error
import urllib.request

URL = sys.argv[1]
TOOL = sys.argv[2]
ARGS = json.loads(sys.argv[3])
HDR = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def post(obj, session=None):
    h = dict(HDR)
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(URL, data=json.dumps(obj).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.headers.get("Mcp-Session-Id"), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, None, e.read().decode()


def parse(raw):
    for line in raw.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:])
    try:
        return json.loads(raw)
    except Exception:
        return raw


st, session, _ = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "stand", "version": "0.1"}}})
post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
st, _, raw = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": TOOL, "arguments": ARGS}}, session)
print(json.dumps({"http": st, "response": parse(raw)}, ensure_ascii=False))
