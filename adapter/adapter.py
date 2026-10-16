#!/usr/bin/env python3
"""Адаптер решения: стоит за extAuthz шлюза и сводит две проверки в одно решение.

Конфигурации:
  * только OPA:        FLOW_URL не задан;
  * OPA и проверка потока: FLOW_URL указывает на проверку потока (обёртка над OpenAPPA).

Правило одно: разрешить, только если OPA сказал «да» и (если включена) проверка потока сказала «да».
Любая ошибка, таймаут, неожиданный ответ или кривой запрос = отказ (fail-closed).

Интерфейс проверки потока: POST JSON-вызова, ответ {"allow": true|false}. Это наш контракт;
перевод в формат хука OpenAPPA — отдельная обёртка, её формат сверяется с документацией OpenAPPA.

Только стандартная библиотека Python 3.9.
"""
import json
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gen"))
from defhash import definition_hash  # noqa: E402


def post_json(url, payload, timeout):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError(f"status {resp.status}")
        return json.loads(resp.read())


def _mcp_post(url, obj, session, timeout):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if session:
        headers["Mcp-Session-Id"] = session
    req = urllib.request.Request(url, data=json.dumps(obj).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw, sid = resp.read().decode("utf-8"), resp.headers.get("Mcp-Session-Id")
    for line in raw.splitlines():
        if line.startswith("data:"):
            return sid, json.loads(line[5:])
    return sid, (json.loads(raw) if raw.strip() else None)


def live_definition_hash(url, tool_name, timeout):
    """Спросить у MCP-сервера tools/list и посчитать хеш определения инструмента прямо сейчас."""
    sid, _ = _mcp_post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "admission-adapter", "version": "0.1"}}},
                       None, timeout)
    _mcp_post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid, timeout)
    _, resp = _mcp_post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid, timeout)
    for tool in resp["result"]["tools"]:
        if tool.get("name") == tool_name:
            return definition_hash(tool)
    raise LookupError("инструмента нет в tools/list")


def decide(call, opa_url, flow_url="", timeout=2.0, targets=None):
    """Вернуть (allow, reasons). Любая ошибка даёт отказ.

    targets: {имя_цели_шлюза: URL MCP-сервера}. Если задано, хеш определения берётся
    у сервера в момент вызова, а то, что прислал шлюз, игнорируется. Кэша нет намеренно:
    кэш на N секунд — это окно в N секунд, когда подменённый инструмент ещё проходит.
    """
    if not isinstance(call, dict) or not isinstance(call.get("tool"), dict):
        return False, ["bad_request"]
    if targets:
        url = targets.get(call["tool"].get("server"))
        try:
            if not url:
                raise LookupError("неизвестная цель")
            live = live_definition_hash(url, call["tool"].get("name"), timeout)
        except Exception:
            return False, ["definition_unavailable"]
        call = {**call, "tool": {**call["tool"], "definition_sha256": live}}
    try:
        result = post_json(opa_url, {"input": call}, timeout).get("result")
        allow = result["allow"] is True
        reasons = sorted(result.get("deny_reasons", []))
    except Exception:
        return False, ["pdp_unavailable"]
    if not allow:
        return False, reasons or ["pdp_denied"]
    if flow_url:
        try:
            if post_json(flow_url, call, timeout).get("allow") is not True:
                return False, ["flow_denied"]
        except Exception:
            return False, ["flow_unavailable"]
    return True, []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            call = json.loads(self.rfile.read(length) or b"null")
        except Exception:
            call = None
        cfg = self.server
        allow, reasons = decide(call, cfg.opa_url, cfg.flow_url, cfg.timeout, cfg.targets)
        # Причины отказа агенту не отдаём: шлюз пробрасывает тело ответа клиенту, а по модели
        # угроз агент враждебен — причины рисуют ему карту политики. Причины пишутся в журнал ниже.
        body = json.dumps({"allow": allow}).encode("utf-8")
        self.send_response(200 if allow else 403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        tool = call.get("tool", {}) if isinstance(call, dict) else {}
        line = {"tool": f"{tool.get('server')}/{tool.get('name')}",
                "agent": call.get("agent") if isinstance(call, dict) else None,
                "allow": allow, "reasons": reasons}
        if cfg.log_input:
            line["input"] = call  # отладка стенда: аргументы могут быть чувствительными
        print(json.dumps(line, ensure_ascii=False), flush=True)

    def log_message(self, *args):
        pass


def make_server(port, opa_url, flow_url="", timeout=2.0, log_input=False, targets=None):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.opa_url, srv.flow_url, srv.timeout, srv.log_input = opa_url, flow_url, timeout, log_input
    srv.targets = targets or {}
    return srv


def parse_targets(spec):
    """'notes=http://127.0.0.1:3001/mcp,wiki=http://...' -> dict"""
    return dict(item.split("=", 1) for item in spec.split(",") if "=" in item)


if __name__ == "__main__":
    srv = make_server(int(os.environ.get("PORT", "9191")),
                      os.environ.get("OPA_URL", "http://127.0.0.1:8181/v1/data/admission"),
                      os.environ.get("FLOW_URL", ""),
                      float(os.environ.get("CHECK_TIMEOUT", "2")),
                      os.environ.get("ADAPTER_LOG_INPUT") == "1",
                      parse_targets(os.environ.get("MCP_TARGETS", "")))
    print(f"adapter on 127.0.0.1:{srv.server_address[1]}", file=sys.stderr)
    srv.serve_forever()
