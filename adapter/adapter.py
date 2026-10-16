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


def post_json(url, payload, timeout):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError(f"status {resp.status}")
        return json.loads(resp.read())


def decide(call, opa_url, flow_url="", timeout=2.0):
    """Вернуть (allow, reasons). Любая ошибка даёт отказ."""
    if not isinstance(call, dict) or not isinstance(call.get("tool"), dict):
        return False, ["bad_request"]
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
        allow, reasons = decide(call, cfg.opa_url, cfg.flow_url, cfg.timeout)
        body = json.dumps({"allow": allow, "reasons": reasons}, ensure_ascii=False).encode("utf-8")
        self.send_response(200 if allow else 403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        tool = call.get("tool", {}) if isinstance(call, dict) else {}
        print(json.dumps({"tool": f"{tool.get('server')}/{tool.get('name')}",
                          "agent": call.get("agent") if isinstance(call, dict) else None,
                          "allow": allow, "reasons": reasons}, ensure_ascii=False), flush=True)

    def log_message(self, *args):
        pass


def make_server(port, opa_url, flow_url="", timeout=2.0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.opa_url, srv.flow_url, srv.timeout = opa_url, flow_url, timeout
    return srv


if __name__ == "__main__":
    srv = make_server(int(os.environ.get("PORT", "9191")),
                      os.environ.get("OPA_URL", "http://127.0.0.1:8181/v1/data/admission"),
                      os.environ.get("FLOW_URL", ""),
                      float(os.environ.get("CHECK_TIMEOUT", "2")))
    print(f"adapter on 127.0.0.1:{srv.server_address[1]}", file=sys.stderr)
    srv.serve_forever()
