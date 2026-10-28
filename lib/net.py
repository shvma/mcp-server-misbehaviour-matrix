"""Small HTTP and MCP client helpers (standard library only)."""
import json
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = "http://localhost:8080/realms/stand/protocol/openid-connect/token"


def http(method, url, token=None, body=None, headers=None, timeout=5):
    """One request. Returns (status, parsed body). HTTP errors are data, not exceptions."""
    h = dict(headers or {})
    if token:
        h["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read().decode(), e.code
    except OSError as e:
        return 0, {"error": str(e)}
    try:
        return status, (json.loads(raw) if raw.strip() else None)
    except ValueError:
        return status, raw


def token(form):
    data = urllib.parse.urlencode(form).encode()
    with urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=data), timeout=5) as r:
        return json.load(r)["access_token"]


def user_token(client, secret, user, password):
    return token({"grant_type": "password", "client_id": client, "client_secret": secret,
                  "username": user, "password": password})


def service_token(client, secret):
    return token({"grant_type": "client_credentials", "client_id": client, "client_secret": secret})


class McpClient:
    """Minimal streamable-HTTP MCP client: initialize, tools/list, tools/call."""

    def __init__(self, url, bearer=None, name="client", timeout=5):
        self.url, self.bearer, self.timeout, self.session = url, bearer, timeout, None
        self.status, self.init = self._rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": name, "version": "1.0"}})
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _post(self, obj):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.bearer:
            h["Authorization"] = "Bearer " + self.bearer
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(obj).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                self.session = r.headers.get("Mcp-Session-Id") or self.session
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except OSError as e:
            return 0, json.dumps({"error": str(e)})

    def _rpc(self, method, params, mid=1):
        status, raw = self._post({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
        for line in raw.splitlines():
            if line.startswith("data:"):
                return status, json.loads(line[5:])
        try:
            return status, (json.loads(raw) if raw.strip() else None)
        except ValueError:
            return status, raw

    def list_tools(self):
        return self._rpc("tools/list", {}, 2)

    def call(self, name, arguments):
        return self._rpc("tools/call", {"name": name, "arguments": arguments}, 3)
