#!/usr/bin/env python3
"""ExtMcp guardrail: pin the tool definition on the tools/list RESPONSE (columns a, a+b).

agentgateway (mcpGuardrails, phase=response) hands this gRPC server the tools/list result the
AGENT is about to receive. We hash each listed tool and compare to the pin from policy/data.json.
A mismatch denies the call (definition_changed), and so does a listed tool that has no pin at all
(tool_not_pinned): a server that adds a new tool must not get its description to the agent just
because nobody pinned it. Because the check is on the agent's own response,
there is no separate "checker" a server could serve something else to: a rug pull that changes the
description reaches the pin on the same bytes the agent would get. failureMode is failClosed in the
gateway, so if this server is down the call is denied too.

The pin comes from git (policy/data.json), the same value OPA used before; OPA no longer checks it.
Standard library + grpcio (see requirements.txt).
"""
import hashlib
import json
import os
import sys
from concurrent import futures
from pathlib import Path

import grpc

sys.path.insert(0, str(Path(__file__).resolve().parent / "gen"))
import ext_mcp_pb2 as pb  # noqa: E402
import ext_mcp_pb2_grpc as pbg  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def definition_hash(defn):
    """Canonical JSON -> SHA-256. Must match lib/defhash.py and the pin in policy/data.json."""
    canon = json.dumps(defn, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def load_pins(data_json):
    """{bare tool name -> pinned definition hash} from policy/data.json ('server/name' keys)."""
    tools = json.loads(Path(data_json).read_text())["tools"]
    return {tid.split("/", 1)[-1]: entry["definition_sha256"]
            for tid, entry in tools.items() if "definition_sha256" in entry}


class Servicer(pbg.ExtMcpServicer):
    def __init__(self, pins):
        self.pins = pins

    def CheckRequest(self, req, ctx):
        return pb.McpRequestResult(**{"pass": pb.Pass()})

    def CheckResponse(self, resp, ctx):
        if not resp.method.endswith("/list"):
            return pb.McpResponseResult(**{"pass": pb.Pass()})
        try:
            tools = json.loads(resp.mcp_response or b"{}").get("tools", [])
            if not isinstance(tools, list) or not all(isinstance(t, dict) for t in tools):
                raise ValueError("tools is not a list of objects")
        except (ValueError, AttributeError):
            return self._deny("unparsable_tools_list")
        for tool in tools:
            pin = self.pins.get(tool.get("name"))
            if pin is None:
                # Fail closed. OPA would refuse a *call* to this tool (tool_not_listed), but its
                # description would already be in the agent's context: that is the poisoning.
                sys.stderr.write(f"[pin] DENY {tool.get('name')}: no pin\n")
                return self._deny("tool_not_pinned")
            served = definition_hash(tool)
            if served != pin:
                sys.stderr.write(f"[pin] DENY {tool.get('name')}: {served[:12]} != pin {pin[:12]}\n")
                return self._deny("definition_changed")
        return pb.McpResponseResult(**{"pass": pb.Pass()})

    @staticmethod
    def _deny(reason):
        return pb.McpResponseResult(error=pb.AuthorizationError(
            code=pb.AuthorizationError.PERMISSION_DENIED, reason=reason))


def serve(pins, port):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pbg.add_ExtMcpServicer_to_server(Servicer(pins), server)
    server.add_insecure_port(f"127.0.0.1:{port}")
    server.start()
    sys.stderr.write(f"[pin] listening on {port}, pins={list(pins)}\n")
    sys.stderr.flush()
    server.wait_for_termination()


if __name__ == "__main__":
    serve(load_pins(os.environ.get("DATA_JSON", ROOT / "policy/data.json")),
          int(os.environ.get("PORT", "9201")))
