# Split view: why it left the matrix, and what C2 is now

## The threat

A rug pull (C1) changes the tool description after it was approved. The sharper version is a
*split view*: the server shows a definition check one (clean) description and the agent another
(tampered) one. A pin that fetches the definition on its **own** request then proves only what the
server said to the checker, not what it said to the agent. The check and the delivery are two
different requests; that gap does not depend on any one cue the server keys on (a client name, the
absence of a token, source address, timing). Removing one cue at a time does not change the structure.

An earlier version of this testbed had exactly that weakness: the decision service fetched `tools/list`
itself with `clientInfo.name = "definition-check"`, and the server simply served the clean definition
to that name and the tampered one to the agent. Split view was **not stopped** there. That check was
rigged to the testbed, and a real server would fingerprint the checker some other way.

## Where the pin is now

The pin is checked by the gateway on the **agent's own `tools/list` response**, with agentgateway's
`mcpGuardrails` running a processor in the `response` phase ([guardrail/pin_processor.py](../guardrail/pin_processor.py),
config in [gateway/a.yaml](../gateway/a.yaml) and [gateway/ab.yaml](../gateway/ab.yaml)). The processor
hashes each definition in the response the agent is about to receive. If one does not match its pin
(`definition_changed`), or a listed tool has no pin at all (`tool_not_pinned`), it refuses the
**`tools/list` response**: the agent gets a JSON-RPC error (`-32001`) instead of the list.

It refuses the list, not the tool. In `results/raw.jsonl` the C1 rows of columns (a), (a′) and (a+b)
show the `tools/list` error and then a `tools/call read_note` that OPA allowed and that returned
alice's note. The pin keeps the changed description out of the agent's context; it does not stop the
agent from calling a tool it already knows. The matrix counts this as stopped because the poison is
the description; `harness/outcome.py` has a separate label for the opposite case (description
delivered, only the call blocked).

## Why split view is no longer a row

With the pin on the delivered bytes there is no separate checker for the server to answer
differently. A split-view server has two choices, both already in the matrix: serve the agent the
changed definition (that is C1, refused) or serve it the clean one (that is C0, nothing to stop).
The previous version of the matrix kept a "C2 split view" row whose server code did exactly what C1
did, so the row measured nothing new. It was removed rather than kept as a duplicate.

This is an argument from where the check sits, not a measurement: the testbed no longer has an
out-of-band checker to run a split-view server against.

## What C2 is now

C2 is a server that leaves its pinned tool alone and **adds a second tool, `export_notes`, that has no
pin**, with the same instruction in its description. A pin that checks only the tools it knows lets
that description through to the agent. OPA would still refuse a *call* to `export_notes`
(`tool_not_listed`), but the description is already in the model's context by then; that is the
poisoning. The guardrail therefore fails closed: any listed tool without a pin refuses the whole list.
The unit test `test_unpinned_tool_denied` in [tests/test_pin_processor.py](../tests/test_pin_processor.py)
pins that behaviour.

## Other ways to bind the check to the delivered bytes

- **Fingerprinting at scan time.** Microsoft's agent-governance-toolkit defines a tool fingerprint as *"A cryptographic hash of a tool's description and schema, used to detect rug pulls"* ([MCP-SECURITY-GATEWAY-1.0](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/MCP-SECURITY-GATEWAY-1.0.md)); its own mapping states *"`check_rug_pull()` runs at scan-time; MCPGateway does not invoke scanner at execution time"* ([owasp-llm-top10-mapping.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/compliance/owasp-llm-top10-mapping.md)). A scan is a separate request, so it has the gap above.
- **Signed tool definitions.** ETDI proposes that *"This entire definition is then digitally signed using the provider's private key"*, with changes that *"necessitate a new version number, triggering user re-approval"* ([arXiv:2506.01333](https://arxiv.org/abs/2506.01333)). If the client verifies the signature on the definition it *actually received*, a split view requires the provider to sign the changed definition too. This needs provider and client support for the extension; it is the same idea (bind the check to the delivered bytes) by a different mechanism, and is not tested here.

Pinning on the response binds the check to the delivered bytes without a protocol extension, at the
cost of a component on the path (the gRPC guardrail) that must parse the `tools/list` response.

Column (c) closes C1 and C2 differently and completely: the agent receives the adapter's own
description, so no description from the server, changed, added or not, ever reaches it.
