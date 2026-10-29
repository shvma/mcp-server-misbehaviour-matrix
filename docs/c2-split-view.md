# C2: a split-view rug pull, and why the pin is on the agent's own response

## The threat

A rug pull (C1) changes the tool description after it was approved. The sharper version (C2) is a
*split view*: the server shows a definition check one (clean) description and the agent another
(tampered) one. A pin that fetches the definition on its **own** request then proves only what the
server said to the checker, not what it said to the agent. The check and the delivery are two
different requests; that gap does not depend on any one cue the server keys on (a client name, the
absence of a token, source address, timing). Removing one cue at a time does not change the structure.

An earlier version of this testbed had exactly that weakness: the decision service fetched `tools/list`
itself with `clientInfo.name = "definition-check"`, and the server simply served the clean definition
to that name and the tampered one to the agent. C2 was **not stopped**. That check was rigged to the
testbed, and a real server would fingerprint the checker some other way.

## What this testbed does now

The pin is checked by the gateway on the **agent's own `tools/list` response**, with agentgateway's
`mcpGuardrails` running a processor in the `response` phase ([guardrail/pin_processor.py](../guardrail/pin_processor.py),
config in [gateway/a.yaml](../gateway/a.yaml) and [gateway/ab.yaml](../gateway/ab.yaml)). The processor
hashes each definition in the response the agent is about to receive and denies the call
(`definition_changed`, JSON-RPC `-32001`) when it does not match the pin from `policy/data.json`.

There is no separate checker to fool: the pin is computed on the exact bytes the agent gets. A server
that serves a changed description cannot hide it, because that changed description *is* what the pin
sees. In the matrix, C1 **and** C2 are **stopped** in columns (a) and (a+b); in `results/raw.jsonl` the
C2 rows for those columns carry a `tools/list` error with `definition_changed`, and the tampered
marker `TAMPERED-7c1e` never reaches the agent.

## The structural point (unchanged)

The fix is not "a better fingerprint"; it is **where** the fingerprint is taken. Any pin on a separate
channel keeps the gap:

- **Fingerprinting at scan time.** Microsoft's agent-governance-toolkit defines a tool fingerprint as *"A cryptographic hash of a tool's description and schema, used to detect rug pulls"* ([MCP-SECURITY-GATEWAY-1.0](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/MCP-SECURITY-GATEWAY-1.0.md)); its own mapping states *"`check_rug_pull()` runs at scan-time; MCPGateway does not invoke scanner at execution time"* ([owasp-llm-top10-mapping.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/compliance/owasp-llm-top10-mapping.md)). A scan is a separate request, so it has the gap above.
- **Signed tool definitions.** ETDI proposes that *"This entire definition is then digitally signed using the provider's private key"*, with changes that *"necessitate a new version number, triggering user re-approval"* ([arXiv:2506.01333](https://arxiv.org/abs/2506.01333)). If the client verifies the signature on the definition it *actually received*, a split view requires the provider to sign the changed definition too. This needs provider and client support for the extension; it is the same idea (bind the check to the delivered bytes) by a different mechanism, and is not tested here.

Pinning on the response binds the check to the delivered bytes without a protocol extension, at the
cost of a component on the path (the gRPC guardrail) that must parse the `tools/list` response.

Column (c) closes C2 differently and completely: the agent receives the adapter's own description, so
no description from the server, changed or not, ever reaches it.
