# C2: the server shows the checker one description and the agent another

## What happened on the testbed

The decision service pins the tool by hashing the definition it receives from its own `tools/list` request, sent directly to the server with `clientInfo.name = "definition-check"`. The agent's `tools/list` goes through the gateway. In the C2 runs the server answered:

| Session | `clientInfo.name` seen by the server | Description served |
|---|---|---|
| decision service | `definition-check` | pinned (hash matches) |
| agent via agentgateway | `agent` | changed, with marker `TAMPERED-7c1e` |

The server trace records `served_changed_description` with `client: "agent"` only (`results/raw.jsonl`, rows with `"behavior": "C2"`). agentgateway 1.6.0 passed the agent's `clientInfo` through to the server, so the name was enough to tell the two apart. The decision service saw the pinned hash, OPA allowed the call, and the agent received the changed description and a successful call result. The outcome is **not stopped** in columns (a) and (a+b), and in (b), which has no definition check.

## Other ways a server can tell the checker apart

These were not tested. Each is enough on its own, and none depends on `clientInfo`:

- the checker's request carries no token (true for this decision service), while the agent's requests reach the server with an exchanged user token in column (a+b);
- the checker opens its own session; the agent's calls arrive in another;
- source address and timing: the checker connects from the decision service host, immediately before each call.

Making the checker look like the agent removes one cue at a time. It does not change the structure of the problem.

## Why a live fingerprint check misses it

The check and the delivery are two different requests. The fingerprint proves what the server said to the checker, not what it said to the agent. Any control that fetches the definition on its own channel, at review time or per call, has the same gap; pinning only moves the moment of the check.

## What open sources propose

- **Fingerprinting at scan time.** Microsoft's agent-governance-toolkit defines a tool fingerprint as *"A cryptographic hash of a tool's description and schema, used to detect rug pulls"* ([MCP-SECURITY-GATEWAY-1.0](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/MCP-SECURITY-GATEWAY-1.0.md)). Its own OWASP mapping states *"`check_rug_pull()` runs at scan-time; MCPGateway does not invoke scanner at execution time"* ([owasp-llm-top10-mapping.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/compliance/owasp-llm-top10-mapping.md)). A scan is a separate request, so it has the gap described above.
- **Signed tool definitions.** ETDI proposes that *"This entire definition is then digitally signed using the provider's private key"*, with changes that *"necessitate a new version number, triggering user re-approval"* ([arXiv:2506.01333](https://arxiv.org/abs/2506.01333)). If the client verifies the signature on the definition it actually received, a split view requires the provider to sign the changed definition too, and a new version triggers re-approval. This needs provider and client support for the extension; it is not tested here.

## A direction this testbed does not test

Compare the definition at the point where it is delivered: the component that relays `tools/list` to the agent hashes or filters each definition against the pin, so that what was checked is what was delivered. Whether agentgateway 1.6.0 can do this through configuration was not established; the testbed does not implement it.

Column (c) closes C2 by design: the agent receives the adapter's own description, and the server's descriptions never reach it.
