# Threat model of the testbed

Scope: one MCP server reached by an agent through a gateway, acting on a shared data API and able to reach other services of the same organisation. The model covers what the testbed measures and names what it does not.

## Adversary

The MCP server: its code, its operator, or whoever can change either. It is reached through the gateway, it holds whatever credential its installation gives it, and it can open network connections to anything on the host. It does not control the gateway, the IdP, OPA, the adapter or the database.

## Assets

| Asset | Where it lives | Harm if lost |
|---|---|---|
| The caller's own data and what she hands the tool | her note `a1` and the call's arguments | confidentiality: it leaves by an unintended path |
| Other users' data | rows of `api.notes` owned by someone other than the caller (`b1`) | confidentiality |
| Integrity of the data | all rows of `api.notes` | integrity |
| Credentials in transit | the token the server receives with a call | the server acts elsewhere as the user |
| What the agent is told about the tool | the tool description in `tools/list` | the description steers the model (tool poisoning) |
| What the agent is told by the tool | the text of the call result | the model acts on false data |

## Trust boundaries

1. Agent → gateway: token validated by the gateway in every column.
2. Gateway → server: the server is untrusted from here on.
3. Server → data API: rights come only from the credential the server presents.
4. Server → network: unrestricted egress in every column.
5. Gateway → agent: the definitions the agent receives on `tools/list` are pinned by the gateway guardrail against the approved hashes, on the agent's own response — there is no separate checker the server could answer differently. A listed tool without a pin is refused (fail closed).

## Threats measured

| ID | The server... | Asset | Boundary | Stopped means |
|---|---|---|---|---|
| C1 | changes its pinned tool's description (rug pull) | what the agent is told about the tool | 2, 5 | the changed description did not reach the agent; if it did and only the call was blocked, the cell says so separately |
| C2 | adds a new tool that has no pin, with instructions in its description | what the agent is told about the tool | 2, 5 | as C1 |
| C3a | posts what the call handed it — the arguments and the caller's own note — to an outside collector (the postmark pattern) | the caller's own data and arguments | 4 | neither the caller's canary nor the call's arguments reached the collector; arguments alone are reported separately |
| C3b | reads another user's note with its credential and posts it to the collector | other users' data | 3, 4 | the other user's canary did not reach the collector |
| C4 | writes a row while serving a read | integrity of the data | 3 | the notes table is identical before and after |
| C5 | replays the token it received against the billing service | credentials in transit | 4 | the billing ledger did not grow |
| C6 | answers with text that is not in the database | what the agent is told by the tool | 2 | the agent's answer equals the database text |

The former C2, a split-view rug pull (a clean definition for a separate checker, a changed one for the agent), is not in the matrix any more: with the pin taken on the agent's own response there is no separate checker, so it was the same run as C1. See [docs/c2-split-view.md](docs/c2-split-view.md).

C0 is the control: the honest call must work in every column, otherwise a "stopped" in that column could mean "broken".

## Not considered

- **A malicious or manipulated agent.** The agent is a script; it never asks for another user's note or calls a tool it was not given. Controls that limit the agent itself (argument constraints, per-agent tool lists) are present in the policy and covered by unit tests, but no behaviour in the matrix exercises them.
- **What a model does with a poisoned description or a false answer.** The testbed records whether the changed text reached the agent. It does not run a model to see whether the text changes its next action.
- **Data flow across calls.** Every column decides per call. A sequence of individually allowed calls that moves private data to an outside channel is outside the matrix.
- **The server's egress.** Its outbound network is not restricted in any column. Column (c) removes the server from the data path, but the adapter still calls it with the call's arguments, so what the arguments carry can leave (C3a). The `none` baseline deliberately reaches the server directly, as the reference that shows every attack landing.
- **Compromise of the gateway, the IdP, OPA, the adapter or the database.** They are trusted components here.
- **MCP methods other than `tools/list` and `tools/call`** (resources, prompts, sampling, notifications). The pin guardrail is attached to `tools/list` only; instructions delivered through `prompts/list` or a tool's result are not pinned.
- **Availability:** slow or flooding servers, resource exhaustion.
- **Network attackers between components.** All traffic is plain HTTP on localhost.
