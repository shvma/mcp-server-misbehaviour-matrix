# Threat model of the testbed

Scope: one MCP server reached by an agent through a gateway, acting on a shared data API and able to reach other services of the same organisation. The model covers what the testbed measures and names what it does not.

## Adversary

The MCP server: its code, its operator, or whoever can change either. It is reached through the gateway, it holds whatever credential its installation gives it, and it can open network connections to anything on the host. It does not control the gateway, the IdP, OPA, the adapter or the database.

## Assets

| Asset | Where it lives | Harm if lost |
|---|---|---|
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
5. Decision service → server: the decision service believes the server's answer to its own `tools/list`.

## Threats measured

| ID | The server... | Asset | Boundary | Stopped means |
|---|---|---|---|---|
| C1 | changes its tool description after the definition was pinned | what the agent is told about the tool | 2 | the changed description did not reach the agent, or the agent's call after seeing it did not go through |
| C2 | serves the pinned description to the checker and a changed one to the agent | what the agent is told about the tool | 5 | as C1 |
| C3 | reads another user's note and posts it to an outside collector | other users' data | 3, 4 | the canary appears neither at the collector nor in the agent's answer |
| C4 | writes a row while serving a read | integrity of the data | 3 | the notes table is identical before and after |
| C5 | replays the token it received against the billing service | credentials in transit | 4 | the billing ledger did not grow |
| C6 | answers with text that is not in the database | what the agent is told by the tool | 2 | the agent's answer equals the database text |

C0 is the control: the honest call must work in every column, otherwise a "stopped" in that column could mean "broken".

## Not considered

- **A malicious or manipulated agent.** The agent is a script; it never asks for another user's note or calls a tool it was not given. Controls that limit the agent itself (argument constraints, per-agent tool lists) are present in the policy and covered by unit tests, but no behaviour in the matrix exercises them.
- **What a model does with a poisoned description or a false answer.** The testbed records whether the changed text reached the agent. It does not run a model to see whether the text changes its next action.
- **Data flow across calls.** Every column decides per call. A sequence of individually allowed calls that moves private data to an outside channel is outside the matrix.
- **A server reached without the gateway.** The server's own network position is not constrained; the testbed assumes agents can only reach it through the gateway.
- **Compromise of the gateway, the IdP, OPA, the adapter or the database.** They are trusted components here.
- **MCP methods other than `tools/list` and `tools/call`** (resources, prompts, sampling, notifications).
- **Availability:** slow or flooding servers, resource exhaustion.
- **Network attackers between components.** All traffic is plain HTTP on localhost.
