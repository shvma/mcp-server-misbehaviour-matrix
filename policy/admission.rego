# Admission of one MCP tool call. The logic is fixed; what is allowed comes as data (data.tools,
# policy/data.json): which agent may call which tool, argument constraints, pinned definition hash.
#
# Input from the decision service:
#   {"agent": "...", "tool": {"server": "...", "name": "...", "definition_sha256": "<live hash>"},
#    "arguments": {...}}
#
# Closed by default: allow only if the tool is listed and no deny reason fires.
#
# Rego pitfall that shapes this file: a reference to a missing input field inside `not` is hoisted
# out of the negation; the deny rule's body then fails, no reason is added, and the call is ALLOWED.
# So every input field is read only inside a helper rule (agent_admitted, definition_matches,
# argument_ok): a missing field leaves the helper undefined and `not` produces the denial.
package mcp.admission

default allow := false

tool_id := sprintf("%s/%s", [input.tool.server, input.tool.name])

entry := data.tools[tool_id]

allow if {
	entry
	count(deny_reasons) == 0
}

deny_reasons contains "tool_not_listed" if not data.tools[tool_id]

deny_reasons contains "agent_not_admitted" if {
	entry
	not agent_admitted
}

agent_admitted if input.agent in entry.agents

# The definition served now differs from the one that was pinned.
deny_reasons contains "definition_changed" if {
	entry
	not definition_matches
}

definition_matches if input.tool.definition_sha256 == entry.definition_sha256

# Every argument the policy constrains must be present and match.
deny_reasons contains "argument_not_allowed" if {
	some name
	entry.arguments[name]
	not argument_ok(name)
}

argument_ok(name) if {
	value := input.arguments[name]
	is_string(value)
	regex.match(entry.arguments[name].pattern, value)
}

# Arguments the policy does not know are refused, not passed through unchecked.
deny_reasons contains "unknown_argument" if {
	entry
	some name
	input.arguments[name]
	not entry.arguments[name]
}

# A constraint kind the policy cannot enforce denies instead of silently allowing.
deny_reasons contains "unknown_constraint" if {
	some name, kind
	entry.arguments[name][kind]
	kind != "pattern"
}
