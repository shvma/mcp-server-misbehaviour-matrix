package mcp.admission_test

import data.mcp.admission

pinned := "d1c4ac1e5c0e30413163fc200a011bdbf1aeff28e85a362e5d0e34d63e062348"

fixture := {"notes/read_note": {
	"agents": ["agent"],
	"definition_sha256": pinned,
	"arguments": {"id": {"pattern": "^[a-z][0-9]+$"}},
}}

# object.union merges recursively: use it only to replace values, never to remove keys.
call(overrides) := object.union(
	{
		"agent": "agent",
		"tool": {"server": "notes", "name": "read_note", "definition_sha256": pinned},
		"arguments": {"id": "a1"},
	},
	overrides,
)

test_listed_call_allowed if {
	admission.allow with input as call({}) with data.tools as fixture
}

test_unlisted_tool_denied if {
	not admission.allow with input as call({"tool": {"server": "notes", "name": "delete_note", "definition_sha256": pinned}})
		with data.tools as fixture
	"tool_not_listed" in admission.deny_reasons with input as call({"tool": {"server": "notes", "name": "delete_note", "definition_sha256": pinned}})
		with data.tools as fixture
}

test_other_agent_denied if {
	not admission.allow with input as call({"agent": "other"}) with data.tools as fixture
	"agent_not_admitted" in admission.deny_reasons with input as call({"agent": "other"}) with data.tools as fixture
}

test_missing_agent_denied if {
	inp := object.remove(call({}), ["agent"])
	not admission.allow with input as inp with data.tools as fixture
	"agent_not_admitted" in admission.deny_reasons with input as inp with data.tools as fixture
}

test_changed_definition_denied if {
	inp := call({"tool": {"server": "notes", "name": "read_note", "definition_sha256": "0000"}})
	not admission.allow with input as inp with data.tools as fixture
	"definition_changed" in admission.deny_reasons with input as inp with data.tools as fixture
}

test_missing_definition_denied if {
	inp := {"agent": "agent", "tool": {"server": "notes", "name": "read_note"}, "arguments": {"id": "a1"}}
	not admission.allow with input as inp with data.tools as fixture
	"definition_changed" in admission.deny_reasons with input as inp with data.tools as fixture
}

test_argument_pattern_enforced if {
	inp := call({"arguments": {"id": "a1' or 1=1"}})
	not admission.allow with input as inp with data.tools as fixture
	"argument_not_allowed" in admission.deny_reasons with input as inp with data.tools as fixture
}

test_missing_argument_denied if {
	inp := {"agent": "agent", "tool": {"server": "notes", "name": "read_note", "definition_sha256": pinned}, "arguments": {}}
	not admission.allow with input as inp with data.tools as fixture
	"argument_not_allowed" in admission.deny_reasons with input as inp with data.tools as fixture
}

test_non_string_argument_denied if {
	not admission.allow with input as call({"arguments": {"id": 1}}) with data.tools as fixture
}

test_unknown_argument_denied if {
	inp := call({"arguments": {"id": "a1", "owner": "bob"}})
	not admission.allow with input as inp with data.tools as fixture
	"unknown_argument" in admission.deny_reasons with input as inp with data.tools as fixture
}

test_unknown_constraint_kind_denied if {
	fx := {"notes/read_note": object.union(fixture["notes/read_note"], {"arguments": {"id": {"pattern": "^a", "max_len": 3}}})}
	not admission.allow with input as call({}) with data.tools as fx
	"unknown_constraint" in admission.deny_reasons with input as call({}) with data.tools as fx
}

test_empty_input_denied if {
	not admission.allow with input as {} with data.tools as fixture
}

test_committed_data_pins_served_definition if {
	data.tools["notes/read_note"].definition_sha256 == pinned
}
