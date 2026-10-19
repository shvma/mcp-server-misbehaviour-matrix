# Модульные тесты логики допуска на абстрактных решениях. Не зависят от decisions/.
package admission_test

import data.admission

fixture := {
	"demo/reader": {
		"verdict": "allow",
		"agents": ["agent-a"],
		"definition_sha256": "h1",
		"expires": "2099-01-01T00:00:00Z",
	},
	"demo/sender": {
		"verdict": "allow_with_constraints",
		"agents": ["agent-a"],
		"definition_sha256": "h2",
		"expires": "2099-01-01T00:00:00Z",
		"constraints": {"recipient_domain_in": ["corp.example"]},
	},
	"demo/writer": {
		"verdict": "allow_with_constraints",
		"agents": ["agent-a"],
		"definition_sha256": "h3",
		"expires": "2099-01-01T00:00:00Z",
		"constraints": {"path_prefix": "/workspace/"},
	},
	"demo/blocked": {
		"verdict": "deny",
		"agents": ["agent-a"],
		"definition_sha256": "h4",
		"expires": "2099-01-01T00:00:00Z",
	},
	"demo/old": {
		"verdict": "allow",
		"agents": ["agent-a"],
		"definition_sha256": "h5",
		"expires": "2020-01-01T00:00:00Z",
	},
	"demo/baddate": {
		"verdict": "allow",
		"agents": ["agent-a"],
		"definition_sha256": "h6",
		"expires": "не дата",
	},
	"demo/noconstraints": {
		"verdict": "allow_with_constraints",
		"agents": ["agent-a"],
		"definition_sha256": "h7",
		"expires": "2099-01-01T00:00:00Z",
	},
	"demo/oddverdict": {
		"verdict": "maybe",
		"agents": ["agent-a"],
		"definition_sha256": "h8",
		"expires": "2099-01-01T00:00:00Z",
	},
}

call(server_name, hash, args) := {
	"agent": "agent-a",
	"tool": {"server": split(server_name, "/")[0], "name": split(server_name, "/")[1], "definition_sha256": hash},
	"arguments": args,
}

ok(inp) if admission.allow with data.decisions as fixture with input as inp

reasons(inp) := r if {
	r := admission.deny_reasons with data.decisions as fixture with input as inp
}

test_allow_plain if ok(call("demo/reader", "h1", {}))

test_unknown_tool_denied if {
	not ok(call("demo/unknown", "h1", {}))
	"no_decision" in reasons(call("demo/unknown", "h1", {}))
}

test_deny_verdict if {
	not ok(call("demo/blocked", "h4", {}))
	"verdict_not_allowing" in reasons(call("demo/blocked", "h4", {}))
}

test_unknown_verdict_fails_closed if not ok(call("demo/oddverdict", "h8", {}))

test_other_agent_denied if {
	inp := object.union(call("demo/reader", "h1", {}), {"agent": "agent-b"})
	not ok(inp)
	"agent_not_admitted" in reasons(inp)
}

test_missing_agent_denied if not ok(object.remove(call("demo/reader", "h1", {}), ["agent"]))

test_changed_definition_denied if {
	not ok(call("demo/reader", "другой-хеш", {}))
	"definition_changed" in reasons(call("demo/reader", "другой-хеш", {}))
}

test_missing_hash_denied if {
	inp := {"agent": "agent-a", "tool": {"server": "demo", "name": "reader"}, "arguments": {}}
	not ok(inp)
}

test_expired_denied if {
	not ok(call("demo/old", "h5", {}))
	"expired" in reasons(call("demo/old", "h5", {}))
}

test_bad_date_fails_closed if not ok(call("demo/baddate", "h6", {}))

test_constraints_missing_denied if not ok(call("demo/noconstraints", "h7", {}))

test_recipient_inside_allowed if ok(call("demo/sender", "h2", {"to": "ann@corp.example"}))

test_recipient_outside_denied if {
	not ok(call("demo/sender", "h2", {"to": "ann@outside.example"}))
	"recipient_not_allowed" in reasons(call("demo/sender", "h2", {"to": "ann@outside.example"}))
}

test_recipient_lookalike_denied if not ok(call("demo/sender", "h2", {"to": "ann@corp.example.outside.example"}))

test_recipient_missing_denied if not ok(call("demo/sender", "h2", {}))

# Несколько адресов в одном поле: внутренний адрес в конце не должен проводить внешний.
test_recipient_comma_list_denied if not ok(call("demo/sender", "h2", {"to": "x@outside.example, ann@corp.example"}))

test_recipient_semicolon_list_denied if not ok(call("demo/sender", "h2", {"to": "x@outside.example;ann@corp.example"}))

test_recipient_not_string_denied if not ok(call("demo/sender", "h2", {"to": ["ann@corp.example"]}))

test_recipient_subdomain_denied if not ok(call("demo/sender", "h2", {"to": "ann@sub.corp.example"}))

test_path_inside_allowed if ok(call("demo/writer", "h3", {"path": "/workspace/notes.txt"}))

test_path_outside_denied if not ok(call("demo/writer", "h3", {"path": "/etc/hosts"}))

test_path_missing_denied if not ok(call("demo/writer", "h3", {}))

# Переход на уровень выше после разрешённого префикса: строка начинается с префикса, а путь ведёт наружу.
test_path_parent_segment_denied if {
	inp := call("demo/writer", "h3", {"path": "/workspace/../etc/hosts"})
	not ok(inp)
	"path_not_allowed" in reasons(inp)
}

test_path_trailing_parent_denied if not ok(call("demo/writer", "h3", {"path": "/workspace/.."}))

test_path_not_string_denied if not ok(call("demo/writer", "h3", {"path": ["/workspace/notes.txt"]}))

# Две точки внутри имени файла — не переход наверх, пропускаем.
test_path_dots_in_name_allowed if ok(call("demo/writer", "h3", {"path": "/workspace/a..b.txt"}))
