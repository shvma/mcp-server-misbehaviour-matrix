# Политика допуска вызова MCP-инструмента. Логика фиксирована, решения приходят данными:
# data.decisions генерирует gen/generate.py из decisions/*.json.
#
# Вход от шлюза (PEP):
#   {"agent": "...", "tool": {"server": "...", "name": "...", "definition_sha256": "..."}, "arguments": {...}}
#
# Всё закрыто по умолчанию: разрешение только если решение есть и ни одна причина отказа не сработала.
#
# Ловушка Rego, из-за которой здесь вспомогательные правила: если внутри `not` стоит ссылка
# на поле входа, OPA выносит её вычисление за пределы `not`. Поля нет -> тело правила отказа
# рушится -> причина не добавляется -> вызов РАЗРЕШЁН. Поэтому каждое поле входа читается
# только внутри вспомогательного правила (agent_admitted, definition_matches, still_valid,
# path_allowed, recipient_allowed): нет поля -> правило не определено -> `not` даёт отказ.
# Найдено тестами test_missing_agent_denied, test_path_missing_denied, test_bad_date_fails_closed.
package admission

default allow := false

tool_id := sprintf("%s/%s", [input.tool.server, input.tool.name])

decision := data.decisions[tool_id]

allow if {
	decision
	count(deny_reasons) == 0
}

deny_reasons contains "no_decision" if not data.decisions[tool_id]

deny_reasons contains "verdict_not_allowing" if {
	decision
	not decision.verdict in {"allow", "allow_with_constraints"}
}

deny_reasons contains "agent_not_admitted" if {
	decision
	not agent_admitted
}

agent_admitted if input.agent in decision.agents

# Определение инструмента изменилось с момента ревью: старое решение больше не про этот инструмент.
deny_reasons contains "definition_changed" if {
	decision
	not definition_matches
}

definition_matches if input.tool.definition_sha256 == decision.definition_sha256

# Невалидная дата тоже даёт отказ: parse не определён, "not" срабатывает.
deny_reasons contains "expired" if {
	decision
	not still_valid
}

still_valid if time.now_ns() < time.parse_rfc3339_ns(decision.expires)

deny_reasons contains "constraints_missing" if {
	decision.verdict == "allow_with_constraints"
	count(object.get(decision, "constraints", {})) == 0
}

deny_reasons contains "recipient_not_allowed" if {
	domains := decision.constraints.recipient_domain_in
	not recipient_allowed(domains)
}

deny_reasons contains "path_not_allowed" if {
	prefix := decision.constraints.path_prefix
	not path_allowed(prefix)
}

path_allowed(prefix) if startswith(input.arguments.path, prefix)

recipient_allowed(domains) if {
	some d in domains
	endswith(input.arguments.to, concat("", ["@", d]))
}
