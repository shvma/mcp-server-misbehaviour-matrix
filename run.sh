#!/usr/bin/env bash
# Одна команда: проверить решения, сгенерировать политику и контракт, прогнать все тесты.
# Сырой вывод тестов сохраняется в results/opa-test.txt.
set -euo pipefail
cd "$(dirname "$0")"
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
python3 gen/generate.py
"$OPA" fmt --list --fail policy build || { echo "Rego не отформатирован: $OPA fmt -w policy" >&2; exit 1; }
"$OPA" test policy build -v 2>&1 | tee results/opa-test.txt
