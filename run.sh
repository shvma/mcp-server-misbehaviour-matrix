#!/usr/bin/env bash
# Одна команда: проверить решения, сгенерировать политику и контракт, прогнать все тесты.
# Сырой вывод тестов: results/opa-test.txt (политика) и results/adapter-test.txt (адаптер).
set -euo pipefail
cd "$(dirname "$0")"
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
python3 gen/generate.py
"$OPA" fmt --list --fail policy build || { echo "Rego не отформатирован: $OPA fmt -w policy" >&2; exit 1; }
"$OPA" test policy build -v 2>&1 | tee results/opa-test.txt
(cd adapter && python3 -W error::ResourceWarning -m unittest -v test_adapter) 2>&1 | tee results/adapter-test.txt
