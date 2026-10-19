#!/usr/bin/env bash
# Одна команда: проверить решения, сгенерировать политику и контракт, прогнать все тесты.
# Живой стенд со шлюзом запускается отдельно: ./stand/run_stand.sh
# Сырой вывод тестов: results/opa-test.txt (политика) и results/adapter-test.txt (адаптер).
set -euo pipefail
cd "$(dirname "$0")"
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
python3 gen/generate.py
"$OPA" fmt --list --fail policy build || { echo "Rego не отформатирован: $OPA fmt -w policy" >&2; exit 1; }
"$OPA" test policy build -v 2>&1 | tee results/opa-test.txt
(cd adapter && python3 -W error::ResourceWarning -m unittest -v test_adapter) 2>&1 | tee results/adapter-test.txt
# Регрессия: правка решения в git ломает тест (T10).
./scripts/mutation_check.sh 2>&1 | tee results/mutation-check.txt
# Вторая конфигурация — контроль потока (OpenAPPA) через appa replay, если установлен appa.
APPA="${APPA:-$(command -v appa || echo "$HOME/.local/bin/appa")}"
if [ -x "$APPA" ]; then
  echo "--- контроль потока (lethal trifecta), $("$APPA" --version) ---"
  "$APPA" replay --config flow/contract.toml -v flow 2>&1 | tee results/flow-replay.txt
else
  echo "--- appa не установлен, контроль потока пропущен (см. flow/README.md) ---"
fi
