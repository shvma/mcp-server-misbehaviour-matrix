#!/usr/bin/env bash
# Регрессия «правка решения ловится тестом» (задача T10).
# Временно расширяет префикс пути в одном решении, пересобирает политику и примеры
# и ждёт, что opa test УПАДЁТ: deny-пример /private/b при префиксе "/" стал бы разрешён.
# Если тест не упал — значит примеры не покрывают изменение, это находка.
# Исходное решение восстанавливается в любом случае (trap).
set -euo pipefail
cd "$(dirname "$0")/.."
OPA="${OPA:-$(command -v opa || echo "$HOME/.local/bin/opa")}"
DEC=decisions/notes__read.json
BAK="$(mktemp)"
cp "$DEC" "$BAK"
restore(){ cp "$BAK" "$DEC"; rm -f "$BAK"; python3 gen/generate.py >/dev/null; }
trap restore EXIT

python3 - "$DEC" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p, encoding="utf-8"))
d["constraints"]["path_prefix"] = "/"   # мутация: разрешить любой путь
json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PY

python3 gen/generate.py >/dev/null
if "$OPA" test policy build >/dev/null 2>&1; then
  echo "FAIL: мутацию решения тесты не поймали — примеры не покрывают изменение"
  exit 1
else
  echo "PASS: правка решения (префикс пути → '/') ломает сгенерированный тест, как и должно"
fi
