#!/usr/bin/env bash
# Offline test runner: every file in tests/ is standalone (no pytest needed),
# which matters because the boards have no dev dependencies installed.
#
#   ./scripts/run_tests.sh              # uses python3.14, else python3
#   PYTHON=./.venv314/bin/python ./scripts/run_tests.sh
set -uo pipefail

cd "$(dirname "$0")/.."

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if command -v python3.14 >/dev/null 2>&1; then PY=python3.14; else PY=python3; fi
fi

echo "runner: $($PY -V 2>&1) ($PY)"
echo

pass=0
fail=0
failed=()

for f in tests/test_*.py; do
  if out=$("$PY" "$f" 2>&1); then
    pass=$((pass + 1))
    printf 'PASS  %s\n' "$f"
  else
    fail=$((fail + 1))
    failed+=("$f")
    printf 'FAIL  %s\n' "$f"
    printf '%s\n' "$out" | tail -15 | sed 's/^/      /'
  fi
done

echo
echo "===== $pass passed, $fail failed ====="
if [ "$fail" -ne 0 ]; then
  printf 'failed: %s\n' "${failed[*]}"
  exit 1
fi
