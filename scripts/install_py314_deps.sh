#!/usr/bin/env bash
# Install Python 3.14 deps for bb_node.py (must match the interpreter used with sudo).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3.14}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "error: $PY not found" >&2
  exit 1
fi

echo "Installing requirements for $($PY --version) via sudo (L2CAP needs root)..."
sudo "$PY" -m pip install --break-system-packages --ignore-installed -r "$ROOT/requirements.txt"
echo "OK — run: sudo $PY $ROOT/bb_node.py --chat"
