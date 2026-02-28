#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Missing virtualenv Python at ${PYTHON_BIN}"
  echo "Run: python3 -m venv .venv && ./.venv/bin/python -m pip install -r backend/requirements.txt"
  exit 1
fi

echo "==> Running backend unit tests"
"${PYTHON_BIN}" -m unittest discover -s "${ROOT_DIR}/backend/tests" -p "test_*.py"

echo
echo "==> Running chapter06/07/08 regression"
"${PYTHON_BIN}" "${ROOT_DIR}/backend/scripts/run_regression.py"

echo
echo "All checks passed."
