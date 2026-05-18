#!/usr/bin/env bash
# DoD gate for the whole repo: lint + validate-meta (+ optionally test one SID).
# Usage: scripts/verify.sh [SID]
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== rulectl lint =="
scripts/rulectl lint
echo "== rulectl validate-meta =="
scripts/rulectl validate-meta
if [ "${1:-}" != "" ]; then
  echo "== rulectl check $1 =="
  scripts/rulectl check "$1"
fi
echo "verify.sh: done"
