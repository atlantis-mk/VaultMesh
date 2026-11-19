#!/usr/bin/env bash
set -euo pipefail
export CI=true GIT_PAGER=cat

FAST_MODE=false
for arg in "$@"; do
  case "$arg" in
    --fast)
      FAST_MODE=true
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

echo "[Gate 1/4] Checking diff size guideline..."
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  CHANGED_LINES=$(git --no-pager diff --numstat HEAD | awk '{add+=$1; del+=$2} END {print add+del+0}')
else
  CHANGED_LINES=$(git --no-pager diff --cached --numstat | awk '{add+=$1; del+=$2} END {print add+del+0}')
fi

if [ "${CHANGED_LINES:-0}" -gt 400 ]; then
  echo "WARN: Diff exceeds 400 lines ($CHANGED_LINES). Verify slice granularity."
fi

echo "[Gate 2/4] Typecheck & Lint..."
if [ -f package.json ]; then
  npm run typecheck --if-present < /dev/null
  npm run lint --if-present < /dev/null
fi
if [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1; then
  cargo check --quiet < /dev/null
fi
if [ -f go.mod ] && command -v go >/dev/null 2>&1; then
  go vet ./... < /dev/null
fi

echo "[Gate 3/4] Deterministic Test Suite..."
if [ "$FAST_MODE" = "true" ]; then
  echo "Fast mode enabled: running fast checks (run full scripts/gate-check.sh before final delivery)."
  if [ -f package.json ]; then
    npm run test:fast --if-present < /dev/null
  fi
else
  if [ -f package.json ]; then
    npm test --if-present < /dev/null
  fi
fi
if [ -f scripts/validate-skills.js ] && command -v node >/dev/null 2>&1; then
  node scripts/validate-skills.js < /dev/null
fi

echo "[Gate 4/4] Basic Secret & Debug Leftover Scan..."
SECRET_ONLY_PATTERN='^\+.*(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,})'
DEBUGGER_PATTERN='^\+.*debugger[;]'
if { git --no-pager diff --cached -U0; git --no-pager diff -U0; } | grep -v '^+++' | grep -E "$SECRET_ONLY_PATTERN"; then
  echo "FAIL: Potential secret or debugger statement detected in diff." >&2
  exit 1
fi
if { git --no-pager diff --cached -U0 -- . ':!*.md'; git --no-pager diff -U0 -- . ':!*.md'; } | grep -v '^+++' | grep -E "$DEBUGGER_PATTERN"; then
  echo "FAIL: Potential secret or debugger statement detected in diff." >&2
  exit 1
fi

echo "ALL SOFTWARE 1.0 GATES PASSED."
