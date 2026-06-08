#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

# Only commit if there are changes
git add -A
if git diff --cached --quiet; then
  exit 0
fi

# Auto-commit with timestamp
git commit -m "chore: auto-sync $(date +%Y-%m-%dT%H:%M:%S%z)"
git push origin main 2>/dev/null
