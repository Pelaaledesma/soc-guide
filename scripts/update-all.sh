#!/usr/bin/env bash
set -e

# ─────────────────────────────────────────────────────────────
# update-all.sh — Weekly SOC Guide data sync
# Runs MITRE sync, commits + pushes any changes to GitHub.
# Render auto-deploys after push.
# ─────────────────────────────────────────────────────────────

cd "$(dirname "$0")/.."
LOG=".cache/update-$(date +%Y%m%d).log"
mkdir -p .cache

echo "$(date) — Running update-all.sh" | tee -a "$LOG"

# 1. Sync MITRE tactics (light mode: no network)
echo "" | tee -a "$LOG"
node scripts/sync-mitre.js --light --apply 2>&1 | tee -a "$LOG"

# 2. Check if anything changed
if git diff --quiet data/sections.json; then
  echo "$(date) — No changes, nothing to commit." | tee -a "$LOG"
  exit 0
fi

# 3. Commit and push
git add data/sections.json
git commit -m "chore: weekly MITRE tactics sync $(date +%Y-%m-%d)"
git push origin main 2>&1 | tee -a "$LOG"

echo "$(date) — ✅ Updated and pushed." | tee -a "$LOG"
