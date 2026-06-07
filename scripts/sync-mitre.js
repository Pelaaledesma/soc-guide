#!/usr/bin/env node
/**
 * sync-mitre.js — Sync MITRE ATT&CK data into data/sections.json
 *
 * Usage:
 *   node scripts/sync-mitre.js               # dry-run (show changes)
 *   node scripts/sync-mitre.js --apply        # write updates
 *   node scripts/sync-mitre.js --light        # use built-in list (no network)
 *   node scripts/sync-mitre.js --light --apply
 *
 * Fetches from: https://raw.githubusercontent.com/mitre/cti/master/
 *   enterprise-attack/enterprise-attack.json  (full STIX bundle, ~47MB)
 *
 * Cached in .cache/ after first fetch. Subsequent runs reuse cache.
 * Use --force-fetch to re-download.
 *
 * The --light flag skips the network fetch entirely and uses a built-in
 * fallback tactic list (updated 2025-12). Useful for environments without
 * network access or when you just want to update the mitreTactics format.
 */

const fs = require('fs');
const path = require('path');

const DATA_PATH = path.join(__dirname, '..', 'data', 'sections.json');
const CACHE_DIR = path.join(__dirname, '..', '.cache');
const BUNDLE_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

// Built-in fallback (enterprise tactics, updated 2025-12)
const BUILTIN_TACTICS = [
  {id:'TA0043',n:'Reconnaissance'},
  {id:'TA0042',n:'Resource Development'},
  {id:'TA0001',n:'Initial Access'},
  {id:'TA0002',n:'Execution'},
  {id:'TA0003',n:'Persistence'},
  {id:'TA0004',n:'Privilege Escalation'},
  {id:'TA0005',n:'Defense Evasion'},
  {id:'TA0006',n:'Credential Access'},
  {id:'TA0007',n:'Discovery'},
  {id:'TA0008',n:'Lateral Movement'},
  {id:'TA0009',n:'Collection'},
  {id:'TA0011',n:'Command and Control'},
  {id:'TA0010',n:'Exfiltration'},
  {id:'TA0040',n:'Impact'},
];

// ─── CLI flags ───────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const APPLY = args.includes('--apply');
const FORCE_FETCH = args.includes('--force-fetch');
const LIGHT = args.includes('--light');
const isDryRun = !APPLY;

// ─── Helpers ─────────────────────────────────────────────────────────────────
function log(...m) { console.log('[sync-mitre]', ...m); }

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${url}`);
  return resp.json();
}

function readCache(key) {
  try {
    return JSON.parse(fs.readFileSync(path.join(CACHE_DIR, key + '.json'), 'utf8'));
  } catch { return null; }
}

function writeCache(key, data) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  fs.writeFileSync(path.join(CACHE_DIR, key + '.json'), JSON.stringify(data));
}

// ─── Sync ────────────────────────────────────────────────────────────────────
async function sync() {
  log('Syncing MITRE ATT&CK enterprise tactics...');

  // Step 1: Get tactics list
  let tactics, objects;
  if (LIGHT) {
    log('Using built-in tactic list (--light). No network fetch.');
    tactics = BUILTIN_TACTICS;
  } else {
    log('Fetching/stix bundle...');
    const cacheKey = 'enterprise-bundle';
    const cached = !FORCE_FETCH ? readCache(cacheKey) : null;
    const bundle = cached || await fetchJSON(BUNDLE_URL);
    if (!cached) {
      writeCache(cacheKey, bundle);
      log(`Cached to .cache/${cacheKey}.json`);
    }
    objects = bundle.objects || bundle;

    tactics = objects
      .filter(obj => obj.type === 'x-mitre-tactic')
      .map(obj => ({
        id: obj.x_mitre_shortname || '',
        name: obj.name || '',
      }))
      .filter(t => t.id.startsWith('TA'))
      .sort((a, b) => a.id.localeCompare(b.id));
  }

  if (tactics.length === 0) {
    log('WARNING: No tactics found. Using built-in fallback.');
    tactics = BUILTIN_TACTICS;
  }

  // Step 2: Count techniques per tactic (only available with full bundle)
  let techCounts = {};
  if (objects) {
    const techniques = objects.filter(obj => obj.type === 'attack-pattern');
    for (const tech of techniques) {
      const phases = tech.kill_chain_phases || [];
      for (const phase of phases) {
        if (phase.kill_chain_name === 'mitre-attack') {
          techCounts[phase.phase_name] = (techCounts[phase.phase_name] || 0) + 1;
        }
      }
    }
    log(`Counted ${techniques.length} attack-patterns across ${Object.keys(techCounts).length} tactics.`);
  } else {
    log('Skipping technique count (--light mode or no bundle data).');
  }

  // Step 3: Load current data and diff
  const current = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  const oldTactics = current.mitreTactics || [];

  const newTactics = tactics.map(t => ({
    id: t.id,
    n: t.name || t.n,
    ...(techCounts[t.id] ? { c: techCounts[t.id] } : {}),
  }));

  const oldMap = {};
  for (const t of oldTactics) oldMap[t.id] = t;

  let changes = 0;
  for (const t2 of newTactics) {
    const t1 = oldMap[t2.id];
    if (!t1) {
      log(`  + NEW tactic: ${t2.id} ${t2.n}${t2.c ? ' ('+t2.c+' techs)' : ''}`);
      changes++;
    } else if (t1.n !== t2.n) {
      log(`  ~ UPDATED ${t2.id}: "${t1.n}" → "${t2.n}"`);
      changes++;
    } else if (t1.c !== t2.c) {
      log(`  ~ TECH COUNT ${t2.id}: ${t1.c||0} → ${t2.c}`);
      changes++;
    }
  }
  const newMap = {};
  for (const t of newTactics) newMap[t.id] = t;
  for (const t of oldTactics) {
    if (!newMap[t.id]) {
      log(`  - REMOVED tactic: ${t.id} ${t.n}`);
      changes++;
    }
  }

  if (changes === 0) {
    log('No changes — MITRE tactics are up to date.');
    return;
  }

  // Step 4: Apply
  if (isDryRun) {
    log(`Dry-run: ${changes} change(s). Run with --apply to update.`);
    return;
  }

  current.mitreTactics = newTactics;
  fs.writeFileSync(DATA_PATH, JSON.stringify(current, null, 2) + '\n', 'utf8');
  log(`✅ Updated — ${changes} change(s). New: ${newTactics.length} tactics synced.`);
}

sync().catch(err => {
  console.error('[sync-mitre] ERROR:', err.message);
  process.exit(1);
});
