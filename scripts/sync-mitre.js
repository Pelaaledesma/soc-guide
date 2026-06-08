#!/usr/bin/env node
/**
 * sync-mitre.js — Sync real MITRE ATT&CK tactics + techniques into data/
 *
 * Usage:
 *   node scripts/sync-mitre.js               # dry-run (show changes)
 *   node scripts/sync-mitre.js --apply        # write updates
 *   node scripts/sync-mitre.js --light        # use built-in fallback list
 *   node scripts/sync-mitre.js --light --apply
 *   node scripts/sync-mitre.js --force-fetch  # re-download bundle
 *
 * Fetches from: https://raw.githubusercontent.com/mitre/cti/master/
 *   enterprise-attack/enterprise-attack.json
 *
 * Cached in .cache/ after first fetch (enterprise-bundle.json, ~47MB).
 * Subsequent runs reuse cache. Use --force-fetch to re-download.
 */

const fs = require('fs');
const path = require('path');

const DATA_PATH = path.join(__dirname, '..', 'data', 'sections.json');
const CACHE_DIR = path.join(__dirname, '..', '.cache');
const BUNDLE_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

// Built-in fallback tactics (enterprise, updated 2025-12)
const BUILTIN_TACTICS = [
  { id: 'TA0001', n: 'Initial Access' },
  { id: 'TA0002', n: 'Execution' },
  { id: 'TA0003', n: 'Persistence' },
  { id: 'TA0004', n: 'Privilege Escalation' },
  { id: 'TA0005', n: 'Defense Evasion' },
  { id: 'TA0006', n: 'Credential Access' },
  { id: 'TA0007', n: 'Discovery' },
  { id: 'TA0008', n: 'Lateral Movement' },
  { id: 'TA0009', n: 'Collection' },
  { id: 'TA0010', n: 'Exfiltration' },
  { id: 'TA0011', n: 'Command and Control' },
  { id: 'TA0040', n: 'Impact' },
  { id: 'TA0042', n: 'Resource Development' },
  { id: 'TA0043', n: 'Reconnaissance' },
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

// ─── Build matrix from bundle objects ────────────────────────────────────────
function buildMatrix(objects) {
  // Tactics
  const tactics = objects
    .filter(obj => obj.type === 'x-mitre-tactic')
    .map(obj => ({
      short: obj.x_mitre_shortname,
      name: obj.name,
      id: obj.external_references?.[0]?.external_id,
    }))
    .filter(t => t.id && t.id.startsWith('TA'))
    .sort((a, b) => a.id.localeCompare(b.id));

  // Map shortname -> { id, name }
  const shortTo = {};
  for (const t of tactics) shortTo[t.short] = t;

  // Techniques grouped by tactic shortname
  const techByShort = {};
  const patterns = objects.filter(obj => obj.type === 'attack-pattern');
  for (const tech of patterns) {
    const phases = tech.kill_chain_phases || [];
    const techId = tech.external_references?.[0]?.external_id || '';
    if (!techId) continue;
    for (const phase of phases) {
      if (phase.kill_chain_name === 'mitre-attack') {
        if (!techByShort[phase.phase_name]) techByShort[phase.phase_name] = [];
        techByShort[phase.phase_name].push({
          id: techId,
          name: tech.name,
          is_sub: tech.x_mitre_is_subtechnique || false,
        });
      }
    }
  }

  // Sort techniques within each tactic
  for (const short of Object.keys(techByShort)) {
    techByShort[short].sort((a, b) => a.id.localeCompare(b.id));
  }

  // Build final matrix
  return tactics.map(t => ({
    id: t.id,
    name: t.name,
    techniques: techByShort[t.short] || [],
  }));
}

// ─── Sync ────────────────────────────────────────────────────────────────────
async function sync() {
  log('Syncing MITRE ATT&CK tactics + techniques...');

  // Step 1: Get tactics list + techniques
  let mitreMatrix = [];
  if (LIGHT) {
    log('Using built-in tactic list (--light). NO TECHNIQUES will be synced.');
    const tactics = BUILTIN_TACTICS.map(t => ({ id: t.id, name: t.n, techniques: [] }));
    mitreMatrix = tactics;
  } else {
    log('Fetching STIX bundle...');
    const cacheKey = 'enterprise-bundle';
    const cached = !FORCE_FETCH ? readCache(cacheKey) : null;
    const bundle = cached || await fetchJSON(BUNDLE_URL);
    if (!cached) {
      writeCache(cacheKey, bundle);
      log(`Cached to .cache/${cacheKey}.json`);
    }
    const objects = bundle.objects || bundle;
    mitreMatrix = buildMatrix(objects);
    log(`Built matrix: ${mitreMatrix.length} tactics, ${mitreMatrix.reduce((s,t)=>s+t.techniques.length,0)} techniques`);
  }

  if (mitreMatrix.length === 0) {
    log('WARNING: No tactics found. Using built-in fallback.');
    mitreMatrix = BUILTIN_TACTICS.map(t => ({ id: t.id, name: t.n, techniques: [] }));
  }

  // Step 2: Also build the flat mitreTactics list
  const newTactics = mitreMatrix.map(t => ({ id: t.id, n: t.name }));

  // Step 3: Load current data and diff
  const current = JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'));
  const oldMatrix = current.mitreMatrix || [];
  const oldTactics = current.mitreTactics || [];

  // Diff tactics
  let changes = 0;
  const oldTMap = {};
  for (const t of oldTactics) oldTMap[t.id] = t;
  for (const t2 of newTactics) {
    const t1 = oldTMap[t2.id];
    if (!t1) {
      log(`  + NEW tactic: ${t2.id} ${t2.n}`);
      changes++;
    } else if (t1.n !== t2.n) {
      log(`  ~ RENAMED ${t2.id}: "${t1.n}" → "${t2.n}"`);
      changes++;
    }
  }
  const newTMap = {};
  for (const t of newTactics) newTMap[t.id] = t;
  for (const t of oldTactics) {
    if (!newTMap[t.id]) {
      log(`  - REMOVED tactic: ${t.id} ${t.n}`);
      changes++;
    }
  }

  // Diff technique counts
  const oldTechCount = {};
  for (const t of oldMatrix) {
    oldTechCount[t.id] = (t.techniques || []).length;
  }
  for (const t of mitreMatrix) {
    const oldCount = oldTechCount[t.id] || 0;
    const newCount = t.techniques.length;
    if (oldCount !== newCount) {
      log(`  ~ TECH COUNT ${t.id}: ${oldCount} → ${newCount}${newCount > oldCount ? ' (+'+(newCount-oldCount)+')' : ' ('+(newCount-oldCount)+')'}`);
      changes++;
    }
  }

  if (changes === 0) {
    log('No changes — MITRE data is up to date.');
    return;
  }

  // Step 4: Apply
  if (isDryRun) {
    log(`Dry-run: ${changes} change(s). Run with --apply to update.`);
    return;
  }

  current.mitreTactics = newTactics;
  current.mitreMatrix = mitreMatrix;
  fs.writeFileSync(DATA_PATH, JSON.stringify(current, null, 2) + '\n', 'utf8');
  log(`✅ Updated — ${changes} change(s). ${mitreMatrix.length} tactics with ${mitreMatrix.reduce((s,t)=>s+t.techniques.length,0)} techniques synced.`);
}

sync().catch(err => {
  console.error('[sync-mitre] ERROR:', err.message);
  process.exit(1);
});
