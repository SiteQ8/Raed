// Pulls the CVE Program's change log, fetches every new or changed record,
// enriches it (KEV, EPSS) and writes the day files the site reads.
//
//   node scripts/update.mjs            normal run (only what changed since last run)
//   node scripts/update.mjs --full     rebuild the whole window from the 30 day log

import { readFile, writeFile, mkdir, readdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { compact } from '../docs/assets/engine/record.js';
import { kwDay } from '../docs/assets/engine/arabic.js';
import { getJSON, pool } from './lib/net.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const DATA = join(ROOT, 'docs/data');
const DAYS = join(DATA, 'days');
const WINDOW_DAYS = 30;
const DELTA = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = 'https://api.first.org/data/v1/epss';

const full = process.argv.includes('--full');
const today = new Date().toISOString().slice(0, 10);
// Days are Kuwait calendar days (UTC+3).
const cutoff = kwDay(new Date(Date.now() - WINDOW_DAYS * 864e5).toISOString().slice(0, 19));

async function readJSON(p, fallback) {
  try { return JSON.parse(await readFile(p, 'utf8')); } catch { return fallback; }
}
async function writeJSON(p, v) {
  await writeFile(p, JSON.stringify(v) + '\n');
}

async function loadDays() {
  const map = new Map();
  if (!existsSync(DAYS)) return map;
  for (const f of await readdir(DAYS)) {
    if (!f.endsWith('.json')) continue;
    for (const it of await readJSON(join(DAYS, f), [])) map.set(it.i, it);
  }
  return map;
}

async function main() {
  await mkdir(DAYS, { recursive: true });
  const state = full ? {} : await readJSON(join(DATA, 'state.json'), {});
  const items = full ? new Map() : await loadDays();
  let updated = full ? [] : await readJSON(join(DATA, 'updated.json'), []);

  console.log('reading the change log');
  const delta = await getJSON(DELTA);
  const since = state.lastFetch || '';
  const latest = new Map();
  for (const e of delta) {
    if (since && e.fetchTime <= since) continue;
    for (const kind of ['new', 'updated']) {
      for (const x of e[kind] || []) {
        const prev = latest.get(x.cveId);
        if (!prev || x.dateUpdated > prev.dateUpdated) latest.set(x.cveId, { ...x, kind });
      }
    }
  }
  const newest = delta.reduce((m, e) => (e.fetchTime > m ? e.fetchTime : m), since);
  console.log(`${latest.size} records changed since ${since || 'the start of the log'}`);

  const list = [...latest.values()];
  const recs = await pool(list, 24, async (x) => {
    const rec = await getJSON(x.githubLink);
    return rec ? compact(rec) : null;
  });
  let failed = 0;
  const changedOld = [];
  for (let n = 0; n < list.length; n++) {
    const it = recs[n];
    if (!it || it.error) { failed++; continue; }
    const old = items.get(it.i);
    if (old?.e != null) { it.e = old.e; it.ep = old.ep; }
    if (kwDay(it.p) >= cutoff) items.set(it.i, it);
    else changedOld.push({ i: it.i, u: it.u, sv: it.sv, s: it.s, v: it.v, r: it.r, st: it.st, p: it.p });
  }
  if (failed) console.log(`${failed} records could not be fetched this run, they stay for the next run`);
  updated = [...changedOld, ...updated.filter((u) => !changedOld.some((c) => c.i === u.i))]
    .sort((a, b) => (a.u < b.u ? 1 : -1))
    .slice(0, 400);

  // Drop what left the window.
  for (const [id, it] of items) if (kwDay(it.p) < cutoff) items.delete(id);

  console.log('reading the KEV catalogue');
  const kevRaw = await getJSON(KEV);
  const kev = (kevRaw?.vulnerabilities || []).map((k) => ({
    i: k.cveID,
    v: k.vendorProject,
    r: k.product,
    n: k.vulnerabilityName,
    da: k.dateAdded,
    due: k.dueDate,
    ra: /^known$/i.test(String(k.knownRansomwareCampaignUse || '').trim()) ? 1 : 0,
    c: (k.cwes || []).filter(Boolean),
    act: k.requiredAction,
    d: (k.shortDescription || '').replace(/\s+/g, ' ').trim(),
  })).sort((a, b) => (a.da < b.da ? 1 : a.da > b.da ? -1 : a.i < b.i ? 1 : -1));
  const kevSet = new Map(kev.map((k) => [k.i, k.da]));
  for (const it of items.values()) {
    if (kevSet.has(it.i)) it.k = kevSet.get(it.i); else delete it.k;
  }

  // EPSS once a day for the whole window, otherwise only for records without a score.
  const needAll = state.epssDate !== today;
  const ids = [...items.values()].filter((it) => !it.st && (needAll || it.e == null)).map((it) => it.i);
  if (ids.length) {
    console.log(`EPSS for ${ids.length} records`);
    const batches = [];
    for (let n = 0; n < ids.length; n += 100) batches.push(ids.slice(n, n + 100));
    const res = await pool(batches, 4, (b) => getJSON(`${EPSS}?cve=${b.join(',')}&limit=100`));
    for (const r of res) {
      for (const row of r?.data || []) {
        const it = items.get(row.cve);
        if (it) { it.e = Number(Number(row.epss).toFixed(4)); it.ep = Number(Number(row.percentile).toFixed(3)); }
      }
    }
    if (needAll) state.epssDate = today;
  }

  // Write day files.
  const byDay = new Map();
  for (const it of items.values()) {
    const d = kwDay(it.p);
    if (!byDay.has(d)) byDay.set(d, []);
    byDay.get(d).push(it);
  }
  for (const f of await readdir(DAYS)) {
    if (f.endsWith('.json') && !byDay.has(f.slice(0, 10))) await rm(join(DAYS, f));
  }
  const days = [];
  for (const [d, arr] of [...byDay].sort((a, b) => (a[0] < b[0] ? 1 : -1))) {
    arr.sort((a, b) => (a.p < b.p ? 1 : a.p > b.p ? -1 : a.i < b.i ? 1 : -1));
    await writeJSON(join(DAYS, `${d}.json`), arr);
    const count = (s) => arr.filter((x) => x.sv === s && !x.st).length;
    days.push({
      d,
      n: arr.filter((x) => !x.st).length,
      rj: arr.filter((x) => x.st === 'REJECTED').length,
      c: count('CRITICAL'), h: count('HIGH'), m: count('MEDIUM'), l: count('LOW'),
      k: arr.filter((x) => x.k).length,
    });
  }

  // Compact search index for the window: id, vendor, product, title, severity, score, date.
  const search = [...items.values()]
    .filter((x) => !x.st)
    .sort((a, b) => (a.p < b.p ? 1 : -1))
    .map((x) => [x.i, x.v || '', x.r || '', (x.t || x.d || '').slice(0, 90), x.sv || '', x.s ?? '', kwDay(x.p), x.k ? 1 : 0]);

  await writeJSON(join(DATA, 'kev.json'), kev);
  // Small per year shards keyed by CVE year, so a record page fetches a few kilobytes instead of the whole catalogue.
  await mkdir(join(DATA, 'kev'), { recursive: true });
  const shards = new Map();
  for (const k of kev) {
    const y = k.i.slice(4, 8);
    if (!shards.has(y)) shards.set(y, {});
    shards.get(y)[k.i] = k;
  }
  for (const f of await readdir(join(DATA, 'kev'))) if (!shards.has(f.slice(0, 4))) await rm(join(DATA, 'kev', f));
  const thisYear = new Date().getUTCFullYear();
  for (let y = 1999; y <= thisYear; y++) if (!shards.has(String(y))) shards.set(String(y), {});
  for (const [y, m] of shards) await writeJSON(join(DATA, 'kev', `${y}.json`), m);
  await writeJSON(join(DATA, 'updated.json'), updated);
  await writeJSON(join(DATA, 'search.json'), search);
  await writeJSON(join(DATA, 'index.json'), {
    generated: new Date().toISOString().slice(0, 19) + 'Z',
    window: WINDOW_DAYS,
    total: search.length,
    kevTotal: kev.length,
    kevLatest: kev[0]?.da || null,
    days,
  });
  state.lastFetch = newest;
  state.runAt = new Date().toISOString();
  await writeJSON(join(DATA, 'state.json'), state);
  console.log(`window ${days.length} days, ${search.length} records, KEV ${kev.length}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
