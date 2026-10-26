// Writes the weekly digest for every complete week (Monday to Sunday, UTC) held in the data window.
// A digest, once written, is kept, so the archive grows past the 30 day window.

import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { nVuln, dateAr, SEV_AR, iso } from '../docs/assets/engine/arabic.js';
import { cweAr } from '../docs/assets/engine/cwe.js';

const ROOT = new URL('..', import.meta.url).pathname;
const DATA = join(ROOT, 'docs/data');
const WEEKS = join(DATA, 'weeks');
const readJSON = async (p, f = null) => { try { return JSON.parse(await readFile(p, 'utf8')); } catch { return f; } };

function isoWeek(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = (t.getUTCDay() + 6) % 7;
  t.setUTCDate(t.getUTCDate() - day + 3);
  const y = t.getUTCFullYear();
  const jan4 = new Date(Date.UTC(y, 0, 4));
  const w = 1 + Math.round(((t - jan4) / 864e5 - 3 + ((jan4.getUTCDay() + 6) % 7)) / 7);
  return { y, w, id: `${y}-W${String(w).padStart(2, '0')}` };
}
const ymd = (d) => d.toISOString().slice(0, 10);

function ordinalWeekAr(w) {
  return `الأسبوع ${w}`;
}

async function main() {
  await mkdir(WEEKS, { recursive: true });
  const index = await readJSON(join(DATA, 'index.json'), { days: [] });
  const kev = await readJSON(join(DATA, 'kev.json'), []);
  const dayFiles = (index.days || []).map((d) => d.d).sort();
  if (!dayFiles.length) return;
  const first = dayFiles[0];
  // Weeks run Monday to Sunday in Kuwait time.
  const now = new Date(Date.now() + 3 * 3600 * 1000);
  // Last Sunday that has fully passed (UTC). On Sunday itself the week is not complete yet.
  const lastSunday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  lastSunday.setUTCDate(lastSunday.getUTCDate() - ((lastSunday.getUTCDay() + 7) % 7 || 7));

  const existing = new Set((await readdir(WEEKS)).filter((f) => /W\d+\.json$/.test(f)).map((f) => f.replace('.json', '')));
  const made = [];
  for (let end = new Date(lastSunday); ; end.setUTCDate(end.getUTCDate() - 7)) {
    const start = new Date(end); start.setUTCDate(start.getUTCDate() - 6);
    if (ymd(start) < first) break;
    const wk = isoWeek(start);
    if (existing.has(wk.id) && !process.argv.includes('--rewrite')) continue;
    const items = [];
    for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
      items.push(...(await readJSON(join(DATA, 'days', `${ymd(d)}.json`), [])));
    }
    const live = items.filter((x) => !x.st);
    const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    for (const it of live) if (it.sv && sev[it.sv] != null) sev[it.sv]++;
    const unscored = live.filter((x) => !x.sv).length;
    const count = (arr, key) => { const m = new Map(); for (const it of arr) { const k = key(it); if (k) m.set(k, (m.get(k) || 0) + 1); } return [...m].sort((a, b) => b[1] - a[1]); };
    const cwe = count(live, (x) => (x.c || [])[0]).slice(0, 8);
    const vendors = count(live, (x) => x.v).slice(0, 8);
    const kevAdded = kev.filter((k) => k.da >= ymd(start) && k.da <= ymd(end));
    const top = [...live].filter((x) => x.s != null).sort((a, b) => b.s - a.s || (b.e || 0) - (a.e || 0)).slice(0, 10);
    const epssTop = [...live].filter((x) => x.e != null).sort((a, b) => b.e - a.e).slice(0, 8);
    const titleAr = `${ordinalWeekAr(wk.w)} من ${wk.y}`;
    const range = `من ${dateAr(ymd(start), { year: false })} إلى ${dateAr(ymd(end))}`;
    const lineAr = `نُشر ${range} ما مجموعه ${live.length === 2 ? 'ثغرتان جديدتان' : nVuln(live.length) + ' جديدة'}، منها ${sev.CRITICAL.toLocaleString('en-US')} حرجة و${sev.HIGH.toLocaleString('en-US')} عالية الخطورة، وأُضيف إلى قائمة الثغرات المستغلة فعلياً ${kevAdded.length ? nVuln(kevAdded.length) : 'لا شيء'}.`;
    const p = [];
    const topCwe = cwe[0] ? cweAr(cwe[0][0])?.name || cwe[0][0] : null;
    const pctCrit = live.length ? Math.round(((sev.CRITICAL + sev.HIGH) / live.length) * 100) : 0;
    p.push(`شكّلت الثغرات الحرجة والعالية ${iso(pctCrit + '%')} من سجلات الأسبوع${unscored ? `، بينما بقيت ${nVuln(unscored)} دون تقييم للخطورة حتى تاريخ النشرة` : ''}.`);
    if (topCwe) p.push(`وتصدّرت أنواعَ الضعف ${topCwe} بعدد ${cwe[0][1].toLocaleString('en-US')}${cwe[1] ? ` ثم ${cweAr(cwe[1][0])?.name || cwe[1][0]} بعدد ${cwe[1][1].toLocaleString('en-US')}` : ''}.`);
    if (vendors[0]) p.push(`وكان ${iso(vendors[0][0])} أكثر المورّدين وروداً في السجلات بعدد ${vendors[0][1].toLocaleString('en-US')}${vendors[1] ? ` يليه ${iso(vendors[1][0])} بعدد ${vendors[1][1].toLocaleString('en-US')}` : ''}.`);
    if (kevAdded.length) {
      const ra = kevAdded.filter((k) => k.ra).length;
      p.push(`وأدرجت CISA خلال الأسبوع ${nVuln(kevAdded.length)} في قائمتها للثغرات المستغلة فعلياً${ra ? `، ومنها ${ra === 1 ? 'واحدة يُعرف استخدامها' : ra === 2 ? 'اثنتان يُعرف استخدامهما' : `${ra} يُعرف استخدامها`} في حملات الفدية` : ''}، لذا تُقدَّم معالجتها على غيرها.`);
    }
    if (epssTop[0]) p.push(`وأعلى ثغرات الأسبوع احتمالاً للاستغلال بحسب نظام EPSS هي ${iso(epssTop[0].i)} باحتمال ${iso((epssTop[0].e * 100).toFixed(1) + '%')} خلال الثلاثين يوماً المقبلة.`);
    const out = {
      id: wk.id, y: wk.y, w: wk.w, from: ymd(start), to: ymd(end), generated: new Date().toISOString().slice(0, 10),
      titleAr, lineAr, paragraphsAr: p, total: live.length, rejected: items.length - live.length, sev, unscored,
      cwe, vendors, kevAdded, top, epssTop,
    };
    await writeFile(join(WEEKS, `${wk.id}.json`), JSON.stringify(out) + '\n');
    made.push(wk.id);
  }
  const all = [];
  for (const f of (await readdir(WEEKS)).filter((f) => /W\d+\.json$/.test(f)).sort().reverse()) {
    const w = await readJSON(join(WEEKS, f));
    all.push({ id: w.id, titleAr: w.titleAr, lineAr: w.lineAr, from: w.from, to: w.to });
  }
  await writeFile(join(WEEKS, 'index.json'), JSON.stringify(all) + '\n');
  console.log(made.length ? `wrote ${made.join(', ')}` : 'no new week to write');
}

main().catch((e) => { console.error(e); process.exit(1); });
