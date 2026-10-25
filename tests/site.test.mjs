// Gates that keep the site honest: Arabic punctuation, naming, data integrity and the engine's sentences.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { summaryAr, nVuln, vectorAr, epssAr, dateAr } from '../docs/assets/engine/arabic.js';
import { compact } from '../docs/assets/engine/record.js';
import { CWE_AR } from '../docs/assets/engine/cwe.js';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const ROOT = new URL('..', import.meta.url).pathname;
const walk = (dir, ext, out = []) => {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) { if (!['node_modules', '.git'].includes(f)) walk(p, ext, out); }
    else if (ext.some((e) => f.endsWith(e))) out.push(p);
  }
  return out;
};
const htmlFiles = walk(join(ROOT, 'docs'), ['.html']);
const textFiles = [...htmlFiles, ...walk(join(ROOT, 'templates'), ['.html']), ...walk(join(ROOT, 'cna-kit'), ['.md', '.txt']),
  ...walk(join(ROOT, 'docs/assets'), ['.js']), ...walk(join(ROOT, 'scripts'), ['.mjs']), join(ROOT, 'README.md')].filter(existsSync);
const AR = /[؀-ۿ]/;

function blocks(html) {
  const body = html.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '');
  const out = [];
  for (const m of body.matchAll(/<(p|li|dd|summary|h1|h2|h3|figcaption|td)\b[^>]*>([\s\S]*?)<\/\1>/g)) {
    if (/<(p|ul|ol|dl|table)\b/.test(m[2])) continue;
    const text = m[2].replace(/<[^>]+>/g, '').replace(/&[a-z]+;/g, ' ').replace(/\s+/g, ' ').trim();
    if (AR.test(text)) out.push(text);
  }
  return out;
}

test('Arabic blocks carry a period only at their end', () => {
  const bad = [];
  for (const f of htmlFiles) {
    for (const t of blocks(readFileSync(f, 'utf8'))) {
      // A period followed by more text, outside numbers, domains and file names, is a mid sentence period.
      const inner = t.replace(/\d+(\.\d+)+/g, '0').replace(/[A-Za-z0-9_-]+\.[A-Za-z]{2,}/g, '').replace(/\.\.\//g, '');
      const at = inner.search(/\.\s*\S/);
      if (at !== -1 && at < inner.trimEnd().length - 1) bad.push(`${f.replace(ROOT, '')}: ${t.slice(0, 120)}`);
    }
  }
  assert.deepEqual(bad, []);
});

test('the Gulf is always the Arabian Gulf, and no excluded brand appears', () => {
  for (const f of textFiles) {
    const s = readFileSync(f, 'utf8');
    assert.ok(!/الخليج الفارسي|Persian Gulf/i.test(s), `${f} names the Gulf wrongly`);
    assert.ok(!/\bnbk\b|national bank of kuwait|بنك الكويت الوطني/i.test(s), `${f} mentions an excluded brand`);
  }
});

test('no long dashes in the written content', () => {
  // Rendered pages quote vendor product names as published, so the gate covers what we write ourselves.
  for (const f of textFiles) {
    if (f.includes('/docs/') && f.endsWith('.html')) continue;
    const s = readFileSync(f, 'utf8');
    assert.ok(!/[–—]/.test(s), `${f} contains an en or em dash`);
  }
});

test('the engine writes one sentence with one final period', () => {
  const sample = {
    i: 'CVE-2026-0001', p: '2026-10-20T10:00:00', v: 'Example', r: 'Gateway', s: 9.8, sv: 'CRITICAL',
    vec: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', c: ['CWE-78'], k: '2026-10-21',
  };
  const s = summaryAr(sample).replace(/[⁨⁩]/g, '');
  assert.match(s, /^ثغرة من نوع حقن أوامر نظام التشغيل في Gateway من Example/);
  assert.match(s, /9\.8 من 10 أي حرجة/);
  assert.match(s, /قائمة الثغرات المستغلة فعلياً\.$/);
  assert.equal(s.replace(/\d\.\d/g, '').split('.').length, 2);
  assert.equal(summaryAr({ i: 'x', st: 'REJECTED' }).split('.').length, 2);
});

test('Arabic counted nouns agree with the number', () => {
  assert.equal(nVuln(1), 'ثغرة واحدة');
  assert.equal(nVuln(2), 'ثغرتان');
  assert.equal(nVuln(7), '7 ثغرات');
  assert.equal(nVuln(10), '10 ثغرات');
  assert.equal(nVuln(11), '11 ثغرة');
  assert.equal(nVuln(103), '103 ثغرات');
  assert.equal(nVuln(1500), '1,500 ثغرة');
});

test('vectors, dates and EPSS read in Arabic', () => {
  const rows = vectorAr('CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
  assert.equal(rows[0][1], 'عبر الشبكة');
  assert.ok(rows.length >= 10);
  assert.equal(dateAr('2026-10-25', { weekday: true }), 'الأحد 25 أكتوبر 2026');
  assert.match(epssAr(0.91, 0.999).replace(/[⁨⁩]/g, ''), /91% وهي ضمن أعلى 1%/);
});

test('every Arabic weakness name has an explanation without a final period', () => {
  for (const [id, [name, why]] of Object.entries(CWE_AR)) {
    assert.ok(name && why, id);
    assert.ok(!why.endsWith('.'), `${id} explanation should not end with a period, the page adds it`);
    assert.ok(!/\./.test(why.replace(/\.\.\//g, '')), `${id} explanation has a period inside`);
  }
});

test('compact keeps the assigner, product and best score', () => {
  const rec = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/CVE-2024-3094.json'), 'utf8'));
  const c = compact(rec);
  assert.equal(c.i, 'CVE-2024-3094');
  assert.equal(c.s, 10);
  assert.equal(c.sv, 'CRITICAL');
  assert.equal(c.r, 'xz');
  assert.deepEqual(c.c, ['CWE-506']);
  assert.equal(c.x.a, 'yes');
});

test('the data window is consistent', () => {
  const index = JSON.parse(readFileSync(join(ROOT, 'docs/data/index.json'), 'utf8'));
  const search = JSON.parse(readFileSync(join(ROOT, 'docs/data/search.json'), 'utf8'));
  const sum = index.days.reduce((a, d) => a + d.n, 0);
  assert.equal(sum, search.length);
  assert.equal(index.total, search.length);
  for (const d of index.days) assert.ok(existsSync(join(ROOT, 'docs/data/days', `${d.d}.json`)), d.d);
  const kev = JSON.parse(readFileSync(join(ROOT, 'docs/data/kev.json'), 'utf8'));
  assert.ok(kev.length > 1000);
});

test('every page has a title, a description and the custom domain is set', () => {
  for (const f of htmlFiles) {
    const s = readFileSync(f, 'utf8');
    assert.match(s, /<title>[^<]+<\/title>/, f);
    assert.match(s, /<meta name="description" content="[^"]{20,}">/, f);
    assert.match(s, /<html lang="ar" dir="rtl">/, f);
  }
  assert.equal(readFileSync(join(ROOT, 'docs/CNAME'), 'utf8').trim(), 'cve.3li.info');
});

test('sparse old records get an honest one sentence summary', () => {
  const s = summaryAr({ i: 'CVE-1999-0001', p: '1999-12-30T05:00:00' }).replace(/[\u2068\u2069]/g, '');
  assert.match(s, /^ثغرة لم تذكر الجهة المرقّمة نوعها ولا منتجها/);
  assert.equal(s.split('.').length, 2);
});

test('KEV shards hold every catalogue entry under its CVE year', () => {
  const kev = JSON.parse(readFileSync(join(ROOT, 'docs/data/kev.json'), 'utf8'));
  let n = 0;
  for (const f of readdirSync(join(ROOT, 'docs/data/kev'))) {
    const m = JSON.parse(readFileSync(join(ROOT, 'docs/data/kev', f), 'utf8'));
    for (const id of Object.keys(m)) { assert.equal(id.slice(4, 8), f.slice(0, 4)); n++; }
  }
  assert.equal(n, kev.length);
});

function cveValidator() {
  const dir = join(ROOT, 'tests/schema');
  const load = (p) => JSON.parse(readFileSync(join(dir, p), 'utf8'));
  const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  let main = JSON.stringify(load('CVE_Record_Format.json'));
  for (const f of ['imports/cvss/cvss-v2.0.json', 'imports/cvss/cvss-v3.0.json', 'imports/cvss/cvss-v3.1.json', 'imports/cvss/cvss-v4.0.json', 'tags/adp-tags.json', 'tags/cna-tags.json', 'tags/reference-tags.json']) {
    const s = load(f);
    const id = `raed:${f}`;
    delete s.$schema; delete s.id; s.$id = id;
    ajv.addSchema(s, id);
    main = main.split(`file:${f}`).join(id);
  }
  const schema = JSON.parse(main); delete schema.$schema;
  return ajv.compile(schema);
}

test('every advisory is a valid CVE JSON 5 record with English and Arabic descriptions', () => {
  const validate = cveValidator();
  const dir = join(ROOT, 'advisories');
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
  assert.ok(files.includes('_template.json'));
  for (const f of files) {
    const a = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    assert.ok(validate(a.record), `${f}: ${JSON.stringify(validate.errors?.slice(0, 3))}`);
    const langs = a.record.containers.cna.descriptions.map((d) => d.lang);
    assert.ok(langs.some((l) => /^en/.test(l)) && langs.includes('ar'), `${f} needs en and ar descriptions`);
    const ar = a.record.containers.cna.descriptions.find((d) => d.lang === 'ar').value;
    assert.equal(ar.replace(/\d+(\.\d+)+/g, '0').split('.').length, 2, `${f} Arabic description must be one sentence`);
    if (!f.startsWith('_')) assert.equal(a.raed.id + '.json', f);
  }
});

test('internal application material stays out of the public site and repository', () => {
  assert.ok(!existsSync(join(ROOT, 'docs/cna/raed')), 'docs/cna/raed must not exist');
  assert.ok(!existsSync(join(ROOT, 'templates/pages/64-cna-raed.html')));
  for (const f of ['raed-application.md', 'application-checklist.md']) assert.ok(!existsSync(join(ROOT, 'cna-kit', f)), `cna-kit/${f} belongs in the private repository`);
  for (const f of [...htmlFiles, join(ROOT, 'docs/sitemap.xml'), ...walk(join(ROOT, 'templates'), ['.html']), ...walk(join(ROOT, 'cna-kit'), ['.md']), join(ROOT, 'README.md')]) {
    assert.ok(!readFileSync(f, 'utf8').includes('/cna/raed'), `${f} links the internal page`);
  }
});

test('the report portal hands reports to GitHub private reporting or mail, never to a server', () => {
  const js = readFileSync(join(ROOT, 'docs/assets/js/report.js'), 'utf8');
  assert.match(js, /https:\/\/github\.com\/SiteQ8\/Raed\/security\/advisories\/new/);
  assert.ok(!/fetch\(|XMLHttpRequest|sendBeacon/.test(js), 'the portal must not send data anywhere');
  const page = readFileSync(join(ROOT, 'docs/report/index.html'), 'utf8');
  assert.match(page, /تسعون يوماً/);
  assert.ok(Array.isArray(JSON.parse(readFileSync(join(ROOT, 'docs/data/hall-of-fame.json'), 'utf8'))));
  assert.match(readFileSync(join(ROOT, 'docs/.well-known/security.txt'), 'utf8'), /Acknowledgments: https:\/\/cve\.3li\.info\/hall-of-fame\//);
});
