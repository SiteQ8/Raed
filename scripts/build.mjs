// Builds the static pages of the site from templates/pages and the data in docs/data.
// Pages that list records render a first screen of real data at build time, and the
// browser scripts then take over for filtering and paging.

import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { summaryAr, dateAr, timeAr, kwDay, nVuln, nRecord, countAr, SEV_AR, sevClass, iso } from '../docs/assets/engine/arabic.js';
import { cweAr } from '../docs/assets/engine/cwe.js';
import { detail } from '../docs/assets/engine/record.js';
import { loadAdvisories, descriptionIn, STATUS_AR } from './lib/advisories.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const DOCS = join(ROOT, 'docs');
const DATA = join(DOCS, 'data');
const SITE = 'https://cve.3li.info';
export const NAME = 'رائد';
const TAGLINE = 'سجل الثغرات الأمنية المعلنة بالعربية';

const readJSON = async (p, f = null) => { try { return JSON.parse(await readFile(p, 'utf8')); } catch { return f; } };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const strip = (s) => String(s).replace(/[⁨⁩]/g, '');
// Isolates in engine output become <bdi> in HTML.
export const html = (s) => esc(s).replace(/⁨/g, '<bdi>').replace(/⁩/g, '</bdi>');

const MARK = `<svg viewBox="0 0 48 48" aria-hidden="true"> <defs><clipPath id="mk"><rect width="48" height="48" rx="11"/></clipPath></defs> <rect width="48" height="48" rx="11" fill="#0f5c63"/> <path fill="#e0a21b" d="M15 6 L17 11.8 L22.8 13.8 L17 15.8 L15 21.6 L13 15.8 L7.2 13.8 L13 11.8 Z"/> <g clip-path="url(#mk)"> <path fill="#f2e3bf" d="M-2 48 L-2 39 C 4 34.5, 9 33.2, 14 33.8 C 19 28.5, 26 25.8, 33 26.8 C 40 27.9, 45.5 32, 50 37 L50 48 Z"/> <path fill="#0f5c63" d="M31.6 30.2 C 34.6 31.8, 36.4 34.8, 36.2 38.6 C 36 43, 33.6 46.6, 30.4 49.5 L 26.6 49.5 C 29.4 46.4, 31.2 43, 31.2 39.4 C 31.2 36.6, 30 34.6, 27.8 33.4 Z"/> </g> </svg>`;

const NAV = [
  ['latest', '/latest/', 'أحدث الثغرات'],
  ['kev', '/kev/', 'المستغلة فعلياً'],
  ['week', '/week/', 'النشرة الأسبوعية'],
  ['about', '/about/', 'عن البرنامج'],
  ['cna', '/cna/', 'الجهات المرقّمة'],
  ['glossary', '/glossary/', 'المصطلحات'],
];

export function layout({ title, desc, path, nav = '', body, scripts = [], head = '', noindex = false }) {
  const full = path === '/' ? `${NAME}: ${TAGLINE}` : `${title} | ${NAME}`;
  const navHtml = NAV.map(([k, href, label]) => `<a href="${href}"${k === nav ? ' aria-current="page"' : ''}>${label}</a>`).join('');
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(full)}</title>
<meta name="description" content="${esc(desc)}">
${noindex ? '<meta name="robots" content="noindex">' : `<link rel="canonical" href="${SITE}${path}">`}
<meta property="og:type" content="website">
<meta property="og:locale" content="ar_AR">
<meta property="og:site_name" content="${NAME}">
<meta property="og:title" content="${esc(full)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${SITE}${path}">
<meta property="og:image" content="${SITE}/assets/img/og.jpg">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#0f5c63">
<link rel="icon" href="/assets/img/mark.svg" type="image/svg+xml">
<link rel="icon" href="/assets/img/favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/assets/img/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="alternate" type="application/atom+xml" title="${NAME}: الثغرات الحرجة والمستغلة" href="/feed.xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;600;700&family=IBM+Plex+Sans:wght@400;600&family=Reem+Kufi:wght@600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/css/site.css">
<link rel="stylesheet" href="/assets/css/mobile.css" media="(max-width: 760px)">
<script>try{var t=localStorage.getItem('theme');if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
${head}
</head>
<body>
<a class="skip" href="#main">انتقل إلى المحتوى</a>
<header class="top">
  <div class="wrap">
    <a class="brand" href="/">${MARK}<span><b>${NAME}</b><small>${TAGLINE}</small></span></a>
    <button class="menu" type="button" aria-expanded="false" aria-controls="nav">القائمة</button>
    <nav class="nav" id="nav" aria-label="الأقسام">${navHtml}</nav>
    <button class="theme" type="button" aria-label="تبديل المظهر الفاتح والداكن"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg></button>
  </div>
</header>
<main id="main">
${body}
</main>
<footer class="foot">
  <div class="wrap">
    <div class="cols">
      <div>
        <h4>${NAME}</h4>
        <p>نسخة عربية مفتوحة من سجل الثغرات الأمنية المعلنة، تقرأ سجلات برنامج CVE كما تنشرها الجهات المرقّمة ثم تعرضها بالعربية وتتجدد كل ساعة.</p>
        <p>المشروع مستقل ولا يتبع برنامج CVE أو مؤسسة MITRE أو وكالة CISA، والمرجع الرسمي لكل سجل هو موقع <a href="https://www.cve.org/" rel="noopener">cve.org</a>.</p>
      </div>
      <div>
        <h4>الأقسام</h4>
        <ul>
          <li><a href="/latest/">أحدث الثغرات</a></li>
          <li><a href="/kev/">الثغرات المستغلة فعلياً</a></li>
          <li><a href="/week/">النشرة الأسبوعية</a></li>
          <li><a href="/cna/join/">نحو جهة ترقيم عربية</a></li>
          <li><a href="/advisories/">نشرات رائد</a></li>
          <li><a href="/report/">أبلغ عن ثغرة</a></li>
          <li><a href="/hall-of-fame/">قاعة الشرف</a></li>
          <li><a href="/faq/">الأسئلة الشائعة</a></li>
          <li><a href="/data/">البيانات المفتوحة</a></li>
        </ul>
      </div>
      <div>
        <h4>المصادر</h4>
        <ul>
          <li><a href="https://github.com/CVEProject/cvelistV5" rel="noopener">قائمة سجلات CVE</a></li>
          <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" rel="noopener">قائمة CISA للثغرات المستغلة</a></li>
          <li><a href="https://www.first.org/epss/" rel="noopener">نظام EPSS من FIRST</a></li>
          <li><a href="https://cwe.mitre.org/" rel="noopener">تصنيف نقاط الضعف CWE</a></li>
          <li><a href="https://github.com/SiteQ8/Raed" rel="noopener">الشيفرة المصدرية</a></li>
        </ul>
      </div>
    </div>
    <p class="fine">CVE® علامة تجارية مسجلة لمؤسسة MITRE، وتُستخدم سجلات البرنامج وفق <a href="https://www.cve.org/Legal/TermsOfUse" rel="noopener">شروط الاستخدام</a> التي تتيح نسخها وتوزيعها مع الإشارة إلى المصدر، أما الشيفرة فمنشورة برخصة MIT.</p>
  </div>
</footer>
<script type="module" src="/assets/js/site.js"></script>
${scripts.map((s) => `<script type="module" src="${s}"></script>`).join('\n')}
</body>
</html>
`;
}

export function sevMark(sv, s) {
  if (!sv) return `<span class="sev na">بلا تقييم</span>`;
  return `<span class="sev ${sevClass(sv)}">${SEV_AR[sv]}${s != null ? ` <span class="num">${Number(s).toFixed(1)}</span>` : ''}</span>`;
}

export function rowHtml(it) {
  const prod = it.r || it.v ? `<span class="prod"><bdi>${esc(it.r || it.v)}</bdi>${it.r && it.v && it.v !== it.r ? ` <small><bdi>${esc(it.v)}</bdi></small>` : ''}</span>` : '';
  return `<li><a class="row" href="/record/?id=${it.i}">
<span class="id"><b dir="ltr">${it.i}</b><small>${dateAr(it.p, { year: false })}</small></span>
<span class="what">${prod}<p>${html(summaryAr(it))}</p></span>
<span class="marks">${sevMark(it.sv, it.s)}${it.k ? '<span class="kev">مستغلة فعلياً</span>' : ''}</span>
</a></li>`;
}

async function writePage(path, content) {
  const file = path.endsWith('/') ? join(DOCS, path, 'index.html') : join(DOCS, path);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, content);
}

async function loadPages() {
  const dir = join(ROOT, 'templates/pages');
  const out = [];
  for (const f of (await readdir(dir)).sort()) {
    if (!f.endsWith('.html')) continue;
    const raw = await readFile(join(dir, f), 'utf8');
    const m = raw.match(/^<!--\s*({[\s\S]*?})\s*-->\n?/);
    if (!m) throw new Error(`page ${f} has no header`);
    out.push({ ...JSON.parse(m[1]), body: raw.slice(m[0].length), file: f });
  }
  return out;
}

function weekOf(dateStr) {
  const d = new Date(dateStr + 'T00:00:00Z');
  const day = (d.getUTCDay() + 6) % 7;
  d.setUTCDate(d.getUTCDate() - day + 3);
  const firstThu = new Date(Date.UTC(d.getUTCFullYear(), 0, 4));
  const wk = 1 + Math.round(((d - firstThu) / 864e5 - 3 + ((firstThu.getUTCDay() + 6) % 7)) / 7);
  return `${d.getUTCFullYear()}-W${String(wk).padStart(2, '0')}`;
}

async function main() {
  const index = await readJSON(join(DATA, 'index.json'), { days: [] });
  const kev = await readJSON(join(DATA, 'kev.json'), []);
  const weeks = await readJSON(join(DATA, 'weeks/index.json'), []);
  const days = index.days || [];
  const latestDay = days[0]?.d;
  const dayItems = latestDay ? await readJSON(join(DATA, 'days', `${latestDay}.json`), []) : [];
  // Today can be thin early in the day, so the home page shows the newest 12 published records across the last two days.
  const prevItems = days[1] ? await readJSON(join(DATA, 'days', `${days[1].d}.json`), []) : [];
  const newest = [...dayItems, ...prevItems].filter((x) => !x.st).slice(0, 12);
  const since = new Date(new Date(index.generated || Date.now()).getTime() - 864e5).toISOString().slice(0, 19);
  const last24 = [...dayItems, ...prevItems].filter((x) => !x.st && x.p >= since).length;
  const advisories = await loadAdvisories();
  const hall = await readJSON(join(DATA, 'hall-of-fame.json'), []);
  const ctx = { index, kev, days, newest, weeks, latestDay, last24, advisories, hall };

  const pages = await loadPages();
  const urls = [];
  for (const p of pages) {
    let body = p.body;
    body = await fill(body, ctx);
    if (p.doc) body = docLayout(body);
    await writePage(p.path, layout({ ...p, body, scripts: p.scripts || [] }));
    if (!p.noindex) urls.push(p.path);
  }
  for (const w of weeks) urls.push(`/week/${w.id}/`);

  // Raed's own advisories.
  for (const adv of ctx.advisories) {
    const id = adv.raed.id;
    await writePage(`/advisories/${id}/`, layout({
      title: `${id}: ${adv.raed.titleAr}`,
      desc: descriptionIn(adv.record, 'ar').slice(0, 200),
      path: `/advisories/${id}/`,
      nav: 'cna',
      body: docLayout(advisoryBody(adv)),
    }));
    await mkdir(join(DOCS, 'advisories'), { recursive: true });
    await writeFile(join(DOCS, 'advisories', `${id}.json`), JSON.stringify(adv.record, null, 2) + '\n');
    urls.push(`/advisories/${id}/`);
  }

  // Weekly digest pages.
  for (const w of weeks) {
    const data = await readJSON(join(DATA, 'weeks', `${w.id}.json`));
    if (!data) continue;
    await writePage(`/week/${w.id}/`, layout({
      title: `النشرة الأسبوعية ${data.titleAr}`,
      desc: data.lineAr,
      path: `/week/${w.id}/`,
      nav: 'week',
      body: docLayout(weekBody(data), [WEEK_RAIL]),
    }));
  }

  await writeFile(join(DOCS, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `<url><loc>${SITE}${u}</loc></url>`).join('\n')}\n</urlset>\n`);
  await writeFile(join(DOCS, 'feed.xml'), feed(ctx, await readWindow(days.slice(0, 7))));
  console.log(`built ${pages.length} pages and ${weeks.length} weekly digests`);
}

// Text pages on wide screens: the reading column on the start side and a sticky rail beside it
// holding the page's contents and the page's own side panel (an <aside class="rail-extra"> in the template).
const WEEK_RAIL = '<p class="rail-label">تابع أولاً بأول</p><p>الثغرات الحرجة والمستغلة تصل في <a href="/feed.xml">موجز Atom</a> مع كل تحديث، وكل النشرات السابقة في <a href="/week/">صفحة النشرة الأسبوعية</a>.</p>';

export function docLayout(body, more = []) {
  const headStart = body.indexOf('<header');
  const wrapEnd = body.lastIndexOf('</div>');
  if (headStart < 0 || wrapEnd < headStart) return body;
  let main = body.slice(headStart, wrapEnd);
  const extras = [...more];
  main = main.replace(/<aside class="rail-extra">([\s\S]*?)<\/aside>\s*/g, (_, x) => { extras.push(x); return ''; });
  const toc = [];
  let n = 0;
  main = main.replace(/<h2( id="([^"]+)")?([^>]*)>([\s\S]*?)<\/h2>/g, (_, hasId, id, rest, text) => {
    const anchor = id || `s${++n}`;
    toc.push([anchor, text.replace(/<[^>]+>/g, '')]);
    return `<h2 id="${anchor}"${rest}>${text}</h2>`;
  });
  const tocHtml = toc.length >= 2
    ? `<nav class="toc" aria-labelledby="toc-h"><p class="rail-label" id="toc-h">في هذه الصفحة</p><ol>${toc.map(([a, t]) => `<li><a href="#${a}">${t}</a></li>`).join('')}</ol></nav>`
    : '';
  const rail = tocHtml + extras.map((x) => `<div class="rail-box">${x.trim()}</div>`).join('');
  return `${body.slice(0, headStart)}<div class="doc${rail ? '' : ' solo'}">\n  <div class="doc-main">${main}</div>\n  ${rail ? `<aside class="rail">${rail}</aside>` : ''}\n  </div>\n${body.slice(wrapEnd)}`;
}

async function readWindow(ds) {
  const out = [];
  for (const d of ds) out.push(...(await readJSON(join(DATA, 'days', `${d.d}.json`), [])));
  return out;
}

function feed(ctx, items) {
  const pick = items.filter((x) => !x.st && (x.sv === 'CRITICAL' || x.k)).sort((a, b) => (a.p < b.p ? 1 : -1)).slice(0, 60);
  const entries = pick.map((it) => `<entry><id>${SITE}/record/?id=${it.i}</id><title>${esc(it.i)}${it.r ? ' ' + esc(it.r) : ''}</title><link href="${SITE}/record/?id=${it.i}"/><updated>${it.u}Z</updated><summary type="text">${esc(strip(summaryAr(it)))}</summary></entry>`).join('\n');
  return `<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="ar"><title>${NAME}: الثغرات الحرجة والمستغلة فعلياً</title><id>${SITE}/feed.xml</id><link href="${SITE}/feed.xml" rel="self"/><link href="${SITE}/"/><updated>${ctx.index.generated || new Date().toISOString()}</updated><author><name>${NAME}</name></author>\n${entries}\n</feed>\n`;
}

function wallHtml(days) {
  const asc = [...days].reverse().slice(-30);
  const max = Math.max(1, ...asc.map((d) => d.n));
  const per = Math.max(5, Math.ceil(max / 32 / 5) * 5);
  let n = 0;
  const cols = asc.map((d) => {
    const ticks = [];
    const add = (count, cls) => { for (let k = 0; k < Math.round(count / per); k++) ticks.push(`<i class="${cls}" style="--n:${n++}"></i>`); };
    add(d.c, 'crit'); add(d.h, 'high'); add(d.m, 'med'); add(d.l, 'low');
    add(Math.max(0, d.n - d.c - d.h - d.m - d.l), 'na');
    const label = `${dateAr(d.d, { weekday: true })}: ${nVuln(d.n)}، منها ${d.c} حرجة و${d.h} عالية`;
    return `<a class="col" href="/latest/?day=${d.d}" title="${esc(label)}" aria-label="${esc(label)}">${ticks.join('')}</a>`;
  });
  return { html: cols.join(''), per, first: asc[0]?.d, last: asc[asc.length - 1]?.d, count: asc.length };
}

async function fill(body, ctx) {
  const { index, kev, days, newest, weeks, latestDay, last24 } = ctx;
  const wk = days.slice(0, 7);
  const sum = (k) => wk.reduce((a, d) => a + (d[k] || 0), 0);
  const map = {
    '{{generated}}': index.generated ? `في ${dateAr(index.generated)} الساعة ${timeAr(index.generated)}` : '',
    '{{today_n}}': last24.toLocaleString('en-US'),
    '{{today_label}}': `${last24 === 2 ? 'ثغرتان نُشرتا' : last24 % 100 >= 3 && last24 % 100 <= 10 ? 'ثغرات نُشرت' : 'ثغرة نُشرت'} في آخر 24 ساعة`,
    '{{week_n}}': sum('n').toLocaleString('en-US'),
    '{{week_crit}}': sum('c').toLocaleString('en-US'),
    '{{week_kev}}': kev.filter((k) => k.da >= (wk[wk.length - 1]?.d || '9')).length.toString(),
    '{{window_n}}': (index.total || 0).toLocaleString('en-US'),
    '{{kev_total}}': kev.length.toLocaleString('en-US'),
    '{{newest_rows}}': newest.map(rowHtml).join('\n'),
    '{{kev_side}}': kev.slice(0, 6).map((k) => `<li><a href="/record/?id=${k.i}">${k.i}</a><p>${html(`${iso(k.r)} من ${iso(k.v)}`)}</p><span class="meta">أُدرجت في ${dateAr(k.da)}${k.ra ? ' وتستخدمها حملات فدية' : ''}</span></li>`).join(''),
    '{{week_link}}': weeks[0] ? `<a href="/week/${weeks[0].id}/">${esc(weeks[0].titleAr)}</a>` : '',
    '{{weeks_list}}': weeks.map((w) => `<li><a href="/week/${w.id}/">${esc(w.titleAr)}</a><p>${esc(w.lineAr)}</p></li>`).join('') || '<li><p>تصدر أول نشرة يوم الاثنين.</p></li>',
    '{{latest_day}}': latestDay || '',
    '{{advisories_n}}': String(ctx.advisories.length),
    '{{hall_list}}': ctx.hall.length
      ? ctx.hall.map((h) => `<li><b>${esc(h.name)}</b><span>${h.advisory ? `<a href="/advisories/${esc(h.advisory)}/">${esc(h.advisory)}</a>` : ''}${h.cve ? ` <a class="ltr" href="/record/?id=${esc(h.cve)}">${esc(h.cve)}</a>` : ''}</span><small>${dateAr(h.date)}</small></li>`).join('')
      : '<li class="empty"><p>القاعة فارغة حتى اليوم، وأول اسم فيها سيكون لأول باحث يُنشر بلاغه.</p></li>',
    '{{advisories_list}}': ctx.advisories.length
      ? ctx.advisories.map((a) => `<li><a href="/advisories/${a.raed.id}/">${esc(a.raed.id)}</a><p>${esc(a.raed.titleAr)}</p><span class="meta">${dateAr(a.raed.published)}، ${esc(STATUS_AR[a.raed.status] || '')}${a.raed.status === 'published' ? `، والرقم <bdi>${esc(a.record.cveMetadata.cveId)}</bdi>` : ''}</span></li>`).join('')
      : '<li><p>لم تصدر نشرة بعد، وستكون أول نشرة لأول ثغرة تبلغنا بها في برمجية أو خدمة عربية.</p></li>',
  };
  if (body.includes('{{wall}}')) {
    const w = wallHtml(days);
    map['{{wall}}'] = `<div class="wall" style="--days:${w.count}" role="img" aria-label="عدد الثغرات المنشورة في كل يوم خلال آخر ${countAr(w.count, { plural: 'أيام', acc: 'يوماً', gen: 'يوم' })}">${w.html}</div><div class="wall-axis"><span>${dateAr(w.first, { year: false })}</span><span>${dateAr(w.last, { year: false })}</span></div><p class="legend"><span style="--c:var(--crit)">حرجة</span><span style="--c:var(--high)">عالية</span><span style="--c:var(--med)">متوسطة</span><span style="--c:var(--low)">منخفضة</span><span style="--c:var(--na)">بلا تقييم</span><span>كل شرطة تمثل ${countAr(w.per, { one: 'سجلاً واحداً', two: 'سجلين', plural: 'سجلات', acc: 'سجلاً', gen: 'سجل' })}</span></p>`;
  }
  if (body.includes('{{top_cwe}}') || body.includes('{{top_vendor}}')) {
    const items = await readWindow(wk);
    const live = items.filter((x) => !x.st);
    const cw = new Map(); const vd = new Map();
    for (const it of live) {
      const c = (it.c || [])[0]; if (c) cw.set(c, (cw.get(c) || 0) + 1);
      if (it.v) vd.set(it.v, (vd.get(it.v) || 0) + 1);
    }
    const bars = (m, label) => { const arr = [...m].sort((a, b) => b[1] - a[1]).slice(0, 8); const mx = arr[0]?.[1] || 1; return arr.map(([k, v]) => `<li><span>${label(k)}</span><span class="num">${v.toLocaleString('en-US')}</span><span class="bar"><i style="width:${Math.round((v / mx) * 100)}%"></i></span></li>`).join(''); };
    map['{{top_cwe}}'] = bars(cw, (k) => esc(cweAr(k)?.name || k));
    map['{{top_vendor}}'] = bars(vd, (k) => `<bdi>${esc(k)}</bdi>`);
  }
  if (body.includes('{{cna_count}}') || body.includes('{{cna_rows}}')) {
    const cnas = await readJSON(join(DATA, 'cnas.json'), []);
    map['{{cna_count}}'] = cnas.length.toLocaleString('en-US');
    map['{{cna_countries}}'] = new Set(cnas.map((c) => c.co).filter((c) => c && c !== 'n/a')).size.toString();
    map['{{cna_arab}}'] = cnas.filter((c) => c.arab).length.toString();
  }
  for (const [k, v] of Object.entries(map)) body = body.split(k).join(v);
  return body;
}

function weekBody(w) {
  const sevs = [['CRITICAL', w.sev.CRITICAL], ['HIGH', w.sev.HIGH], ['MEDIUM', w.sev.MEDIUM], ['LOW', w.sev.LOW]];
  return `<div class="wrap">
<header class="head"><p class="lead"><a href="/week/">النشرة الأسبوعية</a></p><h1>${esc(w.titleAr)}</h1><p class="lead">${esc(w.lineAr)}</p></header>
<div class="stat-row">
<div><b class="num">${w.total.toLocaleString('en-US')}</b><span>مجموع السجلات</span></div>
${sevs.map(([s, n]) => `<div><b class="num">${n.toLocaleString('en-US')}</b><span>${SEV_AR[s]}</span></div>`).join('')}
<div><b class="num">${w.kevAdded.length}</b><span>أُضيفت إلى قائمة الثغرات المستغلة فعلياً</span></div>
</div>
<div class="prose">${w.paragraphsAr.map((p) => `<p>${html(p).replace(/CVE-\d{4}-\d{4,}/g, (m) => `<span class="cid">${m}</span>`)}</p>`).join('')}</div>
${w.kevAdded.length ? `<h2>ما أُضيف إلى قائمة الثغرات المستغلة فعلياً</h2><ul class="side-list">${w.kevAdded.map((k) => `<li><a href="/record/?id=${k.i}">${k.i}</a><p>${html(`${iso(k.r)} من ${iso(k.v)}`)}</p><span class="meta">أُدرجت في ${dateAr(k.da)} وموعد المعالجة للجهات الاتحادية الأمريكية ${dateAr(k.due)}${k.ra ? ' وتستخدمها حملات فدية' : ''}</span></li>`).join('')}</ul>` : ''}
<h2>أخطر ما نُشر هذا الأسبوع</h2>
<ul class="reg">${w.top.map(rowHtml).join('\n')}</ul>
<h2>الأعلى احتمالاً للاستغلال</h2>
<ul class="reg">${w.epssTop.map(rowHtml).join('\n')}</ul>
<div class="cols-2">
<div><h2>أكثر أنواع الضعف</h2><ul class="bars">${w.cwe.map(([k, v]) => `<li><span>${esc(cweAr(k)?.name || k)}</span><span class="num">${v}</span><span class="bar"><i style="width:${Math.round((v / w.cwe[0][1]) * 100)}%"></i></span></li>`).join('')}</ul></div>
<div><h2>المورّدون الأكثر وروداً</h2><ul class="bars">${w.vendors.map(([k, v]) => `<li><span><bdi>${esc(k)}</bdi></span><span class="num">${v}</span><span class="bar"><i style="width:${Math.round((v / w.vendors[0][1]) * 100)}%"></i></span></li>`).join('')}</ul></div>
</div>
<p class="count-line">البيانات حتى ${dateAr(w.generated)} وتشمل السجلات المنشورة من ${dateAr(w.from)} إلى ${dateAr(w.to)}.</p>
</div>`;
}

function advisoryBody(adv) {
  const d = detail(adv.record);
  const ar = descriptionIn(adv.record, 'ar');
  const en = descriptionIn(adv.record, 'en');
  const cve = adv.raed.status === 'published' ? adv.record.cveMetadata.cveId : '';
  const affected = d.affected.map((a) => `<tr><td><bdi>${esc(a.product)}</bdi><br><small style="color:var(--muted)"><bdi>${esc(a.vendor)}</bdi></small></td><td>${a.versions.filter((v) => v.status === 'affected').map((v) => v.lessThan ? `${v.version && v.version !== '0' ? `من <bdi>${esc(v.version)}</bdi> ` : 'كل الإصدارات '}حتى ما قبل <bdi>${esc(v.lessThan)}</bdi>` : `الإصدار <bdi>${esc(v.version)}</bdi>`).join('<br>')}</td></tr>`).join('');
  return `<div class="wrap">
<header class="rec-head">
  <p class="lead"><a href="/advisories/">نشرات رائد</a></p>
  <h1 class="cve">${esc(adv.raed.id)}</h1>
  <div class="state">${sevMark(d.sv, d.s)}<span class="sev na">${esc(STATUS_AR[adv.raed.status] || '')}</span>${cve ? `<a class="ltr" href="/record/?id=${cve}">${cve}</a>` : ''}</div>
  <p class="summary">${esc(adv.raed.titleAr)}</p>
  <p class="dates">صدرت في ${dateAr(adv.raed.published)}.</p>
</header>
<div class="rec-grid"><div>
  <h2>الوصف</h2>
  <p class="summary" style="font-size:19px">${esc(ar)}</p>
  <p class="label">الوصف الإنجليزي كما يُنشر في سجل CVE</p>
  <div class="original">${esc(en)}</div>
  ${d.c?.length ? `<h2>نوع الضعف</h2><p>${d.c.map((c) => `${esc(cweAr(c)?.name || c)} <bdi>${esc(c)}</bdi>`).join('، ')}</p>` : ''}
  ${affected ? `<h2>المنتجات والإصدارات المصابة</h2><table class="t"><thead><tr><th scope="col">المنتج</th><th scope="col">الإصدارات</th></tr></thead><tbody>${affected}</tbody></table>` : ''}
  ${d.refs.length ? `<h2>المراجع</h2><ul class="refs">${d.refs.map((r) => `<li><a href="${esc(r.url)}" rel="noopener">${esc(r.url)}</a></li>`).join('')}</ul>` : ''}
  ${d.credits.length ? `<h2>الشكر</h2><ul class="refs">${d.credits.map((c) => `<li><bdi>${esc(c.who)}</bdi></li>`).join('')}</ul>` : ''}
</div><aside>
  <div class="panel"><h3>السجل بصيغة CVE JSON 5</h3><p class="count-line">هذا الملف هو ما يُرفع إلى خدمات CVE كما هو، ويحمل الوصفين العربي والإنجليزي معاً.</p><a class="btn quiet" href="/advisories/${esc(adv.raed.id)}.json">تنزيل السجل</a></div>
</aside></div></div>`;
}

export { weekOf };

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => { console.error(e); process.exit(1); });
