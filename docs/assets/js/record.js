import { detail } from '../engine/record.js';
import { summaryAr, dateAr, timeAr, countAr, SEV_AR, sevClass, vectorAr, epssAr, versionsAr, SSVC_X, SSVC_A, SSVC_T, iso } from '../engine/arabic.js';
import { cweAr } from '../engine/cwe.js';
import { esc, html, sevMark, getJSON } from './ui.js';

const box = document.getElementById('rec');
const status = document.getElementById('status');
const id = (new URLSearchParams(location.search).get('id') || '').trim().toUpperCase();

const TAG_AR = {
  'vendor-advisory': 'نشرة المورّد', patch: 'إصلاح', exploit: 'شيفرة استغلال', 'third-party-advisory': 'نشرة جهة أخرى',
  'issue-tracking': 'متابعة المشكلة', 'release-notes': 'ملاحظات الإصدار', mitigation: 'تخفيف', technical: 'تفاصيل تقنية',
  'x_refsource_CONFIRM': 'تأكيد', 'x_refsource_MISC': 'متفرقات', 'related': 'ذو صلة', 'signature': 'توقيع',
  'mailing-list': 'قائمة بريدية', 'permissions-required': 'يتطلب صلاحية', 'media-coverage': 'تغطية إعلامية', 'product': 'المنتج',
  'government-resource': 'مصدر حكومي', 'broken-link': 'رابط معطل', 'not-applicable': 'لا ينطبق', 'vdb-entry': 'قاعدة ثغرات',
};
// x_transferred only says the tag came over from the old CVE list, and x_refsource_* names the source.
function refTags(tags) {
  const out = [];
  for (const t of tags || []) {
    if (t === 'x_transferred') continue;
    const m = /^x_refsource_(.+)$/i.exec(t);
    const v = TAG_AR[t] || (m ? `المصدر ${m[1].replace(/_/g, ' ')}` : t);
    if (!out.includes(v)) out.push(v);
  }
  return out;
}
const CREDIT_AR = { finder: 'اكتشفها', reporter: 'أبلغ عنها', analyst: 'حللها', coordinator: 'نسّق الإفصاح', 'remediation developer': 'طوّر الإصلاح', 'remediation reviewer': 'راجع الإصلاح', 'remediation verifier': 'تحقق من الإصلاح', tool: 'أداة', sponsor: 'راعٍ', other: 'أخرى' };
const SRC_AR = (s) => (s === 'cna' ? 'الجهة المرقّمة' : /cisa/i.test(s) ? 'وكالة CISA' : s);

async function fetchRecord(cve) {
  try {
    const r = await fetch(`https://cveawg.mitre.org/api/cve/${cve}`);
    if (r.ok) return await r.json();
    if (r.status === 404) return null;
  } catch (e) { /* fall through to the list on GitHub */ }
  const [, year, num] = cve.match(/CVE-(\d{4})-(\d+)/);
  const bucket = `${num.slice(0, -3) || '0'}xxx`;
  const r = await fetch(`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${cve}.json`);
  return r.ok ? r.json() : null;
}

async function epss(cve) {
  try {
    const r = await fetch(`https://api.first.org/data/v1/epss?cve=${cve}`);
    const j = await r.json();
    const row = j.data?.[0];
    return row ? { e: Number(row.epss), ep: Number(row.percentile), date: row.date } : null;
  } catch { return null; }
}

function panelScore(d) {
  if (d.s == null) return `<div class="panel"><h3>الخطورة</h3><p class="count-line">لم تنشر الجهة المرقّمة ولا جهات النشر المعتمدة تقييماً لخطورة هذه الثغرة بعد.</p></div>`;
  const cls = sevClass(d.sv);
  const rows = vectorAr(d.vec).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('');
  const others = d.metrics.filter((m) => !(m.v === d.cv && m.src === d.cs && m.score === d.s));
  return `<div class="panel"><h3>الخطورة</h3>
<div class="score ${cls}"><b>${Number(d.s).toFixed(1)}</b><span>${SEV_AR[d.sv] || ''} من 10</span></div>
<div class="meter" style="--c:var(--${cls === 'med' ? 'med' : cls})"><i style="width:${d.s * 10}%;background:var(--${cls})"></i></div>
<p class="count-line">تقييم CVSS ${esc(d.cv)} بحسب ${esc(SRC_AR(d.cs))}</p>
<dl class="facts">${rows}</dl>
${d.vec ? `<p class="label">المتجه</p><p class="ltr vec" style="font-size:13.5px;margin:0">${esc(d.vec).split('/').join('/<wbr>')}</p>` : ''}
${others.length ? `<p class="label">تقييمات أخرى</p><dl class="facts">${others.map((m) => `<dt>${esc(SRC_AR(m.src))} <bdi>${esc(m.v)}</bdi></dt><dd><span class="num">${m.score}</span> ${SEV_AR[String(m.sev || '').toUpperCase()] || ''}</dd>`).join('')}</dl>` : ''}
</div>`;
}

function panelExploit(d, ep, kev) {
  const parts = [];
  if (kev) {
    parts.push(`<div class="panel" style="border-color:var(--kev)"><h3>مستغلة فعلياً</h3>
<p style="margin:0 0 8px">أدرجتها وكالة CISA في قائمة الثغرات المستغلة فعلياً في ${dateAr(kev.da)}${kev.ra ? '، ورصدت استخدامها في حملات فدية' : ''}، وحددت لمعالجتها في الجهات الاتحادية الأمريكية موعداً أقصاه ${dateAr(kev.due)}.</p>
<p class="label">الإجراء المطلوب كما نشرته الوكالة</p><p class="ltr" style="margin:0;font-size:14.5px;text-align:left">${esc(kev.act || '')}</p></div>`);
  }
  if (ep) {
    parts.push(`<div class="panel"><h3>احتمال الاستغلال</h3>
<div class="score"><b style="--c:var(--sea);color:var(--sea)">${ep.e * 100 < 0.1 ? '&lt;0.1' : (ep.e * 100).toFixed(ep.e < 0.1 ? 1 : 0)}%</b></div>
<div class="meter"><i style="width:${Math.max(1, ep.ep * 100)}%;background:var(--sea)"></i></div>
<p style="margin:0;font-size:15px;color:var(--ink-2)">${html(epssAr(ep.e, ep.ep))}، بحسب نظام EPSS بتاريخ ${dateAr(ep.date)}.</p></div>`);
  }
  if (d.x) {
    parts.push(`<div class="panel"><h3>تقدير CISA</h3><dl class="facts">
${d.x.x ? `<dt>الاستغلال</dt><dd>${SSVC_X[d.x.x] || esc(d.x.x)}</dd>` : ''}
${d.x.a ? `<dt>الأتمتة</dt><dd>${SSVC_A[d.x.a] || esc(d.x.a)}</dd>` : ''}
${d.x.t ? `<dt>الأثر التقني</dt><dd>${SSVC_T[d.x.t] || esc(d.x.t)}</dd>` : ''}
</dl></div>`);
  }
  return parts.join('');
}

function affectedTable(d) {
  if (!d.affected.length) return '';
  const rows = [];
  // Rows are skipped when the record names neither product nor versions, so the table can end up empty.
  for (const a of d.affected.slice(0, 40)) {
    const vs = versionsAr(a);
    const shown = vs.filter((v) => v.status === 'affected').slice(0, 6);
    const unaffected = vs.filter((v) => v.status === 'unaffected').slice(0, 3);
    const prodName = a.product && a.product !== 'n/a' ? a.product : '';
    if (!prodName && !shown.length && !unaffected.length) continue;
    rows.push(`<tr><td><bdi>${esc(prodName || 'لم يُحدد')}</bdi>${a.vendor && a.vendor !== 'n/a' ? `<br><small style="color:var(--muted)"><bdi>${esc(a.vendor)}</bdi></small>` : ''}</td>
<td>${shown.map((v) => html(v.range)).join('<br>') || (a.defaultStatus === 'affected' ? 'كل الإصدارات' : 'لم تُذكر')}${vs.length > shown.length + unaffected.length ? '<br><small style="color:var(--muted)">وإصدارات أخرى في السجل الأصلي</small>' : ''}</td>
<td>${unaffected.map((v) => html(v.range)).join('<br>') || '<span style="color:var(--muted)">لم تُذكر</span>'}</td></tr>`);
  }
  if (!rows.length) return '';
  return `<h2>المنتجات والإصدارات</h2><div style="overflow-x:auto"><table class="t"><thead><tr><th scope="col">المنتج</th><th scope="col">الإصدارات المصابة</th><th scope="col">غير المصابة</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>${d.affected.length > 40 ? `<p class="count-line">يذكر السجل ${countAr(d.affected.length, { plural: 'منتجات', acc: 'منتجاً', gen: 'منتج' })}، والقائمة كاملة في السجل الأصلي.</p>` : ''}`;
}

function cweBlock(d) {
  if (!d.c?.length) return '';
  return `<h2>نوع الضعف</h2>${d.c.map((c) => {
    const ar = cweAr(c);
    const num = c.replace('CWE-', '');
    const link = /^\d+$/.test(num) ? `https://cwe.mitre.org/data/definitions/${num}.html` : null;
    return `<div class="cwe-box panel"><h3 style="margin:0">${ar ? esc(ar.name) : 'نوع ضعف لم يُترجم بعد'} ${link ? `<a class="ltr" href="${link}" rel="noopener" style="font-weight:400;font-size:14px">${esc(c)}</a>` : `<bdi>${esc(c)}</bdi>`}</h3>${ar ? `<p>${esc(ar.why)}.</p>` : ''}${d.cweNames[c] ? `<p class="ltr" style="text-align:left;color:var(--muted);font-size:14px">${esc(d.cweNames[c])}</p>` : ''}</div>`;
  }).join('')}`;
}

function render(d, kev, ep) {
  const it = { ...d, k: kev?.da };
  const title = `${d.i}${d.r ? ' في ' + d.r : ''}`;
  document.title = `${title} | رائد`;
  document.querySelector('meta[name="description"]')?.setAttribute('content', summaryAr(it).replace(/[⁨⁩]/g, ''));
  const stateMark = d.st === 'REJECTED' ? '<span class="sev crit">مرفوض</span>' : d.st === 'RESERVED' ? '<span class="sev na">محجوز</span>' : sevMark(d.sv, d.s);
  box.innerHTML = `
<header class="rec-head">
  <h1 class="cve">${esc(d.i)}</h1>
  <div class="state">${stateMark}${kev ? '<span class="kev">مستغلة فعلياً</span>' : ''}${d.r || d.v ? `<span class="prod-line"><bdi>${esc(d.r || d.v)}</bdi>${d.r && d.v && d.v !== d.r ? ` <small><bdi>${esc(d.v)}</bdi></small>` : ''}</span>` : ''}</div>
  <p class="summary">${html(summaryAr(it))}</p>
  <p class="dates">نُشر في ${dateAr(d.p)} الساعة ${timeAr(d.p)}، وعُدّل آخر مرة في ${dateAr(d.u)}، والجهة المرقّمة <bdi>${esc(d.a)}</bdi>${d.reserved ? `، وحُجز الرقم في ${dateAr(d.reserved)}` : ''}.</p>
</header>
<div class="rec-grid">
  <div>
    <p class="label">الوصف الأصلي كما نشرته الجهة المرقّمة</p>
    ${d.t ? `<p class="ltr" style="text-align:left;font-weight:600;margin:0 0 8px">${esc(d.t)}</p>` : ''}
    <div class="original">${esc(d.d || 'No description.')}</div>
    ${cweBlock(d)}
    ${affectedTable(d)}
    ${d.solutions || d.workarounds ? `<h2>الإصلاح والتخفيف</h2>${d.solutions ? `<p class="label">الحل كما نشرته الجهة المرقّمة</p><div class="original">${esc(d.solutions)}</div>` : ''}${d.workarounds ? `<p class="label">التخفيف المؤقت</p><div class="original">${esc(d.workarounds)}</div>` : ''}` : ''}
    ${d.refs.length ? `<h2>المراجع</h2><ul class="refs">${d.refs.slice(0, 60).map((r) => `<li><a href="${esc(r.url)}" rel="noopener nofollow">${esc(r.url)}</a>${refTags(r.tags).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</li>`).join('')}</ul>` : ''}
    ${d.credits.length ? `<h2>الشكر</h2><ul class="refs">${d.credits.map((c) => `<li><bdi>${esc(c.who)}</bdi> <span class="tag">${esc(CREDIT_AR[c.type] || c.type)}</span></li>`).join('')}</ul>` : ''}
  </div>
  <aside>
    ${panelScore(d)}
    ${panelExploit(d, ep, kev)}
    <div class="panel"><h3>المصادر الرسمية</h3><ul class="refs">
      <li><a href="https://www.cve.org/CVERecord?id=${d.i}" rel="noopener">السجل في cve.org</a></li>
      <li><a href="https://nvd.nist.gov/vuln/detail/${d.i}" rel="noopener">السجل في قاعدة NVD</a></li>
      <li><a href="https://cveawg.mitre.org/api/cve/${d.i}" rel="noopener">السجل بصيغة JSON</a></li>
    </ul></div>
  </aside>
</div>`;
}

async function main() {
  if (!id) return;
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) { status.textContent = 'رقم الثغرة يبدأ بـ CVE ثم السنة ثم رقم من أربع خانات أو أكثر، مثل CVE-2024-3094.'; return; }
  document.getElementById('q').value = id;
  status.textContent = `يجري جلب السجل ${id} من خدمة CVE الرسمية.`;
  const [rec, kevShard, ep] = await Promise.all([fetchRecord(id), (Number(id.slice(4, 8)) <= new Date().getUTCFullYear() ? getJSON(`/data/kev/${id.slice(4, 8)}.json`).catch(() => ({})) : Promise.resolve({})), epss(id)]);
  if (!rec) { status.textContent = `لم نجد السجل ${id} في قائمة CVE، فتأكد من الرقم، لأنه قد يكون محجوزاً ولم يُنشر سجله بعد.`; return; }
  const d = detail(rec);
  const kev = kevShard[id] || null;
  render(d, kev, ep);
}

main().catch(() => { status.textContent = 'تعذر الوصول إلى خدمة CVE الآن، فأعد المحاولة بعد قليل.'; });
