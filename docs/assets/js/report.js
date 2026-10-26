// The report portal works entirely in the browser: it builds a structured report and hands it to
// GitHub private vulnerability reporting or the reporter's own mail client. Nothing is sent from here.
import { CWE_AR } from '../engine/cwe.js';

const GH = 'https://github.com/SiteQ8/Raed/security/advisories/new';
const MAIL = 'site@hotmail.com';
const DRAFT = 'raed-report-draft';
const form = document.getElementById('report');
const err = document.getElementById('form-error');
const ready = document.getElementById('ready');
const preview = document.getElementById('preview');
const copied = document.getElementById('copied');

// Weakness types, most common first, then the rest by number.
const COMMON = ['CWE-79', 'CWE-89', 'CWE-22', 'CWE-862', 'CWE-863', 'CWE-639', 'CWE-287', 'CWE-306', 'CWE-352', 'CWE-918', 'CWE-78', 'CWE-94', 'CWE-434', 'CWE-502', 'CWE-200', 'CWE-601', 'CWE-798', 'CWE-787', 'CWE-416', 'CWE-400'];
const sel = form.cwe;
const add = (id) => { const o = document.createElement('option'); o.value = id; o.textContent = `${CWE_AR[id][0]} (${id})`; sel.append(o); };
COMMON.filter((id) => CWE_AR[id]).forEach(add);
const sep = document.createElement('option'); sep.disabled = true; sep.textContent = 'أنواع أخرى'; sel.append(sep);
Object.keys(CWE_AR).filter((id) => /^CWE-\d+$/.test(id) && !COMMON.includes(id)).sort((a, b) => +a.slice(4) - +b.slice(4)).forEach(add);

const AV = { N: 'عبر الشبكة (Network)', A: 'من الشبكة المجاورة (Adjacent)', L: 'بوصول محلي (Local)', P: 'بوصول مادي (Physical)' };
const AUTH = { N: 'لا يتطلب تسجيل دخول (None)', L: 'حساب عادي (Low)', H: 'حساب ذو صلاحيات مرتفعة (High)' };
const STATE = { private: 'لم تُنشر في أي مكان', public: 'منشورة أو معروفة للعامة', exploited: 'رأيت دليلاً على استغلالها' };

function values() {
  const d = Object.fromEntries(new FormData(form).entries());
  d.cvd = form.cvd.checked; d.ethics = form.ethics.checked;
  return d;
}

function save() {
  try { localStorage.setItem(DRAFT, JSON.stringify(values())); } catch (e) { /* storage may be blocked */ }
}

function restore() {
  let d;
  try { d = JSON.parse(localStorage.getItem(DRAFT) || 'null'); } catch (e) { d = null; }
  if (!d) return;
  for (const [k, v] of Object.entries(d)) {
    const el = form.elements[k];
    if (!el) continue;
    if (el instanceof RadioNodeList) { for (const r of el) r.checked = r.value === v; }
    else if (el.type === 'checkbox') el.checked = !!v;
    else el.value = v;
  }
}

function build(d) {
  const line = (label, v) => (v ? `**${label}:** ${v}\n` : '');
  const cwe = d.cwe ? `${CWE_AR[d.cwe][0]} (${d.cwe})` : '';
  const who = d.credit === 'anon' ? 'دون ذكر الاسم (anonymous)' : d.name || 'لم يُكتب اسم';
  return `# ${d.title}

## الباحث (Reporter)
${line('الاسم', d.name)}${line('البريد', d.email)}${line('النسبة (Credit)', who)}
## المنتج (Product)
${line('المورّد (Vendor)', d.vendor)}${line('المنتج (Product)', d.product)}${line('الإصدارات المصابة (Affected)', d.versions)}${line('الإصدار المصلح (Fixed in)', d.fixed)}${line('الرابط', d.url)}
## الثغرة (Vulnerability)
${line('نوع الضعف (CWE)', cwe)}${line('مسار الهجوم (Attack vector)', AV[d.av])}${line('تسجيل الدخول (Privileges)', AUTH[d.auth])}${line('الحالة (Status)', STATE[d.state])}
### الوصف (Description)
${d.desc}

### خطوات إظهار الثغرة (Steps to reproduce)
${d.steps}

### الأثر (Impact)
${d.impact}
${d.poc ? `\n### إثبات المفهوم (Proof of concept)\n\`\`\`\n${d.poc}\n\`\`\`\n` : ''}
## الإفصاح المنسّق (Coordinated disclosure)
- يوافق الباحث على عدم النشر حتى يصدر الإصلاح أو تمضي تسعون يوماً من البلاغ أيهما أقرب (90 day coordinated disclosure).
- يؤكد الباحث أنه لم يطّلع على بيانات غيره إلا بالقدر اللازم ولم يحتفظ بها ولم يعطّل الخدمة.

_أُعدّ هذا البلاغ في بوابة رائد https://cve.3li.info/report/_
`;
}

function fillFields(d) {
  const rows = [
    ['المنتج (Package name)', d.product],
    ['الإصدارات المصابة (Affected versions)', d.versions],
    ['الإصدار المصلح (Patched versions)', d.fixed],
    ['نوع الضعف (CWE)', d.cwe],
  ].filter(([, v]) => v && String(v).trim());
  const dl = document.getElementById('gh-fields');
  dl.replaceChildren();
  for (const [k, v] of rows) {
    const wrap = document.createElement('div');
    const dt = document.createElement('dt'); dt.textContent = k;
    const dd = document.createElement('dd');
    const val = document.createElement('bdi'); val.dir = 'ltr'; val.textContent = v;
    const b = document.createElement('button'); b.type = 'button'; b.className = 'copy mini'; b.dataset.copy = 'value'; b.dataset.value = v; b.textContent = 'انسخ';
    b.addEventListener('click', () => copy(v, b, 'نُسخت القيمة، فالصقها في خانتها.'));
    dd.append(val, b); wrap.append(dt, dd); dl.append(wrap);
  }
  dl.hidden = !rows.length;
}

function check(d) {
  const missing = [];
  for (const el of form.querySelectorAll('[required]')) {
    const ok = el.type === 'checkbox' ? el.checked : String(el.value || '').trim();
    el.setAttribute('aria-invalid', ok ? 'false' : 'true');
    if (!ok) missing.push(el);
  }
  if (d.email && !form.email.checkValidity()) missing.push(form.email);
  return missing;
}

form.addEventListener('input', (e) => { if (e.target.getAttribute('aria-invalid') === 'true') e.target.setAttribute('aria-invalid', 'false'); save(); });
form.addEventListener('change', save);
form.addEventListener('submit', (e) => {
  e.preventDefault();
  const d = values();
  const missing = check(d);
  if (missing.length) {
    err.hidden = false;
    err.textContent = `بقيت ${missing.length === 1 ? 'خانة واحدة' : missing.length === 2 ? 'خانتان' : `${missing.length} خانات`} مطلوبة، فأكملها ثم جهّز البلاغ.`;
    missing[0].focus();
    return;
  }
  err.hidden = true;
  const text = build(d);
  preview.textContent = text;
  const subject = `بلاغ ثغرة: ${d.product} | ${d.title}`;
  const full = `mailto:${MAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(text)}`;
  const tooLong = full.length > 6000;
  document.getElementById('mail').href = tooLong ? `mailto:${MAIL}?subject=${encodeURIComponent(subject)}` : full;
  document.getElementById('mail-note').hidden = !tooLong;
  ready.hidden = false;
  ready.dataset.title = d.title;
  fillFields(d);
  ready.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  document.getElementById('ready-h').focus({ preventScroll: true });
});

// Copying starts inside the click itself, so browsers that guard the clipboard and pop-ups (Safari, iOS) allow it.
function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0'; ta.style.top = '0';
  document.body.append(ta); ta.select(); ta.setSelectionRange(0, text.length);
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  ta.remove();
  return ok;
}

function copy(text, btn, okMsg) {
  const done = (ok) => {
    copied.textContent = ok ? okMsg : 'تعذر النسخ التلقائي، فافتح «اعرض نص البلاغ» وانسخه بنفسك.';
    if (btn && ok) {
      const label = btn.dataset.label || btn.textContent;
      btn.dataset.label = label; btn.textContent = 'نُسخ'; btn.classList.add('done');
      setTimeout(() => { btn.textContent = label; btn.classList.remove('done'); }, 2200);
    }
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => done(true), () => done(fallbackCopy(text)));
  } else done(fallbackCopy(text));
}

const texts = () => ({ title: ready.dataset.title || '', body: preview.textContent });

// The link opens GitHub by itself, so no pop-up blocker stands in the way, and the report is copied in the same click.
document.getElementById('open-gh').addEventListener('click', () => {
  copy(texts().body, null, 'نُسخ البلاغ، فالصقه في خانة Description في صفحة GitHub التي فُتحت، ثم انسخ العنوان من الخطوة الثانية.');
});

for (const btn of document.querySelectorAll('.gh-steps .copy, .gh-fields .copy')) {
  btn.addEventListener('click', () => {
    const t = texts();
    const what = btn.dataset.copy;
    const text = what === 'title' ? t.title : what === 'body' ? t.body : btn.dataset.value;
    const msg = what === 'title' ? 'نُسخ العنوان، فالصقه في خانة Title.' : what === 'body' ? 'نُسخ البلاغ، فالصقه في خانة Description.' : 'نُسخت القيمة، فالصقها في خانتها.';
    copy(text, btn, msg);
  });
}

document.getElementById('download').addEventListener('click', () => {
  const blob = new Blob([preview.textContent], { type: 'text/markdown;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'raed-report.md';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

document.getElementById('clear').addEventListener('click', () => {
  form.reset();
  try { localStorage.removeItem(DRAFT); } catch (e) { /* ignore */ }
  ready.hidden = true;
  err.hidden = true;
});

restore();
