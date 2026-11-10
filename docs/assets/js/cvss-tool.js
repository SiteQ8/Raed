// CVSS 3.1 calculator. Everything happens in the browser.
import { METRICS, parse, complete, vector, score, severity } from '../engine/cvss.js';
import { SEV_AR, sevClass } from '../engine/arabic.js';
import { copyText, setParam } from './ui.js';

const $ = (id) => document.getElementById(id);
const DEF = [
  ['AV', 'مسار الهجوم', 'من أين يصل المهاجم إلى المكوّن المصاب؟', [['N', 'عبر الشبكة', 'من أي مكان على الإنترنت'], ['A', 'الشبكة المجاورة', 'من الشبكة المحلية نفسها أو مدى لاسلكي قريب'], ['L', 'محلي', 'بحساب على الجهاز أو ملف يفتحه المستخدم'], ['P', 'مادي', 'بلمس الجهاز نفسه']]],
  ['AC', 'تعقيد الهجوم', 'هل يحتاج الهجوم إلى ظروف خارجة عن تحكم المهاجم؟', [['L', 'منخفض', 'ينجح الهجوم كلما حاول المهاجم'], ['H', 'مرتفع', 'يحتاج إلى ظرف خاص مثل سباق توقيت أو إعداد غير معتاد']]],
  ['PR', 'الصلاحيات المطلوبة', 'ما الصلاحيات التي يحتاجها المهاجم قبل الهجوم؟', [['N', 'لا شيء', 'دون تسجيل دخول'], ['L', 'منخفضة', 'حساب مستخدم عادي'], ['H', 'مرتفعة', 'حساب مدير أو ما يقاربه']]],
  ['UI', 'تدخل المستخدم', 'هل يحتاج الهجوم إلى فعل من شخص غير المهاجم؟', [['N', 'غير مطلوب', 'ينجح الهجوم دون أن يفعل أحد شيئاً'], ['R', 'مطلوب', 'يجب أن يضغط الضحية رابطاً أو يفتح ملفاً مثلاً']]],
  ['S', 'النطاق', 'هل يتجاوز الأثر المكوّن المصاب إلى غيره؟', [['U', 'لا يتغير', 'يبقى الأثر داخل المكوّن المصاب'], ['C', 'يتغير', 'يصل الأثر إلى مكوّن آخر مثل النظام المضيف أو متصفح الزائر']]],
  ['C', 'الأثر في السرية', 'ما مقدار ما ينكشف من البيانات؟', [['H', 'مرتفع', 'تنكشف كل البيانات أو أهمها'], ['L', 'منخفض', 'ينكشف بعضها دون تحكم المهاجم في ما ينكشف'], ['N', 'لا أثر', 'لا ينكشف شيء']]],
  ['I', 'الأثر في السلامة', 'ما مقدار ما يستطيع المهاجم تعديله؟', [['H', 'مرتفع', 'يعدّل أي بيانات أو أهمها'], ['L', 'منخفض', 'يعدّل بعضها دون أثر جسيم'], ['N', 'لا أثر', 'لا يعدّل شيئاً']]],
  ['A', 'الأثر في التوافر', 'ما مقدار تعطّل الخدمة؟', [['H', 'مرتفع', 'تتوقف الخدمة كلياً أو يتكرر توقفها'], ['L', 'منخفض', 'تبطؤ الخدمة أو تتعطل جزئياً'], ['N', 'لا أثر', 'لا تتأثر الخدمة']]],
];
const COUNT = ['', 'بقي مقياس واحد', 'بقي مقياسان', 'بقيت ثلاثة مقاييس', 'بقيت أربعة مقاييس', 'بقيت خمسة مقاييس', 'بقيت ستة مقاييس', 'بقيت سبعة مقاييس', 'بقيت ثمانية مقاييس'];
const m = {};

$('metrics').innerHTML = DEF.map(([k, name, q, opts]) => `
<fieldset class="metric">
  <legend>${name} <bdi class="code">${k}</bdi></legend>
  <p class="help">${q}</p>
  <div class="seg" role="radiogroup" aria-label="${name}">
    ${opts.map(([v, label, hint]) => `<label><input type="radio" name="${k}" value="${v}"><span><b>${label}</b><small>${hint}</small></span></label>`).join('')}
  </div>
</fieldset>`).join('');

// One Arabic sentence that reads the vector the way an analyst would say it.
function explain() {
  const av = { N: 'عبر الشبكة', A: 'من الشبكة المجاورة', L: 'بوصول محلي إلى الجهاز', P: 'بوصول مادي إلى الجهاز' }[m.AV];
  const pr = { N: 'دون أي صلاحيات', L: 'بصلاحيات مستخدم عادي', H: 'بصلاحيات مرتفعة' }[m.PR];
  const ui = m.UI === 'N' ? 'ودون تدخل من أي مستخدم' : 'وتحتاج إلى فعل من مستخدم آخر';
  const ac = m.AC === 'L' ? 'ولا يتطلب استغلالها ظروفاً خاصة' : 'ويتطلب استغلالها ظروفاً خاصة يصعب توافرها';
  const lv = { H: 'مرتفعاً', L: 'منخفضاً' };
  const hit = [['C', 'سرية البيانات'], ['I', 'سلامتها'], ['A', 'توافر الخدمة']].filter(([k]) => m[k] !== 'N');
  const same = hit.length > 1 && hit.every(([k]) => m[k] === m[hit[0][0]]);
  let effect;
  if (!hit.length) effect = 'ولا أثر لها في السرية ولا السلامة ولا التوافر، لذا تكون درجتها صفراً';
  else if (same) effect = `ويكون أثرها ${lv[m[hit[0][0]]]} في ${hit.map((h) => h[1]).join(' و')}`;
  else effect = `ويكون أثرها ${hit.map(([k, n]) => `${lv[m[k]]} في ${n}`).join(' و')}`;
  const scope = m.S === 'C' ? '، ويتجاوز الأثر المكوّن المصاب إلى غيره' : '';
  return `ثغرة تُستغل ${av} ${pr} ${ui}، ${ac}، ${effect}${scope}.`;
}

function draw(fromUser = true) {
  const left = METRICS.filter((k) => !m[k]).length;
  const s = score(m);
  const sev = severity(s);
  $('score').textContent = s == null ? '0.0' : s.toFixed(1);
  $('sev').className = `sev ${s == null ? 'na' : sevClass(sev)}`;
  $('sev').textContent = s == null ? 'اختر القيم' : sev === 'NONE' ? 'بلا أثر' : SEV_AR[sev];
  $('bar').style.width = `${(s || 0) * 10}%`;
  $('score-box').className = `score ${s == null ? 'na' : sevClass(sev)}`;
  $('bar').parentElement.className = `meter score ${s == null ? 'na' : sevClass(sev)}`;
  $('left').textContent = left ? `${COUNT[left]}.` : '';
  $('left').hidden = !left;
  const v = left ? '' : vector(m);
  $('vec').innerHTML = v.split('/').join('/<wbr>');
  $('copy-vec').disabled = $('copy-link').disabled = !v;
  $('explain-box').hidden = !v;
  if (v) $('explain').textContent = explain();
  if (fromUser) { setParam('v', v); if (v) $('vec-in').value = v; }
}

function load(text, quiet) {
  const r = parse(text);
  const msg = $('vec-msg');
  if (r.error) { if (!quiet) msg.textContent = r.error === 'version' ? 'الحاسبة تحسب الإصدارين 3.1 و3.0 فقط، وهذا المتجه من إصدار آخر.' : 'لم نتعرف على هذا المتجه، فتأكد من نسخه كاملاً كما في المثال.'; return false; }
  for (const k of METRICS) delete m[k];
  Object.assign(m, r.m);
  for (const el of document.querySelectorAll('#metrics input')) el.checked = m[el.name] === el.value;
  msg.textContent = complete(m) ? (r.version === '3.0' ? 'متجه من الإصدار 3.0، ومعادلته هي معادلة 3.1 نفسها.' : '') : 'المتجه ناقص، فأكمل المقاييس الباقية.';
  draw();
  return true;
}

$('metrics').addEventListener('change', (e) => { if (e.target.name) { m[e.target.name] = e.target.value; $('vec-msg').textContent = ''; draw(); } });
$('vec-in').addEventListener('input', () => { const t = $('vec-in').value.trim(); if (!t) { $('vec-msg').textContent = ''; return; } if (t.length > 12) load(t); });
$('calc').addEventListener('submit', (e) => { e.preventDefault(); const t = $('vec-in').value.trim(); if (t) load(t); });
$('vec-in').addEventListener('change', () => { const t = $('vec-in').value.trim(); if (t) load(t); });
$('reset').addEventListener('click', () => {
  for (const k of METRICS) delete m[k];
  for (const el of document.querySelectorAll('#metrics input')) el.checked = false;
  $('vec-in').value = ''; $('vec-msg').textContent = ''; $('done').textContent = '';
  draw();
});
const flash = (ok, text) => { $('done').textContent = ok ? text : 'تعذر النسخ التلقائي، فحدّد النص وانسخه بنفسك.'; };
$('copy-vec').addEventListener('click', () => copyText(vector(m)).then((ok) => flash(ok, 'نُسخ المتجه.')));
$('copy-link').addEventListener('click', () => copyText(location.href).then((ok) => flash(ok, 'نُسخ الرابط، ومن يفتحه يرى النتيجة نفسها.')));

const start = new URLSearchParams(location.search).get('v');
if (!start || !load(start, true)) draw(false);
else $('vec-in').value = start;
