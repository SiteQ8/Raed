// Arabic writing for CVE records: severity, CVSS, SSVC, EPSS, dates, counts and the record summary.
// Every sentence is composed from the record's structured fields, never machine translated,
// and ends with a single period: clauses are joined with conjunctions, never with a mid sentence period.

import { cweAr } from './cwe.js';

const FSI = '⁨';
const PDI = '⁩';
export const iso = (s) => (s ? FSI + String(s) + PDI : '');

export const SEV_AR = {
  CRITICAL: 'حرجة',
  HIGH: 'عالية',
  MEDIUM: 'متوسطة',
  LOW: 'منخفضة',
  NONE: 'معدومة',
};

export const MONTHS = ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو', 'يوليو', 'أغسطس', 'سبتمبر', 'أكتوبر', 'نوفمبر', 'ديسمبر'];
export const DAYS_AR = ['الأحد', 'الاثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة', 'السبت'];

// The site speaks Kuwait time (UTC+3, no daylight saving). Timestamps are stored in UTC and shifted when shown;
// a bare date (YYYY-MM-DD) is already a Kuwait calendar day and is shown as is.
export const KW_OFFSET_MS = 3 * 3600 * 1000;
export function kwDate(s) {
  return new Date(new Date(String(s).replace(/Z?$/, 'Z')).getTime() + KW_OFFSET_MS);
}
export function kwDay(s) {
  return kwDate(s).toISOString().slice(0, 10);
}

export function dateAr(s, { weekday = false, year = true } = {}) {
  if (!s) return '';
  const d = String(s).length <= 10 ? new Date(s + 'T00:00:00Z') : kwDate(s);
  if (isNaN(d)) return '';
  const core = `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}${year ? ' ' + d.getUTCFullYear() : ''}`;
  return weekday ? `${DAYS_AR[d.getUTCDay()]} ${core}` : core;
}

export function timeAr(s) {
  if (!s) return '';
  const d = kwDate(s);
  const h = d.getUTCHours();
  const m = String(d.getUTCMinutes()).padStart(2, '0');
  return `${String(h).padStart(2, '0')}:${m} بتوقيت الكويت`;
}

// Counted nouns with digits: 1 and 2 take the word alone, 3 to 10 the genitive plural,
// 11 to 99 the singular accusative and 100 and above (with a last part of 0, 1 or 2) the singular genitive.
// forms: { one, two, plural, acc, gen, zero }, where one and two are full phrases such as «ثغرة واحدة».
export function countAr(n, forms) {
  const num = Number(n);
  if (num === 0 && forms.zero) return forms.zero;
  if (num === 1 && forms.one) return forms.one;
  if (num === 2 && forms.two) return forms.two;
  const mod = num % 100;
  const word = mod >= 3 && mod <= 10 ? forms.plural : mod >= 11 ? forms.acc : forms.gen;
  return `${num.toLocaleString('en-US')} ${word}`;
}
export function nVuln(n) {
  return countAr(n, { zero: 'لا ثغرات', one: 'ثغرة واحدة', two: 'ثغرتان', plural: 'ثغرات', acc: 'ثغرة', gen: 'ثغرة' });
}
export function nRecord(n) {
  return countAr(n, { zero: 'لا سجلات', one: 'سجل واحد', two: 'سجلان', plural: 'سجلات', acc: 'سجلاً', gen: 'سجل' });
}

// ---------- CVSS ----------

export function parseVector(vec) {
  const out = {};
  if (!vec) return out;
  for (const part of String(vec).split('/')) {
    const [k, v] = part.split(':');
    if (k && v && k !== 'CVSS') out[k] = v;
  }
  return out;
}

const AV = { N: 'عبر الشبكة', A: 'من الشبكة المجاورة', L: 'بوصول محلي إلى الجهاز', P: 'بوصول مادي إلى الجهاز' };
const PR = { N: 'دون أي صلاحيات', L: 'بصلاحيات مستخدم عادي', H: 'بصلاحيات مرتفعة' };
const UI = { N: 'دون تدخل من المستخدم', R: 'بتدخل من المستخدم', P: 'بتدخل من المستخدم', A: 'بتدخل نشط من المستخدم' };
const AC = { L: 'لا تتطلب ظروفاً خاصة', H: 'تتطلب ظروفاً خاصة يصعب توافرها' };

export function vectorAr(vec) {
  const m = parseVector(vec);
  const rows = [];
  if (m.AV) rows.push(['مسار الهجوم', AV[m.AV] || m.AV]);
  if (m.AC) rows.push(['تعقيد الهجوم', m.AC === 'L' ? 'منخفض' : 'مرتفع']);
  if (m.AT) rows.push(['متطلبات الهجوم', m.AT === 'N' ? 'لا شيء' : 'وجود شروط مسبقة']);
  if (m.PR) rows.push(['الصلاحيات المطلوبة', { N: 'لا شيء', L: 'منخفضة', H: 'مرتفعة' }[m.PR] || m.PR]);
  if (m.UI) rows.push(['تدخل المستخدم', { N: 'غير مطلوب', R: 'مطلوب', P: 'مطلوب بشكل سلبي', A: 'مطلوب بشكل نشط' }[m.UI] || m.UI]);
  if (m.S) rows.push(['النطاق', m.S === 'C' ? 'يتجاوز المكوّن المصاب' : 'يقتصر على المكوّن المصاب']);
  const lvl = (v) => ({ H: 'مرتفع', L: 'منخفض', N: 'لا أثر' }[v] || v);
  if (m.C) rows.push(['الأثر في السرية', lvl(m.C)]);
  if (m.I) rows.push(['الأثر في السلامة', lvl(m.I)]);
  if (m.A) rows.push(['الأثر في التوافر', lvl(m.A)]);
  if (m.VC) rows.push(['الأثر في سرية النظام المصاب', lvl(m.VC)]);
  if (m.VI) rows.push(['الأثر في سلامة النظام المصاب', lvl(m.VI)]);
  if (m.VA) rows.push(['الأثر في توافر النظام المصاب', lvl(m.VA)]);
  if (m.SC) rows.push(['الأثر في سرية الأنظمة اللاحقة', lvl(m.SC)]);
  if (m.SI) rows.push(['الأثر في سلامة الأنظمة اللاحقة', lvl(m.SI)]);
  if (m.SA) rows.push(['الأثر في توافر الأنظمة اللاحقة', lvl(m.SA)]);
  return rows;
}

function impacts(m) {
  const c = m.C || m.VC;
  const i = m.I || m.VI;
  const a = m.A || m.VA;
  const parts = [];
  if (c === 'H') parts.push('سرية البيانات');
  if (i === 'H') parts.push(c === 'H' ? 'سلامتها' : 'سلامة البيانات');
  if (a === 'H') parts.push('توافر الخدمة');
  if (!parts.length) {
    if (c === 'L') parts.push('سرية البيانات');
    if (i === 'L') parts.push(c === 'L' ? 'سلامتها' : 'سلامة البيانات');
    if (a === 'L') parts.push('توافر الخدمة');
    if (parts.length) return { soft: true, list: parts };
  }
  return { soft: false, list: parts };
}

function joinAnd(list) {
  if (list.length <= 1) return list.join('');
  return list.slice(0, -1).join(' و') + ' و' + list[list.length - 1];
}

// ---------- SSVC and EPSS ----------

export const SSVC_X = { none: 'لا دليل على استغلالها', poc: 'نُشر إثبات مفهوم لاستغلالها', active: 'تُستغل فعلياً' };
export const SSVC_A = { yes: 'يمكن أتمتة استغلالها', no: 'لا يمكن أتمتة استغلالها بسهولة' };
export const SSVC_T = { partial: 'تمنح المهاجم سيطرة جزئية', total: 'تمنح المهاجم سيطرة كاملة على المكوّن' };

export function epssAr(e, ep) {
  if (e == null) return '';
  const pct = e * 100;
  const shown = pct < 0.1 ? 'أقل من 0.1' : pct < 10 ? pct.toFixed(1) : Math.round(pct).toString();
  let tail = '';
  if (ep != null) {
    const top = (1 - ep) * 100;
    if (top <= 1) tail = ` وهي ضمن أعلى ${iso('1%')} من جميع الثغرات`;
    else if (top <= 10) tail = ` وهي ضمن أعلى ${iso(Math.ceil(top) + '%')} من جميع الثغرات`;
  }
  return `يبلغ احتمال استغلالها خلال الثلاثين يوماً المقبلة ${iso(shown + '%')}${tail}`;
}

// ---------- Summary ----------

function productPhrase(it) {
  const v = it.v;
  const r = it.r;
  if (r && v && r.toLowerCase().startsWith(v.toLowerCase())) return `في ${iso(r)}`;
  if (r && v) return `في ${iso(r)} من ${iso(v)}`;
  if (r) return `في ${iso(r)}`;
  if (v) return `في منتج من ${iso(v)}`;
  return '';
}

export function summaryAr(it) {
  if (it.st === 'REJECTED') return 'رُفض هذا المعرّف ولم يعد يمثل ثغرة، لذا لا ينبغي الاستناد إليه.';
  if (it.st === 'RESERVED') return 'هذا المعرّف محجوز ولم تُنشر تفاصيله بعد.';
  const cw = (it.c || []).map(cweAr).find(Boolean);
  const kind = cw ? `ثغرة من نوع ${cw.name}` : 'ثغرة';
  const where = productPhrase(it);
  if (!cw && !where && !it.vec) {
    // Older records often carry only free text, so say so plainly instead of inventing detail.
    let t = 'ثغرة لم تذكر الجهة المرقّمة نوعها ولا منتجها في حقول السجل المنظمة، لذا فالوصف الأصلي هو المرجع لتفاصيلها';
    t += it.s != null && it.sv ? `، ويقدّر التقييم خطورتها بـ ${iso(Number(it.s).toFixed(1))} من 10 أي ${SEV_AR[it.sv] || ''}` : '، ولم يُنشر تقييم لخطورتها في السجل';
    if (it.k) t += '، وقد أدرجتها CISA في قائمة الثغرات المستغلة فعلياً';
    return t + '.';
  }
  let s = [kind, where].filter(Boolean).join(' ');
  const m = parseVector(it.vec);
  const how = [];
  if (m.AV) how.push(AV[m.AV]);
  if (m.PR) how.push(PR[m.PR]);
  if (m.UI) how.push(UI[m.UI]);
  const imp = impacts(m);
  if (how.length) {
    s += `، ويمكن استغلالها ${how.length > 1 ? how.slice(0, -1).join(' و') + ' و' + how[how.length - 1] : how[0]}`;
    if (imp.list.length) s += imp.soft ? ` للمساس جزئياً ب${joinAnd(imp.list)}` : ` للمساس ب${joinAnd(imp.list)}`;
  } else if (imp.list.length) {
    s += `، وتمس ${joinAnd(imp.list)}`;
  }
  if (it.s != null && it.sv) {
    s += `، ويقدّر التقييم خطورتها بـ ${iso(Number(it.s).toFixed(1))} من 10 أي ${SEV_AR[it.sv] || ''}`;
  } else {
    s += '، ولم تنشر الجهة المرقّمة تقييماً لخطورتها بعد';
  }
  if (it.k) s += `، وقد أدرجتها CISA في قائمة الثغرات المستغلة فعلياً`;
  else if (it.x?.x === 'active') s += '، وثمة دليل على استغلالها فعلياً';
  return s + '.';
}

export function sevClass(sv) {
  return { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', NONE: 'none' }[sv] || 'na';
}

// Version ranges for one affected entry, in Arabic.
export function versionsAr(a) {
  const out = [];
  const na = (x) => !x || /^(n\/a|unspecified|unknown)$/i.test(String(x).trim());
  for (const v of a.versions || []) {
    if (na(v.version) && na(v.lessThan) && na(v.lessThanOrEqual)) continue;
    const st = v.status === 'affected' ? 'مصاب' : v.status === 'unaffected' ? 'غير مصاب' : 'غير معروف';
    let range;
    if (v.lessThan) range = v.version && v.version !== '0' && v.version !== '*' ? `من ${iso(v.version)} حتى ما قبل ${iso(v.lessThan)}` : `كل الإصدارات قبل ${iso(v.lessThan)}`;
    else if (v.lessThanOrEqual) range = v.version && v.version !== '0' && v.version !== '*' ? `من ${iso(v.version)} حتى ${iso(v.lessThanOrEqual)} ضمناً` : `كل الإصدارات حتى ${iso(v.lessThanOrEqual)} ضمناً`;
    else range = v.version === '*' || v.version === 'all' ? 'كل الإصدارات' : `الإصدار ${iso(v.version)}`;
    out.push({ status: v.status, st, range });
  }
  return out;
}
