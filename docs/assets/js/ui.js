// Shared rendering for the browser pages. Mirrors scripts/build.mjs so server and client rows match.
import { summaryAr, dateAr, SEV_AR, sevClass } from '../engine/arabic.js';

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const html = (s) => esc(s).replace(/⁨/g, '<bdi>').replace(/⁩/g, '</bdi>');

export const idHtml = (id) => { const m = /^(CVE-\d{4}-)(\d+)$/.exec(id); return m ? `<span class="pre">${m[1]}</span>${m[2]}` : esc(id); };

export function sevMark(sv, s) {
  if (!sv) return '<span class="sev na">بلا تقييم</span>';
  return `<span class="sev ${sevClass(sv)}">${SEV_AR[sv]}${s != null && s !== '' ? ` <span class="num">${Number(s).toFixed(1)}</span>` : ''}</span>`;
}

export function rowHtml(it) {
  const prod = it.r || it.v ? `<span class="prod"><bdi>${esc(it.r || it.v)}</bdi>${it.r && it.v && it.v !== it.r ? ` <small><bdi>${esc(it.v)}</bdi></small>` : ''}</span>` : '';
  return `<li><a class="row" href="/record/?id=${esc(it.i)}">
<span class="id"><b dir="ltr">${idHtml(it.i)}</b><small>${dateAr(it.p, { year: false })}</small></span>
<span class="what">${prod}<p>${html(summaryAr(it))}</p></span>
<span class="marks">${sevMark(it.sv, it.s)}${it.k ? '<span class="kev">مستغلة فعلياً</span>' : ''}</span>
</a></li>`;
}

export async function getJSON(url) {
  const r = await fetch(url, { cache: 'no-cache' });
  if (!r.ok) throw new Error(String(r.status));
  return r.json();
}

export const CVE_RE = /^\s*CVE-\d{4}-\d{4,}\s*$/i;

// Normalises Arabic and Latin text for matching: lower case, no diacritics, unified alef and ya.
export function norm(s) {
  return String(s || '').toLowerCase().normalize('NFKD').replace(/[ً-ٰٟ]/g, '').replace(/[أإآ]/g, 'ا').replace(/ى/g, 'ي').replace(/\s+/g, ' ').trim();
}

export function setParam(key, val) {
  const u = new URL(location.href);
  if (val) u.searchParams.set(key, val); else u.searchParams.delete(key);
  history.replaceState(null, '', u);
}

// Search rows carry only a few fields, so full records come from their day files.
const dayFiles = new Map();
export function dayItems(d) {
  if (!dayFiles.has(d)) dayFiles.set(d, getJSON(`/data/days/${d}.json`).catch(() => []));
  return dayFiles.get(d);
}
export async function fullItems(rows) {
  await Promise.all([...new Set(rows.map((r) => r[6]))].map(dayItems));
  const out = [];
  for (const r of rows) {
    const items = await dayItems(r[6]);
    out.push(items.find((it) => it.i === r[0]) || { i: r[0], p: r[6], v: r[1], r: r[2], sv: r[4] || undefined, s: r[5] === '' ? undefined : r[5], k: r[7] || undefined });
  }
  return out;
}

// CSV with a byte order mark and CRLF so Excel opens Arabic text correctly.
export function downloadCsv(name, header, rows) {
  const cell = (v) => { const s = String(v ?? ''); return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const text = '﻿' + [header, ...rows].map((r) => r.map(cell).join(',')).join('\r\n') + '\r\n';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 30000);
}
export const CSV_HEAD = ['رقم الثغرة', 'المورّد', 'المنتج', 'الخطورة', 'الدرجة', 'تاريخ النشر', 'مستغلة فعلياً', 'الرابط'];
export const csvRow = (i, v, r, sv, s, p, k) => [i, v || '', r || '', SEV_AR[sv] || 'بلا تقييم', s ?? '', String(p || '').slice(0, 10), k ? 'نعم' : 'لا', `https://cve.3li.info/record/?id=${i}`];

// Copies inside the click itself so Safari allows it; resolves to true when the text reached the clipboard.
export function copyText(text) {
  const legacy = () => {
    const back = document.activeElement;
    const ta = document.createElement('textarea');
    ta.value = text; ta.contentEditable = 'true'; ta.readOnly = false;
    Object.assign(ta.style, { position: 'fixed', top: '0', left: '0', opacity: '0', fontSize: '16px', width: '1px', height: '1px' });
    document.body.append(ta); ta.focus({ preventScroll: true }); ta.select(); ta.setSelectionRange(0, text.length);
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    if (back && back.focus) back.focus({ preventScroll: true });
    return ok;
  };
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(() => true, () => legacy());
  return Promise.resolve(legacy());
}

// Watch list: product and vendor names kept in this browser only.
const WATCH = 'raed-watch';
export function watchTerms() {
  try { const v = JSON.parse(localStorage.getItem(WATCH) || '[]'); return Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).slice(0, 60) : []; } catch (e) { return []; }
}
export function saveWatch(terms) {
  try { localStorage.setItem(WATCH, JSON.stringify(terms)); return true; } catch (e) { return false; }
}
