// Shared rendering for the browser pages. Mirrors scripts/build.mjs so server and client rows match.
import { summaryAr, dateAr, SEV_AR, sevClass } from '../engine/arabic.js';

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const html = (s) => esc(s).replace(/⁨/g, '<bdi>').replace(/⁩/g, '</bdi>');

export function sevMark(sv, s) {
  if (!sv) return '<span class="sev na">بلا تقييم</span>';
  return `<span class="sev ${sevClass(sv)}">${SEV_AR[sv]}${s != null && s !== '' ? ` <span class="num">${Number(s).toFixed(1)}</span>` : ''}</span>`;
}

export function rowHtml(it) {
  const prod = it.r || it.v ? `<span class="prod"><bdi>${esc(it.r || it.v)}</bdi>${it.r && it.v && it.v !== it.r ? ` <small><bdi>${esc(it.v)}</bdi></small>` : ''}</span>` : '';
  return `<li><a class="row" href="/record/?id=${esc(it.i)}">
<span class="id"><b dir="ltr">${esc(it.i)}</b><small>${dateAr(it.p, { year: false })}</small></span>
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
