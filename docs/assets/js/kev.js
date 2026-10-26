import { getJSON, esc, html, norm, setParam } from './ui.js';
import { dateAr, nVuln, iso } from '../engine/arabic.js';
import { cweAr } from '../engine/cwe.js';

const $ = (id) => document.getElementById(id);
const PAGE = 60;
const params = new URLSearchParams(location.search);
const state = { q: params.get('q') || '', ra: params.get('ra') === '1', y: params.get('y') === '1', shown: PAGE };
let all = [];

function row(k) {
  const cw = (k.c || []).map(cweAr).find(Boolean);
  const line = `${cw ? `ثغرة من نوع ${cw.name}` : 'ثغرة'} في ${iso(k.r)} من ${iso(k.v)}، أدرجتها CISA في ${dateAr(k.da)} وحددت لمعالجتها موعداً أقصاه ${dateAr(k.due)}${k.ra ? '، وتستخدمها حملات فدية' : ''}.`;
  return `<li><a class="row" href="/record/?id=${esc(k.i)}">
<span class="id"><b dir="ltr">${esc(k.i)}</b><small>${dateAr(k.da, { year: true })}</small></span>
<span class="what"><span class="prod"><bdi>${esc(k.r || k.v)}</bdi>${k.r && k.v && k.v !== k.r ? ` <small><bdi>${esc(k.v)}</bdi></small>` : ''}</span><p>${html(line)}<span class="en" dir="ltr">${esc(k.n)}</span></p></span>
<span class="marks"><span class="kev">مستغلة فعلياً</span>${k.ra ? '<span class="sev crit">فدية</span>' : ''}</span>
</a></li>`;
}

function draw() {
  const words = norm(state.q).split(' ').filter(Boolean);
  const year = String(new Date().getUTCFullYear());
  const list = all.filter((k) => {
    if (state.ra && !k.ra) return false;
    if (state.y && !k.da.startsWith(year)) return false;
    if (!words.length) return true;
    const hay = norm(`${k.i} ${k.v} ${k.r} ${k.n}`);
    return words.every((w) => hay.includes(w));
  });
  $('list').innerHTML = list.slice(0, state.shown).map(row).join('');
  $('count').textContent = list.length ? `${nVuln(list.length)} من أصل ${all.length.toLocaleString('en-US')}، مرتبة من الأحدث إدراجاً` : 'لا توجد ثغرات بهذه التصفية.';
  $('more').hidden = list.length <= state.shown;
}

async function main() {
  all = await getJSON('/data/kev.json');
  const q = $('q');
  q.value = state.q;
  let t;
  q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { state.q = q.value.trim(); state.shown = PAGE; setParam('q', state.q); draw(); }, 180); });
  for (const c of document.querySelectorAll('.chip')) {
    c.setAttribute('aria-pressed', String(state[c.dataset.f]));
    c.addEventListener('click', () => { state[c.dataset.f] = !state[c.dataset.f]; c.setAttribute('aria-pressed', String(state[c.dataset.f])); setParam(c.dataset.f, state[c.dataset.f] ? '1' : ''); state.shown = PAGE; draw(); });
  }
  $('more').addEventListener('click', () => { state.shown += PAGE; draw(); });
  draw();
}

main().catch(() => { $('count').textContent = 'تعذر تحميل القائمة، فأعد تحميل الصفحة بعد قليل.'; });
