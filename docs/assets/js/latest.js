import { rowHtml, getJSON, norm, setParam, esc } from './ui.js';
import { dateAr, nVuln } from '../engine/arabic.js';

const PAGE = 50;
const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const state = { day: params.get('day') || '', q: params.get('q') || '', sev: new Set((params.get('sev') || '').split(',').filter(Boolean)), kev: params.get('kev') === '1', shown: PAGE };
const dayCache = new Map();
let index, search, list = [];

async function day(d) {
  if (!dayCache.has(d)) dayCache.set(d, getJSON(`/data/days/${d}.json`).catch(() => []));
  return dayCache.get(d);
}

function drawDays() {
  $('days').innerHTML = index.days.map((d) => `<button type="button" data-day="${d.d}" aria-pressed="${!state.q && d.d === state.day}"><b class="num">${d.n.toLocaleString('en-US')}</b>${dateAr(d.d, { year: false })}</button>`).join('');
}

function pass(it) {
  if (it.st) return false;
  if (state.sev.size && !state.sev.has(it.sv)) return false;
  if (state.kev && !it.k) return false;
  return true;
}

async function compute() {
  if (state.q) {
    const words = norm(state.q).split(' ').filter(Boolean);
    const hits = search.filter((row) => {
      const hay = norm(`${row[0]} ${row[1]} ${row[2]} ${row[3]}`);
      return words.every((w) => hay.includes(w));
    }).filter((row) => (!state.sev.size || state.sev.has(row[4])) && (!state.kev || row[7]));
    list = hits.map((row) => ({ ref: row }));
  } else {
    const items = await day(state.day);
    list = items.filter(pass).map((it) => ({ it }));
  }
}

async function materialise(slice) {
  // Search rows carry only a few fields, so the full record comes from its day file.
  const need = [...new Set(slice.filter((x) => !x.it).map((x) => x.ref[6]))];
  await Promise.all(need.map(day));
  for (const x of slice) {
    if (x.it) continue;
    const items = await day(x.ref[6]);
    x.it = items.find((it) => it.i === x.ref[0]) || { i: x.ref[0], p: x.ref[6], v: x.ref[1], r: x.ref[2], sv: x.ref[4] || undefined, s: x.ref[5] === '' ? undefined : x.ref[5], k: x.ref[7] || undefined };
  }
}

async function draw() {
  await compute();
  const slice = list.slice(0, state.shown);
  await materialise(slice);
  $('list').innerHTML = slice.map((x) => rowHtml(x.it)).join('');
  const where = state.q ? `تطابق «${esc(state.q)}» في آخر ثلاثين يوماً` : `نُشرت ${dateAr(state.day, { weekday: true })}`;
  $('count').innerHTML = list.length ? `${nVuln(list.length)} ${where}` : `لا توجد ثغرات ${where} بهذه التصفية، فجرّب إزالة بعض الشروط أو اختيار يوم آخر.`;
  $('more').hidden = list.length <= state.shown;
  drawDays();
}

async function main() {
  index = await getJSON('/data/index.json');
  if (!state.day || !index.days.some((d) => d.d === state.day)) state.day = index.days[0].d;
  const q = $('q');
  q.value = state.q;
  for (const c of document.querySelectorAll('.chip')) {
    if (c.dataset.sev) c.setAttribute('aria-pressed', String(state.sev.has(c.dataset.sev)));
    if (c.dataset.kev) c.setAttribute('aria-pressed', String(state.kev));
    c.addEventListener('click', () => {
      if (c.dataset.sev) { state.sev.has(c.dataset.sev) ? state.sev.delete(c.dataset.sev) : state.sev.add(c.dataset.sev); c.setAttribute('aria-pressed', String(state.sev.has(c.dataset.sev))); setParam('sev', [...state.sev].join(',')); }
      else { state.kev = !state.kev; c.setAttribute('aria-pressed', String(state.kev)); setParam('kev', state.kev ? '1' : ''); }
      state.shown = PAGE; draw();
    });
  }
  let t;
  q.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      state.q = q.value.trim(); state.shown = PAGE; setParam('q', state.q);
      if (state.q && !search) search = await getJSON('/data/search.json');
      draw();
    }, 220);
  });
  $('days').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-day]');
    if (!b) return;
    state.day = b.dataset.day; state.q = ''; q.value = ''; state.shown = PAGE;
    setParam('q', ''); setParam('day', state.day); draw();
  });
  $('more').addEventListener('click', () => { state.shown += PAGE; draw(); });
  if (state.q) search = await getJSON('/data/search.json');
  await draw();
  document.querySelector('#days [aria-pressed="true"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}

main().catch(() => { $('count').textContent = 'تعذر تحميل السجلات، فأعد تحميل الصفحة بعد قليل.'; });
