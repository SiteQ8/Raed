// Watch list: the reader's own products and vendors matched against the last thirty days. Nothing leaves the browser.
import { rowHtml, getJSON, norm, esc, fullItems, downloadCsv, CSV_HEAD, csvRow, copyText, watchTerms, saveWatch } from './ui.js';
import { nVuln } from '../engine/arabic.js';

const PAGE = 30;
const SEEN = 'raed-watch-seen';
const $ = (id) => document.getElementById(id);
const state = { hi: false, kev: false, new: false, shown: PAGE };
let terms = watchTerms();
let search = [], hits = [], prevSeen = '';

const hay = (row) => norm(`${row[1]} ${row[2]}`);
const matches = (term) => { const w = norm(term).split(' ').filter(Boolean); return (row) => { const h = row._h || (row._h = hay(row)); return w.every((x) => h.includes(x)); }; };

function compute() {
  const tests = terms.map(matches);
  hits = search.filter((row) => tests.some((t) => t(row)))
    .filter((row) => (!state.hi || row[4] === 'CRITICAL' || row[4] === 'HIGH') && (!state.kev || row[7]) && (!state.new || (prevSeen && row[6] >= prevSeen)));
}

function drawTerms() {
  $('terms').innerHTML = terms.map((t, i) => {
    const n = search.filter(matches(t)).length;
    return `<li><bdi>${esc(t)}</bdi><span class="num">${n.toLocaleString('en-US')}</span><button type="button" data-i="${i}" aria-label="احذف ${esc(t)} من القائمة">×</button></li>`;
  }).join('');
}

async function draw() {
  drawTerms();
  const has = terms.length > 0;
  $('empty').hidden = has; $('tools-bar').hidden = !has;
  if (!has) { $('list').innerHTML = ''; $('count').textContent = ''; $('more').hidden = true; return; }
  compute();
  const items = await fullItems(hits.slice(0, state.shown));
  $('list').innerHTML = items.map(rowHtml).join('');
  const filtered = state.hi || state.kev || state.new;
  $('count').textContent = hits.length
    ? `${nVuln(hits.length)} في آخر ثلاثين يوماً لما تتابعه${filtered ? ' بهذه التصفية' : ''}`
    : filtered ? 'لا توجد ثغرات بهذه التصفية، فجرّب إزالة بعض الشروط.' : 'لم تُنشر ثغرات لما تتابعه في آخر ثلاثين يوماً، وتأكد من كتابة الاسم كما يكتبه المورّد بالإنجليزية.';
  $('more').hidden = hits.length <= state.shown;
}

function add(raw) {
  const t = String(raw || '').replace(/\s+/g, ' ').trim().slice(0, 60);
  if (t.length < 2) return 'اكتب حرفين على الأقل.';
  if (terms.some((x) => norm(x) === norm(t))) return 'هذا الاسم في قائمتك من قبل.';
  if (terms.length >= 60) return 'بلغت القائمة حدها وهو ستون اسماً، فاحذف منها ما لا تحتاجه.';
  terms.push(t);
  if (!saveWatch(terms)) return 'أُضيف الاسم لهذه الزيارة فقط، لأن متصفحك يمنع الحفظ.';
  return '';
}

async function main() {
  try { prevSeen = localStorage.getItem(SEEN) || ''; localStorage.setItem(SEEN, new Date().toISOString().slice(0, 10)); } catch (e) { prevSeen = ''; }
  document.querySelector('[data-f="new"]').hidden = !prevSeen;
  search = await getJSON('/data/search.json');

  // A shared link carries names in ?t=, joined into the reader's own list.
  const shared = (new URLSearchParams(location.search).get('t') || '').split('|').map((x) => x.trim()).filter(Boolean).slice(0, 60);
  let note = '';
  if (shared.length) {
    const before = terms.length;
    for (const t of shared) add(t);
    const n = terms.length - before;
    if (n) note = n === 1 ? 'أُضيف اسم واحد من الرابط إلى قائمتك.' : n === 2 ? 'أُضيف اسمان من الرابط إلى قائمتك.' : `أُضيفت ${n} ${n <= 10 ? 'أسماء' : 'اسماً'} من الرابط إلى قائمتك.`;
    history.replaceState(null, '', location.pathname);
  }

  const count = new Map();
  for (const row of search) { const v = row[1]; if (v && !/^n\/a$/i.test(v)) count.set(v, (count.get(v) || 0) + 1); }
  const top = [...count].sort((a, b) => b[1] - a[1]);
  $('suggest').innerHTML = top.slice(0, 250).map(([v]) => `<option value="${esc(v)}">`).join('');
  $('starters').innerHTML = top.slice(0, 8).map(([v]) => `<button class="chip" type="button" data-add="${esc(v)}"><bdi>${esc(v)}</bdi></button>`).join('');

  $('add').addEventListener('submit', (e) => {
    e.preventDefault();
    const msg = add($('term').value);
    if (!msg || msg.startsWith('أُضيف')) { $('term').value = ''; state.shown = PAGE; }
    draw().then(() => { if (msg) $('count').textContent = msg; });
  });
  $('starters').addEventListener('click', (e) => { const b = e.target.closest('[data-add]'); if (b) { add(b.dataset.add); draw(); } });
  $('terms').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-i]');
    if (!b) return;
    terms.splice(Number(b.dataset.i), 1); saveWatch(terms); state.shown = PAGE; draw();
    $('term').focus();
  });
  for (const c of document.querySelectorAll('#tools-bar .chip')) {
    c.addEventListener('click', () => { state[c.dataset.f] = !state[c.dataset.f]; c.setAttribute('aria-pressed', String(state[c.dataset.f])); state.shown = PAGE; draw(); });
  }
  $('more').addEventListener('click', () => { state.shown += PAGE; draw(); });
  $('csv').addEventListener('click', () => downloadCsv('raed-watch.csv', CSV_HEAD, hits.map((r) => csvRow(r[0], r[1], r[2], r[4], r[5], r[6], r[7]))));
  $('share').addEventListener('click', () => {
    const url = `${location.origin}/watch/?t=${encodeURIComponent(terms.join('|'))}`;
    copyText(url).then((ok) => { $('count').textContent = ok ? 'نُسخ رابط قائمتك، ومن يفتحه تُضاف الأسماء إلى قائمته.' : 'تعذر النسخ التلقائي.'; });
  });
  await draw();
  if (note) $('count').textContent = note;
}

main().catch(() => { $('count').textContent = 'تعذر تحميل السجلات، فأعد تحميل الصفحة بعد قليل.'; });
