import { norm } from './ui.js';

const input = document.getElementById('gq');
const terms = [...document.querySelectorAll('.term')];
const groups = [...document.querySelectorAll('.gloss-group')];
const count = document.getElementById('gcount');
const empty = document.getElementById('gempty');
const total = terms.length;

function nTerms(n) {
  if (n === 0) return 'لا مصطلحات';
  if (n === 1) return 'مصطلح واحد';
  if (n === 2) return 'مصطلحان';
  return `${n} ${n % 100 >= 3 && n % 100 <= 10 ? 'مصطلحات' : 'مصطلحاً'}`;
}

function filter() {
  const words = norm(input.value).split(' ').filter(Boolean);
  let shown = 0;
  for (const t of terms) {
    const hit = !words.length || words.every((w) => norm(t.textContent).includes(w));
    t.hidden = !hit;
    if (hit) shown++;
  }
  for (const g of groups) g.hidden = !g.querySelector('.term:not([hidden])');
  empty.hidden = shown > 0;
  count.textContent = words.length ? `${nTerms(shown)} من ${total}` : `${nTerms(total)} في أربع مجموعات`;
}

input.addEventListener('input', filter);
filter();

// A link to a term (#cvss) highlights it once.
const target = location.hash ? document.getElementById(decodeURIComponent(location.hash.slice(1))) : null;
if (target?.classList.contains('term')) target.classList.add('flash');
