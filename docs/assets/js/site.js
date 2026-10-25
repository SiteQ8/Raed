// Menu and theme, on every page.
const menu = document.querySelector('.menu');
const nav = document.getElementById('nav');
menu?.addEventListener('click', () => {
  const open = nav.classList.toggle('open');
  menu.setAttribute('aria-expanded', String(open));
});

const themeBtn = document.querySelector('.theme');
themeBtn?.addEventListener('click', () => {
  const root = document.documentElement;
  const current = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  try { localStorage.setItem('theme', next); } catch (e) { /* storage may be blocked */ }
});

// Any search box: a CVE number opens its record, anything else searches the last thirty days.
for (const form of document.querySelectorAll('form.find')) {
  form.addEventListener('submit', (e) => {
    const v = form.querySelector('input').value.trim();
    if (!v) { e.preventDefault(); return; }
    if (!/^CVE-\d{4}-\d{4,}$/i.test(v)) {
      e.preventDefault();
      location.href = '/latest/?q=' + encodeURIComponent(v);
    } else {
      form.querySelector('input').value = v.toUpperCase();
    }
  });
}

// Contents rail on text pages: mark the section being read.
const toc = document.querySelector('.toc');
if (toc && 'IntersectionObserver' in window) {
  const links = new Map([...toc.querySelectorAll('a')].map((a) => [a.hash.slice(1), a]));
  const mark = (id) => links.forEach((a, k) => a.setAttribute('aria-current', k === id ? 'true' : 'false'));
  const io = new IntersectionObserver((entries) => {
    const seen = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
    if (seen[0]) mark(seen[0].target.id);
  }, { rootMargin: '0px 0px -65% 0px' });
  mark(links.keys().next().value);
  links.forEach((_, id) => { const h = document.getElementById(id); if (h) io.observe(h); });
}
