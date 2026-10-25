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
