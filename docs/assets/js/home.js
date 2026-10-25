// Example chips under the search box fill it and search.
const input = document.getElementById('q');
for (const b of document.querySelectorAll('[data-try]')) {
  b.addEventListener('click', () => {
    input.value = b.dataset.try;
    input.form.requestSubmit();
  });
}
