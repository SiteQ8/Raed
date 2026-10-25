// Small network helpers: JSON with retries, and a concurrency pool.

const UA = 'raed (+https://cve.3li.info)';

export async function getJSON(url, { tries = 4, timeout = 30000 } = {}) {
  let last;
  for (let n = 0; n < tries; n++) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeout);
    try {
      const r = await fetch(url, { headers: { 'user-agent': UA, accept: 'application/json' }, signal: ctl.signal });
      if (r.status === 404) return null;
      if (r.status === 429 || r.status >= 500) throw new Error(`HTTP ${r.status}`);
      if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
      return await r.json();
    } catch (e) {
      last = e;
      await new Promise((res) => setTimeout(res, 800 * 2 ** n));
    } finally {
      clearTimeout(timer);
    }
  }
  throw last;
}

export async function pool(items, size, fn) {
  const out = new Array(items.length);
  let next = 0;
  let done = 0;
  const workers = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      try {
        out[i] = await fn(items[i], i);
      } catch (e) {
        out[i] = { error: String(e.message || e) };
      }
      done++;
      if (process.stdout.isTTY === false && done % 1000 === 0) console.log(`  ${done}/${items.length}`);
    }
  });
  await Promise.all(workers);
  return out;
}
