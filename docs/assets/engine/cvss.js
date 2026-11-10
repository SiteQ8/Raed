// CVSS 3.1 base score, as the FIRST specification defines it (section 7.1 and the Roundup of appendix A).
export const METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
};
const VALID = { AV: 'NALP', AC: 'LH', PR: 'NLH', UI: 'NR', S: 'UC', C: 'HLN', I: 'HLN', A: 'HLN' };

export function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

// Reads a 3.0 or 3.1 vector. Returns { version, m } or { error } where error is 'version' or 'format'.
export function parse(vec) {
  const parts = String(vec || '').trim().toUpperCase().split('/').filter(Boolean);
  let version = '3.1';
  if (/^CVSS:/.test(parts[0] || '')) {
    version = parts.shift().slice(5);
    if (version !== '3.1' && version !== '3.0') return { error: 'version' };
  }
  const m = {};
  for (const p of parts) {
    const [k, v] = p.split(':');
    if (VALID[k]) { if (!v || v.length !== 1 || !VALID[k].includes(v)) return { error: 'format' }; m[k] = v; }
  }
  if (!Object.keys(m).length) return { error: 'format' };
  return { version, m };
}

export const complete = (m) => METRICS.every((k) => m[k]);
export const vector = (m) => `CVSS:3.1/${METRICS.map((k) => `${k}:${m[k]}`).join('/')}`;

export function score(m) {
  if (!complete(m)) return null;
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * W.PR[m.S][m.PR] * W.UI[m.UI];
  if (impact <= 0) return 0;
  return m.S === 'U' ? roundup(Math.min(impact + expl, 10)) : roundup(Math.min(1.08 * (impact + expl), 10));
}

export function severity(s) {
  if (s == null) return '';
  if (s === 0) return 'NONE';
  if (s < 4) return 'LOW';
  if (s < 7) return 'MEDIUM';
  if (s < 9) return 'HIGH';
  return 'CRITICAL';
}
