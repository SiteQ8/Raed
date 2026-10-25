// Turns a CVE JSON 5 record into the compact shape the site uses.
// Runs in Node (build) and in the browser (record page) unchanged.

const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];

function en(list) {
  if (!Array.isArray(list) || !list.length) return '';
  const hit = list.find((d) => /^en/i.test(d.lang || '')) || list[0];
  return (hit.value || '').replace(/\s+/g, ' ').trim();
}

function sevFromScore(score, version) {
  if (score == null) return null;
  if (String(version).startsWith('2')) return score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

// Picks the best CVSS score: the assigner's own first, newest version first,
// then the CISA ADP enrichment.
export function pickCvss(containers) {
  const order = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'];
  const sources = [];
  if (containers?.cna) sources.push({ src: 'cna', c: containers.cna });
  for (const a of containers?.adp || []) sources.push({ src: 'adp', c: a, who: a.providerMetadata?.shortName || '' });
  for (const s of sources) {
    for (const key of order) {
      for (const m of s.c.metrics || []) {
        const v = m[key];
        if (v && typeof v.baseScore === 'number') {
          const version = key.replace('cvssV', '').replace('_', '.');
          return {
            v: version,
            score: v.baseScore,
            sev: (v.baseSeverity || sevFromScore(v.baseScore, version) || '').toUpperCase() || null,
            vec: v.vectorString || '',
            src: s.src === 'cna' ? 'cna' : s.who || 'adp',
          };
        }
      }
    }
  }
  return null;
}

export function pickSsvc(containers) {
  for (const a of containers?.adp || []) {
    for (const m of a.metrics || []) {
      const o = m.other;
      if (o && /ssvc/i.test(o.type || '') && o.content?.options) {
        const out = {};
        for (const opt of o.content.options) {
          if ('Exploitation' in opt) out.x = String(opt.Exploitation).toLowerCase();
          if ('Automatable' in opt) out.a = String(opt.Automatable).toLowerCase();
          if ('Technical Impact' in opt) out.t = String(opt['Technical Impact']).toLowerCase();
        }
        return out;
      }
    }
  }
  return null;
}

export function pickKevFromAdp(containers) {
  for (const a of containers?.adp || []) {
    for (const m of a.metrics || []) {
      const o = m.other;
      if (o && /kev/i.test(o.type || '')) return { added: o.content?.dateAdded || null };
    }
  }
  return null;
}

function cwes(containers) {
  const out = [];
  const add = (pt) => {
    for (const p of pt || []) for (const d of p.descriptions || []) {
      const id = d.cweId || (String(d.description || '').match(/CWE-\d+/) || [])[0];
      if (id && !out.includes(id)) out.push(id);
    }
  };
  add(containers?.cna?.problemTypes);
  for (const a of containers?.adp || []) add(a.problemTypes);
  return out;
}

function product(containers) {
  const aff = containers?.cna?.affected || [];
  const named = (a) => (a.vendor && a.vendor !== 'n/a') || (a.product && a.product !== 'n/a') || a.packageName;
  const hasAffected = (a) => (a.versions || []).some((v) => v.status === 'affected') || a.defaultStatus === 'affected';
  const first = aff.find((a) => named(a) && hasAffected(a)) || aff.find(named) || aff[0];
  const clean = (s) => (s && !/^(n\/a|unknown|unspecified)$/i.test(s) ? String(s).trim() : '');
  return {
    vendor: clean(first?.vendor),
    product: clean(first?.product) || clean(first?.packageName),
    more: Math.max(0, aff.length - 1),
  };
}

export function compact(rec) {
  const m = rec.cveMetadata || {};
  const c = rec.containers || {};
  const state = m.state || 'PUBLISHED';
  const p = product(c);
  const cv = pickCvss(c);
  const out = {
    i: m.cveId,
    st: state === 'PUBLISHED' ? undefined : state,
    p: (m.datePublished || m.dateReserved || '').slice(0, 19),
    u: (m.dateUpdated || m.datePublished || '').slice(0, 19),
    a: m.assignerShortName || '',
    t: (c.cna?.title || '').replace(/\s+/g, ' ').trim().slice(0, 160) || undefined,
    d: state === 'REJECTED' ? en(c.cna?.rejectedReasons) : en(c.cna?.descriptions),
    v: p.vendor || undefined,
    r: p.product || undefined,
    s: cv?.score ?? undefined,
    sv: cv?.sev || undefined,
    vec: cv?.vec || undefined,
    cv: cv?.v || undefined,
    cs: cv?.src || undefined,
    c: cwes(c),
    x: pickSsvc(c) || undefined,
  };
  if (!out.c.length) delete out.c;
  for (const k of Object.keys(out)) if (out[k] === undefined || out[k] === '') delete out[k];
  return out;
}

// Full detail for the record page.
export function detail(rec) {
  const c = rec.containers || {};
  const base = compact(rec);
  const affected = (c.cna?.affected || []).map((a) => ({
    vendor: a.vendor || '',
    product: a.product || a.packageName || '',
    platforms: a.platforms || [],
    defaultStatus: a.defaultStatus || '',
    versions: (a.versions || []).map((v) => ({
      status: v.status,
      version: v.version,
      lessThan: v.lessThan,
      lessThanOrEqual: v.lessThanOrEqual,
      type: v.versionType,
    })),
  }));
  const refs = [];
  const seen = new Set();
  const addRefs = (list, from) => {
    for (const r of list || []) {
      if (!r.url || seen.has(r.url)) continue;
      seen.add(r.url);
      refs.push({ url: r.url, name: r.name || '', tags: r.tags || [], from });
    }
  };
  addRefs(c.cna?.references, 'cna');
  for (const a of c.adp || []) addRefs(a.references, a.providerMetadata?.shortName || 'adp');
  const cweNames = {};
  for (const p of c.cna?.problemTypes || []) for (const d of p.descriptions || []) {
    if (d.cweId) cweNames[d.cweId] = d.description;
  }
  const credits = (c.cna?.credits || []).map((x) => ({ who: x.value, type: x.type || '' }));
  const metrics = [];
  for (const [src, cont] of [['cna', c.cna], ...(c.adp || []).map((a) => [a.providerMetadata?.shortName || 'adp', a])]) {
    for (const m of cont?.metrics || []) {
      for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']) {
        if (m[key]) metrics.push({ src, v: key.replace('cvssV', '').replace('_', '.'), score: m[key].baseScore, sev: m[key].baseSeverity, vec: m[key].vectorString });
      }
    }
  }
  return {
    ...base,
    reserved: (rec.cveMetadata?.dateReserved || '').slice(0, 19),
    public: (c.cna?.datePublic || '').slice(0, 19) || undefined,
    affected,
    refs,
    cweNames,
    credits,
    metrics,
    kevAdp: pickKevFromAdp(c),
    solutions: en(c.cna?.solutions) || undefined,
    workarounds: en(c.cna?.workarounds) || undefined,
  };
}

export { SEV, sevFromScore };
