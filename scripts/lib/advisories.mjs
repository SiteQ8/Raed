// Raed's own advisories: each file in advisories/ holds a full CVE JSON 5 record plus a little metadata.
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const ROOT = new URL('../..', import.meta.url).pathname;
export const ADV_DIR = join(ROOT, 'advisories');

export async function loadAdvisories({ includeDrafts = false, includeTemplates = false } = {}) {
  const out = [];
  for (const f of (await readdir(ADV_DIR)).sort()) {
    if (!f.endsWith('.json')) continue;
    if (f.startsWith('_') && !includeTemplates) continue;
    const a = JSON.parse(await readFile(join(ADV_DIR, f), 'utf8'));
    a.file = f;
    if (a.raed?.status === 'draft' && !includeDrafts && !f.startsWith('_')) continue;
    out.push(a);
  }
  return out.sort((x, y) => (x.raed.published < y.raed.published ? 1 : -1));
}

export function descriptionIn(record, lang) {
  const list = record?.containers?.cna?.descriptions || [];
  const hit = list.find((d) => String(d.lang || '').toLowerCase().startsWith(lang));
  return hit ? hit.value : '';
}

export const STATUS_AR = {
  draft: 'مسودة',
  requested: 'طُلب له رقم من الجهة المرقّمة المختصة',
  published: 'منشور في قائمة CVE',
};
