// Reads the CVE Program's partner list and keeps what the CNA page needs.

import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { getJSON } from './lib/net.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const SRC = 'https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json';

// Member states of the Arab League, as the partner list spells country names.
export const ARAB = new Set([
  'Algeria', 'Bahrain', 'Comoros', 'Djibouti', 'Egypt', 'Iraq', 'Jordan', 'Kuwait', 'Lebanon', 'Libya',
  'Mauritania', 'Morocco', 'Oman', 'Palestine', 'Qatar', 'Saudi Arabia', 'Kingdom of Saudi Arabia', 'Somalia', 'Sudan',
  'Syria', 'Tunisia', 'United Arab Emirates', 'UAE', 'Yemen',
]);

export const COUNTRY_AR = {
  USA: 'الولايات المتحدة', Germany: 'ألمانيا', China: 'الصين', Taiwan: 'تايوان', Spain: 'إسبانيا', Japan: 'اليابان',
  France: 'فرنسا', Switzerland: 'سويسرا', Australia: 'أستراليا', UK: 'المملكة المتحدة', Sweden: 'السويد',
  Netherlands: 'هولندا', Canada: 'كندا', Israel: 'إسرائيل', India: 'الهند', 'South Korea': 'كوريا الجنوبية',
  Belgium: 'بلجيكا', Austria: 'النمسا', Denmark: 'الدنمارك', Finland: 'فنلندا', 'Türkiye': 'تركيا', Italy: 'إيطاليا',
  'Slovak Republic': 'سلوفاكيا', Norway: 'النرويج', 'Czech Republic': 'التشيك', Romania: 'رومانيا', Ireland: 'أيرلندا',
  'New Zealand': 'نيوزيلندا', Russia: 'روسيا', Brazil: 'البرازيل', Singapore: 'سنغافورة', 'South Africa': 'جنوب أفريقيا',
  Colombia: 'كولومبيا', Vietnam: 'فيتنام', Estonia: 'إستونيا', Latvia: 'لاتفيا', Poland: 'بولندا',
  'Dominican Republic': 'جمهورية الدومينيكان', Greece: 'اليونان', Lithuania: 'ليتوانيا', Hungary: 'المجر',
  Uzbekistan: 'أوزبكستان', Luxembourg: 'لوكسمبورغ', Portugal: 'البرتغال', Malaysia: 'ماليزيا', Thailand: 'تايلاند',
  Indonesia: 'إندونيسيا', Mexico: 'المكسيك', Argentina: 'الأرجنتين', Chile: 'تشيلي', Ukraine: 'أوكرانيا',
  Slovenia: 'سلوفينيا', Croatia: 'كرواتيا', Bulgaria: 'بلغاريا', Serbia: 'صربيا', Philippines: 'الفلبين', 'n/a': 'غير محدد',
};

export const TYPE_AR = {
  Vendor: 'مورّد', 'Open Source': 'مشروع مفتوح المصدر', Researcher: 'باحثون', 'Bug Bounty Provider': 'منصة مكافآت الثغرات',
  'CERT': 'فريق استجابة للطوارئ', 'Hosted Service': 'خدمة مستضافة', Consultancy: 'استشارات', 'Vulnerability Coordinator': 'منسّق ثغرات',
};

async function main() {
  const raw = await getJSON(SRC);
  const out = raw.map((c) => {
    const adv = c.securityAdvisories?.advisories?.[0]?.url || '';
    const pol = c.disclosurePolicy?.[0]?.url || '';
    return {
      s: c.shortName,
      n: c.organizationName,
      co: c.country || 'n/a',
      t: c.CNA?.type || [],
      root: c.CNA?.root?.shortName && c.CNA.root.shortName !== 'n/a' ? c.CNA.root.organizationName : c.CNA?.TLR?.organizationName || '',
      roles: (c.CNA?.roles || []).map((r) => r.role),
      scope: (c.scope || '').replace(/\s+/g, ' ').trim().slice(0, 400),
      adv, pol,
      arab: ARAB.has(c.country) ? 1 : 0,
    };
  }).sort((a, b) => a.n.localeCompare(b.n));
  await writeFile(join(ROOT, 'docs/data/cnas.json'), JSON.stringify(out) + '\n');
  console.log(`${out.length} partners, ${out.filter((x) => x.arab).length} in Arab states`);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => { console.error(e); process.exit(1); });
