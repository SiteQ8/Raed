import { getJSON, esc, norm } from './ui.js';

const $ = (id) => document.getElementById(id);
const COUNTRY_AR = {
  USA: 'الولايات المتحدة', Germany: 'ألمانيا', China: 'الصين', Taiwan: 'تايوان', Spain: 'إسبانيا', Japan: 'اليابان',
  France: 'فرنسا', Switzerland: 'سويسرا', Australia: 'أستراليا', UK: 'المملكة المتحدة', Sweden: 'السويد',
  Netherlands: 'هولندا', Canada: 'كندا', Israel: 'إسرائيل', India: 'الهند', 'South Korea': 'كوريا الجنوبية',
  Belgium: 'بلجيكا', Austria: 'النمسا', Denmark: 'الدنمارك', Finland: 'فنلندا', 'Türkiye': 'تركيا', Italy: 'إيطاليا',
  'Slovak Republic': 'سلوفاكيا', Norway: 'النرويج', 'Czech Republic': 'التشيك', Romania: 'رومانيا', Ireland: 'أيرلندا',
  'New Zealand': 'نيوزيلندا', Russia: 'روسيا', Brazil: 'البرازيل', Singapore: 'سنغافورة', 'South Africa': 'جنوب أفريقيا',
  Colombia: 'كولومبيا', Vietnam: 'فيتنام', Estonia: 'إستونيا', Latvia: 'لاتفيا', Poland: 'بولندا',
  'Dominican Republic': 'جمهورية الدومينيكان', Greece: 'اليونان', Lithuania: 'ليتوانيا', Hungary: 'المجر',
  Uzbekistan: 'أوزبكستان', Luxembourg: 'لوكسمبورغ', 'n/a': 'غير محدد',
};
const TYPE_AR = {
  Vendor: 'مورّد', 'Open Source': 'مشروع مفتوح المصدر', Researcher: 'باحثون', 'Bug Bounty Provider': 'منصة مكافآت الثغرات',
  CERT: 'فريق استجابة للطوارئ', 'Hosted Service': 'خدمة مستضافة', Consultancy: 'استشارات', 'Vulnerability Coordinator': 'منسّق ثغرات',
};
const co = (c) => COUNTRY_AR[c] || c;
const ty = (t) => TYPE_AR[t] || t;

const PAGE = 50;
let shown = PAGE;

async function main() {
  const all = await getJSON('/data/cnas.json');
  const countries = [...new Set(all.map((c) => c.co))].sort((a, b) => co(a).localeCompare(co(b), 'ar'));
  const types = [...new Set(all.flatMap((c) => c.t))].sort();
  $('country').insertAdjacentHTML('beforeend', countries.map((c) => `<option value="${esc(c)}">${esc(co(c))}</option>`).join(''));
  $('type').insertAdjacentHTML('beforeend', types.map((t) => `<option value="${esc(t)}">${esc(ty(t))}</option>`).join(''));
  const draw = () => {
    const words = norm($('q').value).split(' ').filter(Boolean);
    const c = $('country').value;
    const t = $('type').value;
    const list = all.filter((x) => (!c || x.co === c) && (!t || x.t.includes(t)) && words.every((w) => norm(`${x.n} ${x.s} ${x.scope}`).includes(w)));
    $('rows').innerHTML = list.slice(0, shown).map((x) => `<tr><td><bdi style="font-weight:600">${esc(x.n)}</bdi>${x.adv ? `<br><a href="${esc(x.adv)}" rel="noopener" style="font-size:13.5px">النشرات الأمنية</a>` : ''}</td><td data-label="الدولة">${esc(co(x.co))}</td><td data-label="النوع">${x.t.map((v) => esc(ty(v))).join('، ')}</td><td data-label="النطاق كما كتبته الجهة" dir="ltr" style="text-align:left;font-size:14px;color:var(--ink-2)">${esc(x.scope)}</td></tr>`).join('');
    $('count').textContent = `${list.length.toLocaleString('en-US')} من ${all.length.toLocaleString('en-US')} جهة${list.length > shown ? `، تظهر منها أول ${shown}` : ''}`;
    $('more').hidden = list.length <= shown;
  };
  for (const el of ['q', 'country', 'type']) $(el).addEventListener('input', () => { shown = PAGE; draw(); });
  $('more').addEventListener('click', () => { shown += PAGE; draw(); });
  draw();
}

main().catch(() => { $('count').textContent = 'تعذر تحميل القائمة.'; });
