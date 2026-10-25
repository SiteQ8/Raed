# رائد

سجل عربي مفتوح للثغرات الأمنية المعلنة، يقرأ كل سجل يصدر عن برنامج CVE خلال ساعة من نشره ثم يعرضه بالعربية مع درجة الخطورة واحتمال الاستغلال وإدراجه في قائمة الثغرات المستغلة فعلياً، ويبقي الوصف الأصلي كما نشرته الجهة المرقّمة لأنه المرجع.

الموقع: **https://cve.3li.info**

## ما فيه

- **أحدث الثغرات** لآخر ثلاثين يوماً يوماً بيوم، مع بحث بالمنتج أو المورّد أو الرقم وتصفية بالخطورة والاستغلال الفعلي.
- **صفحة السجل** لأي رقم منذ عام 1999، تُقرأ مباشرة من خدمة CVE الرسمية وتُعرض بالعربية مع فك متجه CVSS واحتمال EPSS وتقدير SSVC.
- **الثغرات المستغلة فعلياً** من قائمة CISA كاملة بالعربية.
- **النشرة الأسبوعية** كل اثنين، بعناوين دائمة.
- **دليل الجهات المرقّمة** و**الطريق إلى جهة ترقيم عربية** مع حزمة طلب جاهزة في [cna-kit](cna-kit).
- **بيانات مفتوحة** بصيغة JSON وموجز Atom للثغرات الحرجة والمستغلة.

## كيف تُكتب العربية

لا تُترجم الأوصاف آلياً، بل يكتب المحرك في `docs/assets/engine/` الخلاصة العربية من حقول السجل المنظمة، أي من نوع الضعف في تصنيف CWE ومتجه CVSS واسم المنتج والمورّد، بعبارات مراجعة سلفاً، وتنتهي كل جملة بنقطة واحدة وتُربط أجزاؤها بأدوات العطف، وتتحقق الاختبارات من ذلك في كل صفحة قبل النشر.

## التحديث

| المهمة | الموعد |
|---|---|
| سجل التغييرات في قائمة CVE وقائمة CISA | كل ساعة عند الدقيقة 23 |
| احتمالات EPSS لكل سجلات النافذة | مرة يومياً |
| قائمة الجهات المرقّمة | مع كل تحديث |
| النشرة الأسبوعية | كل اثنين للأسبوع المنتهي |

```sh
npm run update   # يجلب ما تغير منذ آخر تشغيل
npm run weekly   # يكتب نشرة كل أسبوع مكتمل
npm run build    # يبني الصفحات من templates/pages
npm test         # بوابات العربية والتسمية وسلامة البيانات
```

## المصادر والترخيص

السجلات من [قائمة CVE](https://github.com/CVEProject/cvelistV5) وفق [شروط استخدام البرنامج](https://www.cve.org/Legal/TermsOfUse)، والثغرات المستغلة من [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)، واحتمالات الاستغلال من [FIRST EPSS](https://www.first.org/epss/)، والتفاصيل في [NOTICE](NOTICE). CVE® علامة تجارية مسجلة لمؤسسة MITRE، والمشروع مستقل لا يتبع البرنامج. الشيفرة برخصة MIT.

---

## Raed (English)

An open Arabic edition of the CVE List at https://cve.3li.info. Every record published by the CVE Program is read within the hour and rendered in Arabic from its structured fields (CWE, CVSS vector, product, vendor), never machine translated, next to the original description, CVSS, EPSS, SSVC and CISA KEV status. It also carries a weekly digest, the CNA directory and an application kit for the first Arab CNA. Data is open JSON; code is MIT.
